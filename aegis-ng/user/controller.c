#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "aegis.skel.h"
#include "../include/common.h"

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

struct user_flow_state {
    struct flow_key key;
    double ema_tx_bps;     
    __u64 last_tx_bytes;
    bool is_blocked;
};

struct dest_tracker_state {
    __u32 daddr;
    __u16 dport;
    __u64 last_packet_ts;
    double ema_interval;      
    double ema_variance;      
    int beacon_count;         
    bool is_blocked;
};

#define MAX_TRACKED_FLOWS 10000
struct user_flow_state tracker[MAX_TRACKED_FLOWS];
int tracker_count = 0;

struct dest_tracker_state d_tracker[MAX_TRACKED_FLOWS];
int d_tracker_count = 0;

void print_ip(__u32 ip, char *buf) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
}

void run_anomaly_engine(struct aegis_bpf *skel) {
    int stats_fd = bpf_map__fd(skel->maps.map_stats);
    int enforce_fd = bpf_map__fd(skel->maps.map_enforcement);
    int proc_fd = bpf_map__fd(skel->maps.map_process);
    
    struct flow_key prev_key = {}, key;
    int num_cpus = libbpf_num_possible_cpus();
    struct aegis_flow_stats percpu_stats[num_cpus];

    while (bpf_map_get_next_key(stats_fd, &prev_key, &key) == 0) {
        if (bpf_map_lookup_elem(stats_fd, &key, percpu_stats) != 0) {
            prev_key = key;
            continue;
        }

        __u64 total_tx_bytes = 0;
        __u64 max_last_ts = 0;

        for (int i = 0; i < num_cpus; i++) {
            total_tx_bytes += percpu_stats[i].tx_bytes;
            if (percpu_stats[i].last_packet_ts > max_last_ts) {
                max_last_ts = percpu_stats[i].last_packet_ts;
            }
        }

        bool is_dns = (ntohs(key.dport) == 53);

        // ==========================================
        // [로직 1 & 3] 대용량 유출 및 DNS 터널링 탐지
        // ==========================================
        int track_idx = -1;
        for (int i = 0; i < tracker_count; i++) {
            if (memcmp(&tracker[i].key, &key, sizeof(struct flow_key)) == 0) { 
                track_idx = i; break; 
            }
        }
        
        if (track_idx == -1 && tracker_count < MAX_TRACKED_FLOWS) {
            track_idx = tracker_count++;
            tracker[track_idx].key = key;
            tracker[track_idx].last_tx_bytes = total_tx_bytes;
            tracker[track_idx].ema_tx_bps = 0.0;
            tracker[track_idx].is_blocked = false;
        }

        if (track_idx != -1 && !tracker[track_idx].is_blocked) {
            double current_bps = 0.0;
            if (total_tx_bytes > tracker[track_idx].last_tx_bytes) {
                current_bps = (double)(total_tx_bytes - tracker[track_idx].last_tx_bytes);
            }
            tracker[track_idx].ema_tx_bps = (0.2 * current_bps) + (0.8 * tracker[track_idx].ema_tx_bps);
            tracker[track_idx].last_tx_bytes = total_tx_bytes;

            // 일반 트래픽은 1MB/s, DNS 트래픽은 5KB/s(5120 Bytes)를 초과하면 유출로 판단
            double threshold = is_dns ? 5120.0 : 1048576.0;

            if (tracker[track_idx].ema_tx_bps > threshold) { 
                tracker[track_idx].is_blocked = true;
                
                struct aegis_process_info proc = {};
                char dest_ip[INET_ADDRSTRLEN];
                print_ip(key.daddr, dest_ip);

                if (is_dns) {
                    // DNS는 UDP이므로 프로세스 이름 대신 시스템 태그 부착
                    printf("\033[1;33m[BLOCK] DNS Tunneling Detected\033[0m | System (UDP) -> %s:53 | BPS: %.0f\n", 
                           dest_ip, tracker[track_idx].ema_tx_bps);
                } else {
                    if (bpf_map_lookup_elem(proc_fd, &key, &proc) != 0) {
                        struct flow_key lookup_key = key;
                        lookup_key.saddr = 0;
                        bpf_map_lookup_elem(proc_fd, &lookup_key, &proc);
                    }
                    printf("\033[1;31m[BLOCK] Bulk Exfiltration\033[0m | PID: %u (%s) -> %s:%u | BPS: %.0f\n", 
                           proc.pid, proc.comm, dest_ip, ntohs(key.dport), tracker[track_idx].ema_tx_bps);
                }
                       
                __u8 action_drop = 1;
                bpf_map_update_elem(enforce_fd, &key, &action_drop, BPF_ANY);
            }
        }

        // ==========================================
        // [로직 2 & 4] 일반 C2 및 DNS 비코닝 탐지
        // ==========================================
        int d_idx = -1;
        for (int i = 0; i < d_tracker_count; i++) {
            if (d_tracker[i].daddr == key.daddr && d_tracker[i].dport == key.dport) {
                d_idx = i; break;
            }
        }

        if (d_idx == -1 && d_tracker_count < MAX_TRACKED_FLOWS) {
            d_idx = d_tracker_count++;
            d_tracker[d_idx].daddr = key.daddr;
            d_tracker[d_idx].dport = key.dport;
            d_tracker[d_idx].last_packet_ts = max_last_ts;
            d_tracker[d_idx].ema_interval = 0.0;
            d_tracker[d_idx].ema_variance = 0.0;
            d_tracker[d_idx].beacon_count = 0;
            d_tracker[d_idx].is_blocked = false;
        }

        if (d_idx != -1 && !d_tracker[d_idx].is_blocked) {
            if (max_last_ts > d_tracker[d_idx].last_packet_ts) {
                double delta_sec = (double)(max_last_ts - d_tracker[d_idx].last_packet_ts) / 1e9;

                if (delta_sec > 2.0 && delta_sec < 3600.0) {
                    d_tracker[d_idx].beacon_count++;

                    if (d_tracker[d_idx].beacon_count == 1) {
                        d_tracker[d_idx].ema_interval = delta_sec;
                        d_tracker[d_idx].ema_variance = 0.0;
                    } else {
                        double diff = delta_sec - d_tracker[d_idx].ema_interval;
                        d_tracker[d_idx].ema_interval += 0.2 * diff;
                        d_tracker[d_idx].ema_variance = (1 - 0.2) * (d_tracker[d_idx].ema_variance + 0.2 * diff * diff);
                    }

                    if (d_tracker[d_idx].beacon_count >= 5) {
                        double std_dev = sqrt(d_tracker[d_idx].ema_variance);
                        double cv = (d_tracker[d_idx].ema_interval > 0) ? (std_dev / d_tracker[d_idx].ema_interval) : 1.0;

                        if (cv < 0.10) {
                            d_tracker[d_idx].is_blocked = true;
                            char dest_ip[INET_ADDRSTRLEN];
                            print_ip(key.daddr, dest_ip);

                            if (is_dns) {
                                printf("\033[1;36m[BLOCK] DNS Beaconing Detected\033[0m | System (UDP) -> %s:53 | Interval: %.2fs (CV: %.3f)\n", 
                                       dest_ip, d_tracker[d_idx].ema_interval, cv);
                            } else {
                                struct aegis_process_info proc = {};
                                struct flow_key lookup_key = key;
                                lookup_key.saddr = 0;
                                bpf_map_lookup_elem(proc_fd, &lookup_key, &proc);
                                
                                printf("\033[1;35m[BLOCK] C2 Beaconing Detected\033[0m | PID: %u (%s) -> %s:%u | Interval: %.2fs (CV: %.3f)\n", 
                                       proc.pid, proc.comm, dest_ip, ntohs(key.dport), d_tracker[d_idx].ema_interval, cv);
                            }
                                   
                            struct flow_key block_key = {};
                            block_key.daddr = key.daddr;
                            block_key.dport = key.dport;
                            __u8 action_drop = 1;
                            bpf_map_update_elem(enforce_fd, &block_key, &action_drop, BPF_ANY);
                        }
                    }
                }
                d_tracker[d_idx].last_packet_ts = max_last_ts;
            }
        }
        prev_key = key;
    }
}

int main(int argc, char **argv) {
    struct aegis_bpf *skel;
    int epoll_fd, timer_fd;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = aegis_bpf__open_and_load();
    if (!skel) return 1;
    if (aegis_bpf__attach(skel) != 0) goto cleanup;

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
    bpf_tc_hook_create(&tc_hook);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = bpf_program__fd(skel->progs.bpf_tc_egress));
    
    if (bpf_tc_attach(&tc_hook, &tc_opts) != 0) goto cleanup;

    epoll_fd = epoll_create1(0);
    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    
    struct itimerspec ts = { .it_interval = {1, 0}, .it_value = {1, 0} };
    timerfd_settime(timer_fd, 0, &ts, NULL);

    struct epoll_event ev_timer = { .events = EPOLLIN, .data.fd = timer_fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev_timer);

    printf("\033[1;32mAegis-NG Engine Started on '%s'.\033[0m Monitoring...\n", ifname);

    struct epoll_event events[10];
    while (!exiting) {
        int n = epoll_wait(epoll_fd, events, 10, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == timer_fd) {
                uint64_t expirations;
                if (read(timer_fd, &expirations, sizeof(expirations)) > 0) run_anomaly_engine(skel);
            }
        }
    }

cleanup:
    if (ifindex > 0) {
        tc_opts.prog_fd = tc_opts.prog_id = 0;
        bpf_tc_detach(&tc_hook, &tc_opts);
        bpf_tc_hook_destroy(&tc_hook);
    }
    aegis_bpf__destroy(skel);
    printf("\nExiting gracefully.\n");
    return 0;
}
