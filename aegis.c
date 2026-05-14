#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>

#include "aegis.skel.h"

// ---------------------------------------------------------
// [전역 변수 및 시그널 핸들러]
// ---------------------------------------------------------
static volatile bool stop = false;
static void sig_handler(int sig) { stop = true; }

// 헥스 덤프 헬퍼 함수 (페이로드 시각화)
void print_hex_dump(const char *payload, int len) {
    printf("      [Payload Dump] ");
    for (int i = 0; i < len && i < 16; i++) {
        printf("%02x ", (unsigned char)payload[i]);
    }
    printf("...\n");
}

// 링버퍼로 샘플링 받은 데이터의 엔트로피 계산 함수 
double calculate_entropy(const char *payload, int len) {
    if (len == 0) return 0.0;
    int counts[256] = {0};
    for (int i = 0; i < len; i++) {
        counts[(unsigned char)payload[i]]++;
    }
    double entropy = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}
// [링버퍼 이벤트 핸들러] 커널에서 올라온 차단/샘플링 알람 처리
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    struct aegis_bpf *skel = (struct aegis_bpf *)ctx; 
    char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->saddr, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &e->daddr, d_ip, sizeof(d_ip));


    // 1. 샘플링 데이터(Reason 5) 처리: 정밀 분석 및 등급 강등 (주기적으로 시행)
    if (e->reason == 5) {
        double entropy = calculate_shannon_entropy(e->payload, 128);

        // 엔트로피 임계치(6.5) 초과 시: 신뢰 등급 강등 (Level 2 -> 1)
        if (entropy > 6.5) {
            struct stats_key key = { .pid = e->pid, .dest_ip = e->daddr, .dest_port = e->dport };
            struct process_policy p_val;
            int policy_fd = bpf_map__fd(skel->maps.map_policy);

            if (bpf_map_lookup_elem(policy_fd, &key, &p_val) == 0) {
                    p_val.trust_level = 1;     // 의심 상태로 변경
                    bpf_map_update_elem(policy_fd, &key, &p_val, BPF_ANY);
                    
                    printf("\n\033[1;33m[!] BEHAVIOR ALERT:\033[0m High Entropy Detected (%.2f)\n", entropy);
                    printf("    Process: %s (PID:%u) | Trust Level Demoted: \033[1;32mWHITE\033[0m -> \033[1;31mGRAY\033[0m\n", e->comm, e->pid);
                    printf("    Target : %s:%u\n", d_ip, e->dport);
                
            }
        }
        return 0; // 일반 샘플링은 화면 출력을 생략
    }

    // 2. 이미 차단된 위협(Reason 2, 3, 4) 보고 및 영구 차단 여부 확인 (이것들은 trust_level 1에서 발생)
    printf("\n\033[1;41m[ SECURITY VIOLATION ]\033[0m\n");
    printf("  REASON       : ");
    switch (e->reason) {
        case 2: printf("Packet Size Anomaly (3-Sigma Violation)\n"); break;
        case 3: printf("Rate Limit Exceeded\n"); break;
        case 4: printf("Out of Office Hours\n"); break;
    }
    printf("  DETAILS      : %s (PID:%u) -> %s:%u\n", e->comm, e->pid, d_ip, e->dport); //구체적 내용 알림
    printf("  \033[1;36mPermanently BLOCK this process/destination? (y/n): \033[0m");

    scanf(" %c", &choice);
    if (tolower(choice) == 'y') {
        struct stats_key key = { .pid = e->pid, .dest_ip = e->daddr, .dest_port = e->dport };
        struct process_policy p_val;
        int policy_fd = bpf_map__fd(skel->maps.map_policy);
        // 사용자가 Y를 누르면 (1->2 로 올리기)

        if (bpf_map_lookup_elem(policy_fd, &key, &p_val) == 0) {
            p_val.trust_level = 0; // 블랙리스트(영구 차단)로 변경 (기존 1 -> 0)
            bpf_map_update_elem(policy_fd, &key, &p_val, BPF_ANY);
            printf("  >> \033[1;31mBlacklisted.\033[0m All future traffic from this session will be SHOT.\n");
        }
    } else {
        printf("  >> \033[1;32mTemporary Block Only.\033[0m Policy remains unchanged.\n");
    }

    return 0;
}

// 임계치 주입 함수 ( map_stats -> 3-Sigma 계산 -> map_policy 주입)
void sync_security_policies(struct aegis_bpf *skel) {
    int stats_fd = bpf_map__fd(skel->maps.map_stats);
    int policy_fd = bpf_map__fd(skel->maps.map_policy);
    
    struct stats_key cur_key = {}, next_key;
    struct stats_info s_val;
    struct process_policy p_val;

    //데이터가 충분히 쌓여있지 않을때 처리
    while (bpf_map_get_next_key(stats_fd, &cur_key, &next_key) == 0) {
        cur_key = next_key;
        if (bpf_map_lookup_elem(stats_fd, &cur_key, &s_val) != 0) continue;

        if (bpf_map_lookup_elem(policy_fd, &cur_key, &p_val) != 0) {
            memset(&p_val, 0, sizeof(p_val));
            p_val.trust_level = 2;          
            p_val.is_new_destination = 1;   
            p_val.sample_rate = 10;         
            bpf_map_update_elem(policy_fd, &cur_key, &p_val, BPF_ANY);
            continue;
        }

        // [학습 종료및 1,000개 패킷 단위로 map_stats 초기화]
        bool should_update = false;
        bool is_initial_learning = (p_val.is_new_destination == 1 && s_val.packet_count >= 30); //학습 중인지 아닌지를 1 /0 
        bool is_overflow_prevent = (s_val.packet_count >= 10000); // 1,000개 패킷 단위로 리셋 해야하기에 1,000개 이상 1 아니면 0

        if (is_initial_learning || is_overflow_prevent) { //둘중 하나라도 참이면 업데이트
            
            // --- [통계 계산 시작] ---
            double n = (double)s_val.packet_count;
            
            // 1. 패킷 크기 기반 3시그마 계산
            double mean_size = (double)s_val.total_bytes / n;
            double var_size = ((double)s_val.total_sq_bytes / n) - (mean_size * mean_size);
            double std_dev = sqrt(var_size < 0 ? 0 : var_size);
            p_val.max_packet_size = (unsigned long long)(mean_size + (3 * std_dev));

            // 2. 전송량(BPS) 및 빈도(PPS) 계산
            double total_duration_sec = (double)s_val.interval_sum / 1e9;
            if (total_duration_sec < 0.001) total_duration_sec = 0.001;

            double avg_bps = (double)s_val.total_bytes / total_duration_sec;
            double avg_pps = (double)s_val.packet_count / total_duration_sec;

            // 변동 계수(CV)를 활용한 동적 마진 계산, 즉 변동이 많으면 그 값을 반영해서 처리
            double cv = (mean_size > 0) ? (std_dev / mean_size) : 0;
            double dynamic_margin = 1.5 + (cv * 1.0);
            if (dynamic_margin > 5.0) dynamic_margin = 5.0;

            p_val.max_bytes_per_sec = (unsigned long long)(avg_bps * dynamic_margin);
            p_val.max_packets_per_sec = (unsigned int)(avg_pps * dynamic_margin);
            // --- [통계 계산 종료] ---

            // 상태 변경 로직
            if (is_initial_learning) {
                p_val.trust_level = 1; // Gray 등급 강등
                p_val.is_new_destination = 0;
                p_val.sample_rate = 100;
                printf("\n\033[1;32m[Learning Complete]\033[0m Session PID:%u (New Profile)\n", cur_key.pid);
            } else {
                printf("\n\033[1;34m[Stats Refresh]\033[0m Session PID:%u (Overflow Prevention)\n", cur_key.pid);
            }

            // 정책 업데이트 및 통계 맵 리셋
            bpf_map_update_elem(policy_fd, &cur_key, &p_val, BPF_ANY); //정책 업데이트
            bpf_map_update_elem(stats_fd, &cur_key, &zero_stats, BPF_ANY); // 여기서 초기화

            printf("  > Max Packet Size : %llu bytes\n", p_val.max_packet_size);
            printf("  > Max Throughput  : %llu bytes/sec (Margin: %.2fx)\n", p_val.max_bytes_per_sec, dynamic_margin);
            printf("  > Max Frequency   : %u packets/sec\n", p_val.max_packets_per_sec);
        }
    }
}

// 종료된 프로세스를 확인하고 지우는 함수 (PID 재사용 방지 및 메모리 확보)
void cleanup_stale_policies(struct aegis_bpf *skel) {
    int stats_fd = bpf_map__fd(skel->maps.map_stats);
    int policy_fd = bpf_map__fd(skel->maps.map_policy);
    
    struct stats_key cur_key = {}, next_key;
    int deleted_count = 0;

    // map_stats를 기준으로 전체 항목을 순회 (Key-Value 데이터베이스 스캔 방식)
    while (bpf_map_get_next_key(stats_fd, &cur_key, &next_key) == 0) {
        cur_key = next_key;

        /* kill(pid, 0)의 의미:
         * 실제로 시그널을 보내지 않고, 해당 PID가 살아있는지 커널에 확인 요청.
         * 만약 반환값이 -1이고 errno가 ESRCH(No such process)라면 프로세스가 종료된 것임.
         */
        if (kill(cur_key.pid, 0) == -1 && errno == ESRCH) {
            
            // 1. 통계 맵에서 해당 PID 정보 삭제
            bpf_map_delete_elem(stats_fd, &cur_key);
            
            // 2. 정책 맵에서 해당 PID 정보 삭제
            bpf_map_delete_elem(policy_fd, &cur_key);

            deleted_count++;
        }
    }

    // 청소 결과 로그 (테스트용)
    if (deleted_count > 0) {
        printf("\033[1;34m[GC]\033[0m Cleaned up %d stale entries (Process terminated).\n", deleted_count);
    }
}

// [메인 실행부]
int main(int argc, char **argv) {
    struct aegis_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err, ifindex;
    const char *ifname = "ens33"; // 본인의 환경에 맞게 수정

    // 실행 주기를 관리하기 위한 변수
    time_t now;
    time_t last_sync_time = 0;
    time_t last_cleanup_time = 0;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { fprintf(stderr, "Interface %s not found\n", ifname); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. 메모리 제한 해제 및 스켈레톤 로드
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    skel = aegis_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "Failed to load BPF skeleton\n"); return 1; }

    // 2. Kprobe 및 TC Attach
    err = aegis_bpf__attach(skel);
    if (err) goto cleanup;

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
    bpf_tc_hook_create(&hook);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(skel->progs.bpf_tc_egress));
    err = bpf_tc_attach(&hook, &opts);
    if (err) goto cleanup;

    // 3. 링버퍼 초기화
    // handle_event 함수에 skel을 전달하여 함수 내부에서 맵에 접근할 수 있게 합니다.
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, skel, NULL);
    if (!rb) goto cleanup;

    printf("\n\033[1;32m[Aegis-BPF Intelligence Engine Started]\033[0m\n");
    printf("Monitoring traffic on %s... Press Ctrl+C to stop.\n", ifname);

    // 4. 주요 동작 루프 처리
    while (!stop) {
        // [A] 링버퍼 이벤트 감시 (가장 높은 우선순위)
        err = ring_buffer__poll(rb, 100); 
        if (err < 0 && err != -EINTR) break;

        now = time(NULL);

        // [B] 현실 시간 및 정책 동기화 (1초 주기)
        if (now - last_sync_time >= 1) {
            // 커널 전역 변수(시간) 갱신 (이걸로 사용자 시간을 커널에 주입)
            struct tm *tm_info = localtime(&now);
            skel->bss->current_hour = tm_info->tm_hour;

            // 통계 분석 및 3-Sigma 정책 피드백 실행
            sync_security_policies(skel);
            
            last_sync_time = now;
        }

        // [C] 종료된 프로세스 정보 정리 (10초 주기)
        // 종료된 프로세스를 확인하고 맵에서 제거하여 메모리 확보 및 PID 재사용 방지
        if (now - last_cleanup_time >= 10) {
            cleanup_stale_policies(skel);
            last_cleanup_time = now;
        }

        // CPU 과점유 방지를 위한 미세 대기 (0.1초)
        usleep(100000); 
    }

// [종료 처리] 루프 탈출 시 자원 정리 및 TC 필터 해제
cleanup:
    printf("\n\033[1;33m[Shutting down Aegis-BPF...]\033[0m\n");
    if (ifindex > 0) {
        opts.prog_fd = opts.prog_id = 0;
        bpf_tc_detach(&hook, &opts);
    }
    ring_buffer__free(rb);
    aegis_bpf__destroy(skel);
    printf("Cleanup complete. Goodbye.\n");
    
    return 0;
}
