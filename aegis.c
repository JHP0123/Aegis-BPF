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
static volatile sig_atomic_t stop = 0;

static void sig_handler(int sig) {
    stop = 1;
}

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

    while (bpf_map_get_next_key(stats_fd, &cur_key, &next_key) == 0) {
        cur_key = next_key;
        if (bpf_map_lookup_elem(stats_fd, &cur_key, &s_val) != 0) continue;

        // 1. 해당 세션의 현재 정책 확인
        if (bpf_map_lookup_elem(policy_fd, &cur_key, &p_val) != 0) {
            // 정책이 없다면 새로 생성 (is_new_destination = 1로 시작)
            memset(&p_val, 0, sizeof(p_val));
            p_val.trust_level = 2;          // [중요] 일단 무조건 허용(White)
            p_val.is_new_destination = 1;   // "현재 학습 중" 표시
            p_val.sample_rate = 10;         // 학습을 위해 샘플링 빈도를 높임
            bpf_map_update_elem(policy_fd, &cur_key, &p_val, BPF_ANY);
            continue;
        }

        // 2. [학습 종료 판정] 데이터가 충분히 쌓였는가? (예: 패킷 30개 이상)
        if (p_val.is_new_destination == 1 && s_val.packet_count >= 30) {
            
            // 이제 충분히 지켜봤으니 통계를 기반으로 '감시 모드' 전환
            double n = (double)s_val.packet_count;
            double mean = (double)s_val.total_bytes / n;
            double variance = ((double)s_val.total_sq_bytes / n) - (mean * mean);
            double std_dev = sqrt(variance < 0 ? 0 : variance);
            
            // 3시그마 임계치 계산
            p_val.max_packet_size = (unsigned long long)(mean + (3 * std_dev));
            
            // 상태 전환: White(2) -> Gray(1) 및 학습 완료(0) 표시
            p_val.trust_level = 1; 
            p_val.is_new_destination = 0; 
            p_val.sample_rate = 100; // 감시 모드로 들어갔으니 샘플링 빈도를 낮춤

            bpf_map_update_elem(policy_fd, &cur_key, &p_val, BPF_ANY);

            printf("\n\033[1;32m[Learning Complete]\033[0m Session PID:%u established profile.\n", cur_key.pid);
            printf("  > Normal Size Range: up to %llu bytes. \033[1;33mMonitoring Started.\033[0m\n", p_val.max_packet_size);
        }
    }
}


// [메인 실행부]
int main(int argc, char **argv) {
    struct aegis_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err, ifindex;
    const char *ifname = "ens33"; // 본인의 환경에 맞게 수정

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
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) goto cleanup;

    printf("\033[1;32m[Aegis-BPF Intelligence Engine Started]\033[0m\n");
    printf("Monitoring traffic on %s... Press Ctrl+C to stop.\n", ifname);

    // 4. 메인 분석 루프
    while (!stop) {
        // [A] 현실 시간 동기화 (커널 전역 변수 갱신)
        time_t t = time(NULL);
        skel->bss->current_hour = localtime(&t)->tm_hour;

        // [B] 통계 분석 및 정책 피드백 (3-Sigma 학습)
        sync_security_policies(skel);

        // [C] 보안 이벤트 감시 (Ring Buffer Polling)
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) break;

        usleep(500000); // 0.5초 주기로 정책 검토
    }

// [종료 처리] 루프 탈출 시 자원 정리 및 TC 필터 해제
cleanup:
    printf("\n\033[1;33m[Shutting down Aegis-BPF...]\033[0m\n");
    // TC 필터 해제
    opts.prog_fd = opts.prog_id = 0;
    bpf_tc_detach(&hook, &opts);
    
    // 자원 반환
    ring_buffer__free(rb);
    aegis_bpf__destroy(skel);
    printf("Cleanup complete. Goodbye.\n");
    
    return 0;
}
