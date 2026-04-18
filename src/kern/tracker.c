#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP 0x0800

char _license[] SEC("license") = "GPL";

/* --- [전역 변수: 유저 영역에서 실시간 업데이트] --- */
// 현실 세계의 시각(Hour) 정보를 공유받음
volatile const __u32 current_hour = 0; 

/* --- [데이터 구조체 정의] --- */

// 1. 주소록 조회용 키
struct ip_port_key {
    __u32 dest_ip;
    __u16 dest_port;
    __u16 padding;
};

// 2. 프로세스 기본 정보
struct process_info_value {
    __u32 pid;
    __u32 tid;
    char comm[16];
};

// 3. 통계 및 정책 공용 키 (PID + 목적지 세션)
struct stats_key {
    __u32 pid;
    __u32 dest_ip;
    __u16 dest_port;
    __u16 padding;  
};

// 4. [5대 정책 항목 반영] 프로세스별 세부 정책
struct process_policy {
    // 항목 1 & 2: 전송량 및 빈도 (Throughput/Frequency)
    __u64 max_bytes_per_sec;    
    __u64 max_packet_size;      // 평균 + 3시그마 임계치
    __u32 max_packets_per_sec;  

    // 항목 3: 신뢰 상태 (Trust Level)
    __u8  trust_level;          // 0:Black, 1:Gray, 2:White
    __u8  is_new_destination;

    // 항목 4: 시간 제약 (Temporal Constraint)
    __u32 allowed_start_hour;
    __u32 allowed_end_hour;

    // 항목 5: 샘플링 트리거 (Sampling Rate)
    __u32 sample_rate;

    // [커널 관리용 실시간 상태]
    __u64 current_window_bytes;
    __u32 current_window_packets;
    __u64 last_window_ts;       // 1초 단위 갱신 기준
};

// 5. 정밀 분석용 통계 가계부
struct stats_info {
    char comm[16];
    __u64 packet_count;
    __u64 total_bytes;
    __u64 total_sq_bytes;
    __u64 last_packet_ts;
    __u64 interval_sum;
    __u32 max_packet_size;
    __u32 byte_frequency[8];
};

// 6. [최종 반영] 유저 영역 보고용 이벤트 (페이로드 스냅샷 포함)
struct event_t {
    __u32 pid;
    __u32 uid;
    char comm[16];
    
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    
    __u32 reason;       // 1:신뢰도, 2:크기초과, 3:전송량/빈도, 4:시간외, 5:샘플링
    __u32 packet_len;
    
    char payload[128];  // [핵심] 패킷 앞부분 128바이트 스냅샷
};

/* --- [BPF 맵 정의] --- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct stats_key);
    __type(value, struct stats_info);
} map_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_port_key);
    __type(value, struct process_info_value);
} map_process SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct stats_key);
    __type(value, struct process_policy);
} map_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 페이로드 복사를 위해 용량 상향
} rb SEC(".maps");

/* --- [헬퍼 함수: 이벤트 전송 및 페이로드 복사] --- */

static __always_inline void send_to_user(struct __sk_buff *skb, struct process_info_value *proc, struct stats_key *key, __u32 reason, __u32 payload_offset, __u32 saddr, __u16 sport) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    e->pid = proc->pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __builtin_memcpy(e->comm, proc->comm, 16);
    
    e->saddr = saddr; e->sport = sport;
    e->daddr = key->dest_ip; e->dport = key->dest_port;
    
    e->reason = reason;
    e->packet_len = skb->len;

    // 패킷에서 실제 데이터(Payload) 128바이트 복사
    __builtin_memset(e->payload, 0, 128);
    __u32 copy_len = skb->len - payload_offset;
    if (copy_len > 0) {
        if (copy_len > 128) copy_len = 128;
        bpf_skb_load_bytes(skb, payload_offset, e->payload, copy_len);
    }

    bpf_ringbuf_submit(e, 0);
}

/* --- [메인 로직: TC 훅] --- */

SEC("tc")
int bpf_tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 1. 헤더 분석 (L3, L4)
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u16 sport = 0, dport = 0;
    __u32 payload_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source); dport = bpf_ntohs(tcp->dest);
        payload_offset += (tcp->doff * 4);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        sport = bpf_ntohs(udp->source); dport = bpf_ntohs(udp->dest);
        payload_offset += sizeof(struct udphdr);
    } else return TC_ACT_OK;

    // 2. 프로세스 식별
    struct ip_port_key lookup_key = { .dest_ip = daddr, .dest_port = dport };
    struct process_info_value *proc_info = bpf_map_lookup_elem(&map_process, &lookup_key);
    if (!proc_info) return TC_ACT_OK;

    struct stats_key s_key = { .pid = proc_info->pid, .dest_ip = daddr, .dest_port = dport };

    // 3. [정책 분석 엔진 가동]
    struct process_policy *policy = bpf_map_lookup_elem(&map_policy, &s_key);
    if (policy) {
        // [A] 블랙리스트 필터링
        if (policy->trust_level == 0) return TC_ACT_SHOT;

        // [B] 실시간 윈도우 계산
        __u64 now = bpf_ktime_get_ns();
        if (now - policy->last_window_ts >= 1000000000ULL) {
            policy->current_window_bytes = 0;
            policy->current_window_packets = 0;
            policy->last_window_ts = now;
        }
        __sync_fetch_and_add(&policy->current_window_packets, 1);

        // [C] 샘플링 트리거 (Level 2여도 수행)
        if (policy->sample_rate > 0 && (policy->current_window_packets % policy->sample_rate == 0)) {
            send_to_user(skb, proc_info, &s_key, 5, payload_offset, saddr, sport);
        }

        // [D] 시간 제약 필터링
        if (policy->allowed_start_hour != policy->allowed_end_hour) {
            if (current_hour < policy->allowed_start_hour || current_hour >= policy->allowed_end_hour) {
                send_to_user(skb, proc_info, &s_key, 4, payload_offset, saddr, sport);
                return TC_ACT_SHOT;
            }
        }

        // [E] 신뢰 상태 분기
        if (policy->trust_level == 2) goto collect_stats;

        // [F] 의심 상태 정밀 필터링
        if (policy->trust_level == 1) {
            // 크기(3시그마) 체크
            if (policy->max_packet_size > 0 && skb->len > policy->max_packet_size) {
                send_to_user(skb, proc_info, &s_key, 2, payload_offset, saddr, sport);
                return TC_ACT_SHOT;
            }
            // 빈도/전송량 체크
            if (policy->max_packets_per_sec > 0 && policy->current_window_packets > policy->max_packets_per_sec) {
                send_to_user(skb, proc_info, &s_key, 3, payload_offset, saddr, sport);
                return TC_ACT_SHOT;
            }
            policy->current_window_bytes += skb->len;
            if (policy->max_bytes_per_sec > 0 && policy->current_window_bytes > policy->max_bytes_per_sec) {
                send_to_user(skb, proc_info, &s_key, 3, payload_offset, saddr, sport);
                return TC_ACT_SHOT;
            }
        }
    }

collect_stats:
    // 4. 정보 수집 및 가계부 작성
    struct stats_info *stats = bpf_map_lookup_elem(&map_stats, &s_key);
    if (stats) {
        __sync_fetch_and_add(&stats->packet_count, 1);
        __sync_fetch_and_add(&stats->total_bytes, skb->len);
        __sync_fetch_and_add(&stats->total_sq_bytes, (__u64)skb->len * skb->len);
        
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            if (payload_offset + i < skb->len) {
                __u8 bv = 0; bpf_skb_load_bytes(skb, payload_offset + i, &bv, 1);
                __sync_fetch_and_add(&stats->byte_frequency[(bv / 32) & 7], 1);
            }
        }
    }
    return TC_ACT_OK;
}