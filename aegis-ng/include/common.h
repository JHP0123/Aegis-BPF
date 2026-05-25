#ifndef __COMMON_H
#define __COMMON_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

// BPF 맵의 키로 사용할 4-Tuple 식별자 (모든 커널에서 100% 호환)
struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// vmlinux.h 내부의 기존 커널 구조체와 이름이 겹치지 않도록 접두사 추가
struct aegis_process_info {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    char comm[16];
    __u64 start_ts;
};

// 커널 내부의 기존 flow_stats와 이름 충돌 방지
struct aegis_flow_stats {
    __u64 tx_bytes;
    __u64 tx_packets;
    __u64 first_packet_ts;
    __u64 last_packet_ts;
};

struct alert_event {
    struct flow_key key;
    __u32 pid;
    char comm[16];
    __u8 protocol; 
    __u8 alert_type; 
    __u64 metric_value;
};

#endif /* __COMMON_H */
