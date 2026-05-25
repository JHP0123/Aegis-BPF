#define __TARGET_ARCH_x86

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "../include/common.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP 0x0800

char _license[] SEC("license") = "GPL";

/* --- [BPF Maps] --- */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct aegis_process_info);
} map_process SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct aegis_flow_stats);
} map_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u8);
} map_enforcement SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb_alerts SEC(".maps");


/* --- [Hooks] --- */

// [프로세스 맵핑] 데이터 전송 시점의 4-Tuple과 PID 결합
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk)
{
    struct flow_key key = {};
    __u16 sport = 0;

    // 커널 메모리에서 안전하게 IP와 Port 추출 (네트워크 바이트 정렬 맞춤)
    bpf_core_read(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_core_read(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    bpf_core_read(&key.dport, sizeof(key.dport), &sk->__sk_common.skc_dport);
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    key.sport = bpf_htons(sport);

    // 목적지가 아직 세팅되지 않은 경우 무시
    if (key.daddr == 0 || key.dport == 0) return 0;

    struct aegis_process_info proc = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    proc.pid = pid_tgid >> 32;
    proc.tgid = (__u32)pid_tgid;
    proc.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    proc.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    bpf_map_update_elem(&map_process, &key, &proc, BPF_ANY);
    return 0;
}

// [가비지 컬렉션] 소켓 종료 시 4-Tuple 키를 통해 정리
SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock *sk)
{
    struct flow_key key = {};
    __u16 sport = 0;

    bpf_core_read(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_core_read(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    bpf_core_read(&key.dport, sizeof(key.dport), &sk->__sk_common.skc_dport);
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    key.sport = bpf_htons(sport);

    bpf_map_delete_elem(&map_process, &key);
    bpf_map_delete_elem(&map_stats, &key);
    bpf_map_delete_elem(&map_enforcement, &key);
    return 0;
}

// [네트워크 차단 및 통계] TC Egress (송신 패킷 제어)
SEC("tc")
int bpf_tc_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    struct flow_key key = {};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        key.sport = udp->source;
        key.dport = udp->dest;
    } else {
        return TC_ACT_OK; // TCP, UDP 외 패스
    }

    // 1. 차단 정책 확인
    __u8 *enforce_action = bpf_map_lookup_elem(&map_enforcement, &key);
    if (enforce_action && *enforce_action == 1) {
        return TC_ACT_SHOT;
    }

    // 2. 통계 수집
    struct aegis_flow_stats *stats = bpf_map_lookup_elem(&map_stats, &key);
    if (!stats) {
        struct aegis_flow_stats new_stats = {
            .tx_bytes = skb->len,
            .tx_packets = 1,
            .first_packet_ts = bpf_ktime_get_ns(),
            .last_packet_ts = bpf_ktime_get_ns()
        };
        bpf_map_update_elem(&map_stats, &key, &new_stats, BPF_ANY);
    } else {
        stats->tx_bytes += skb->len;
        stats->tx_packets += 1;
        stats->last_packet_ts = bpf_ktime_get_ns();
    }

    return TC_ACT_OK;
}
