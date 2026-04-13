#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

char _license[] SEC("license") = "GPL";

struct ip_port_key
{
	__u32 dest_ip;
	__u16 dest_port;
	__u16 padding;
};

struct process_info_value
{
	__u32 pid;
	__u32 tid;
	char comm[16];	// process name
};

struct stats_key
{
	__u32 pid;
	__u32 dest_ip;
	__u16 dest_port;
	__u16 padding;	
};

struct stats_info
{
	char comm[16];
	__u64 packet_count;
	__u64 total_bytes;
	__u64 total_sq_bytes;
	__u64 last_packet_ts;
	__u64 interval_sum;
	__u32 max_packet_size;
	__u32 byte_frequency[8];	
};

struct 
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct stats_key);
	__type(value, struct stats_info);
} map_stats SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ip_port_key);
	__type(value, struct process_info_value);
} map_process SEC(".maps");


SEC("kprobe/tcp_sendmsg")
int bpf_prog_tcp_sendmsg(struct pt_regs *ctx)
{
	// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
	// kprobe는 어떤 함수가 실행될 때, CPU register 값을 가져온다. 
	// 함수의 파라메타가 sk, msg, size이므로, 이들은 x86-64 기준 
	// %rdi, %rsi, ... 에 저장이 되고, 이 register 값들의 정보를 가져온다. 
	// PT_REGS_PARM1은 첫번째 register의 값을 가져오는데 이것이 socket 정보.
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;
	
	// key와 value 구조체를 다 0으로 초기화
	struct ip_port_key key = {};
	struct process_info_value val = {};

	// PID, TID 추출
	// 상위 32비트: TGID (process ID)
	// 하위 32비트: PID (Thread ID)
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	val.pid = pid_tgid >> 32;
	val.tid = (__u32)pid_tgid;

	// 프로세스 이름 추
	bpf_get_current_comm(&val.comm, sizeof(val.comm));

	// destination port 추출
	// struct sk 구조체는 TCP 연결 상태, 송신 큐, 윈도우 크기 등의 정보들을 가지고 있다. 
	// sk->__sk_common에 IP와 port 정보들이 저장되어 있다. 
	// sk->__sk_common.skc_daddr: dest IP
	// sk->__sk_common.skc_dport: dest port
	__u16 dport = 0;
	bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
	key.dest_port = bpf_ntohs(dport);

	// destination IP 추출
	bpf_probe_read_kernel(&key.dest_ip, sizeof(key.dest_ip), &sk->__sk_common.skc_daddr);

	// map에 저장
	bpf_map_update_elem(&map_process, &key, &val, BPF_ANY);
	
	return 0;
}

SEC("tc")
int bpf_tc_egress(struct __sk_buff *skb)
{
	// TC Hook에서 sk_buff 구조체를 입력 파라메타로 가져옴
	// data_end는 패킷의 끝 주소를 의미
	// data는 패킷의 시작점을 의미
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	// 이더넷 헤더 부분의 끝부분이 패킷 전체 길이보다 바깥에 위치하는 불량 패킷
	// 포인터를 사용하는데, verifier가 메모리 경계 검사를 하기 때문에 필요
	if ((void*)(eth + 1) > data_end)
		return TC_ACT_OK;
	// IPv4만 골라서 하기
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	
	// 패킷 구조:[ethenet header][IP header][TCP/UDP header][Payload]
	// 아래는 지금 IP header의 시작 주소를 설정한 것
	struct iphdr *ip = (void *)(eth +1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	// map_process_track에서 해당 IP, port를 찾아야 되는데 그때 사용할 lookup_key를 설정
	struct ip_port_key lookup_key = {};
	lookup_key.dest_ip = ip->daddr;

	__u32 payload_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

	// TCP인 경우 lookup_key의 port와 payload_offset을 갱신
	if (ip->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		lookup_key.dest_port = bpf_ntohs(tcp->dest);
		payload_offset += (tcp->doff * 4);
	}
        // UPD인 경우 	
	else if(ip->protocol == IPPROTO_UDP)
	{
		struct udphdr *udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		lookup_key.dest_port = bpf_ntohs(udp->dest);
		payload_offset += sizeof(struct udphdr);
	}
	else
	{
		return TC_ACT_OK;
	}

	// lookup_key를 통해 map_process에서 해당 정보를 찾는다
	// map_process의 value는 pid, tid, comm이 존재 
	struct process_info_value *proc_info = bpf_map_lookup_elem(&map_process, &lookup_key);
	if (!proc_info)
		return TC_ACT_OK;

	// map_stats의 key 생성
	struct stats_key s_key = {};
        s_key.pid = proc_info->pid;
	s_key.dest_ip = lookup_key.dest_ip;
	s_key.dest_port = lookup_key.dest_port;

	// 패킷의 길이
	// 패킷 TC hook 지나간 시점
	__u32 pkt_len = skb->len;
	__u64 now_ts = bpf_ktime_get_ns();
	
	// map_stats에서 s_key를 통해 map에 이미 있는지, 없는지를 판단
	struct stats_info *stats = bpf_map_lookup_elem(&map_stats, &s_key);
	
	// map_stats에 이미 해당 key가 존재하는 경우, value 정보 갱신
	if (stats)
	{
		__sync_fetch_and_add(&stats->packet_count, 1);
		__sync_fetch_and_add(&stats->total_bytes, pkt_len);
		__sync_fetch_and_add(&stats->total_sq_bytes, (__u64)pkt_len * pkt_len);
		
		if (now_ts > stats->last_packet_ts)
		{
			__sync_fetch_and_add(&stats->interval_sum, (now_ts - stats->last_packet_ts));
		}
		stats->last_packet_ts = now_ts;
		
		if (pkt_len > stats->max_packet_size)
		{
			stats->max_packet_size = pkt_len;
		}
	}
	// map_stats에 해당 key가 없는 경우, 새로 추가
	else
	{
		// comm 정보 갱신
		struct stats_info new_stats = {};
		__builtin_memcpy(new_stats.comm, proc_info->comm, sizeof(new_stats.comm));
		
		new_stats.packet_count = 1;
		new_stats.total_bytes = pkt_len;
		new_stats.total_sq_bytes = (__u64)pkt_len * pkt_len;
		new_stats.last_packet_ts = now_ts;
		new_stats.interval_sum = 0;
		new_stats.max_packet_size = pkt_len;


		bpf_map_update_elem(&map_stats, &s_key, &new_stats, BPF_ANY);

		stats = bpf_map_lookup_elem(&map_stats, &s_key);
		if (!stats)
			return TC_ACT_OK;
	}

	// byte_frequency[8]을 설정하는 곳. 
	// 여기서는 packet의 payload를 시작으로 첫 64비트를 8개로 나누어 frequency 계산
	// 질문: byte frequency의 시작점을 어디로 해야 좋을까요?
	// 각 패킷마다 해당 bucket에 ++을 하므로 해킷이 지나갈 때마다 누적이 된다. 
	#pragma unroll
	for (int i = 0; i < 64; i++)
	{
		if (payload_offset + i < skb->len)
		{
			__u8 byte_val = 0;
			bpf_skb_load_bytes(skb, payload_offset + i, &byte_val, 1);
			int bucket = byte_val / 32;
			stats->byte_frequency[bucket & 7]++;		
		}
	}

	return TC_ACT_OK;
}





