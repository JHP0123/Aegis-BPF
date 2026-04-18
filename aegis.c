#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <net/if.h>       // if_nametoindex 사용
#include <linux/if_link.h>
#include <linux/pkt_cls.h>
#include "aegis.skel.h"

// 오류 처리를 위한 매크로
#define CLEANUP() do { aegis_bpf__destroy(skel); } while (0)
// 이 부분은 유저 프로세스, 자동으로 TC와 연결하는 과정을 위해 만든 부분
int main(int argc, char **argv) {
    struct aegis_bpf *skel;
    int err;
    int ifindex = if_nametoindex("ens33"); // 본인의 인터페이스 이름에 맞게 수정

    if (ifindex == 0) {
        fprintf(stderr, "네트워크 인터페이스를 찾을 수 없습니다.\n");
        return 1;
    }

    // 1. Rlimit 설정 (eBPF 메모리 잠금 해제)
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit 실패");
        return 1;
    }

    // 2. 스켈레톤 열기 및 로드
    skel = aegis_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "eBPF 프로그램 로드 실패\n");
        return 1;
    }

    // 3. Kprobe 등 기본 섹션 자동 Attach
    err = aegis_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Kprobe Attach 실패: %d\n", err);
        CLEANUP();
        return 1;
    }

    // 4. TC 필터 자동 장착 (명령어 sudo tc ... 를 대체하는 코드)
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );

    // 4-1. clsact qdisc 생성 (기존에 있으면 무시됨)
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "TC Hook 생성 실패: %d\n", err);
        CLEANUP();
        return 1;
    }

    // 4-2. BPF 프로그램(TC)을 인터페이스에 연결
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = bpf_program__fd(skel->progs.bpf_tc_egress),
    );

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "TC Attach 실패: %d\n", err);
        CLEANUP();
        return 1;
    }

    printf("Aegis-BPF 가동 시작 (Interface: ens33)\n");
    printf("Kprobe 및 TC 필터가 모두 정상적으로 장착되었습니다.\n");
    printf("Ctrl+C를 누르면 종료됩니다.\n\n");

    // 5. 통계 데이터 출력 루프 (1초마다)
    while (1) {
        // 여기에 맵 데이터를 읽어서 출력하는 로직을 넣으시면 됩니다.
        sleep(1);
    }

    // 종료 시 해제 (정상 종료 로직 추가 필요)
    aegis_bpf__destroy(skel);
    return 0;
}