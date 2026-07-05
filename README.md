# Aegis-BPF

__eBPF 기반 실시간 커널 트래픽 분석 및 초경량 사용자 중심 보안 시스템__

## 1. Project Overview

- __Background__: 개발 친화적인 Linux 데스크톱 환경의 점유율이 상승하고 있으나, 기존 개인용 보안 프로그램은 잦은 Context Switching을 유발하여 시스템 성능을 크게 저하시키는 구조적 한계가 존재

- __Objective__: 리눅스 커널 수준의 eBPF 기술을 사용하여 Context Switching을 최소화하고 시스템 자원 소모를 최소화 하는 사용자 친화적 실시간 보안 시스템을 제안

## 2. Core Features

- __Kernel-level Inline Filtering__: 패킷이 NIC로 빠져나가기 직전인 TC에서 bpf_tc_egress Hook을 통해 실시간 패킷 검사 수행. 위협으로 판단되는 패킷은 즉시 TC_ACT_SHOT을 반환하여 유저 영역 개입 없이 커널 계층에서 DROP.

- __Lock-Free Concurrency Optimization__: 대용량 트래픽 환경에서 멀티코어 CPU의 Lock 충돌을 방지하기 위해 통계 수집 맵인 map_stats을 BPF_MAP_TYPE_LRU_PERCPU_HASH로 설계. 각 코어가 독립적인 메모리 공간에 패킷 통계를 기록.

- __Host-based Process Visibility__: 패킷의 IP/Port 4-Tuple 정보만으로는 추적하기 힘든 악성 행위의 주체를 식별. kprobe/tcp_sendmsg 훅을 사용하여 커널 소켓 정보와 bpf_get_current_pid_tgid()를 결합하여 어떤 프로세스(PID, comm)가 해당 트래픽을 발생시켰는지를 매핑. 

- __Asynchronous Polling & Zero-Copy__: 유저 스페이스 데몬(controller.c)은 패킷 페이로드를 복사해 가져오는 대신, epoll과 timerfd를 이용해 1초 주기로 커널 map의 통계치만 비동기적으로 폴링. 이를 통해 context switching을 최소화.

- __Automated Garbage Collection__: 소켓이 닫히는 시점인 kprobe/tcp_close에 Hook을 걸어서 종료된 세션의 BPF Map 데이터를 즉시 삭제. 이를 통해 발생할 수 있는 커널 메모리 누수를 차단.

## 3. System Architecture

- Aegis-BPF는 Kernel Space와 User Space의 분리된 아키텍처로 구성

- <아키텍처 그림>

### Kernel Space(데이터 수집 및 즉각 차단)

- __1. Flow & Process Mapping(map_process)__
    - tcp_sendmsg 시스템 콜에 Hook을 걸어서 IP와 Port를 추출
    - 추출된 4-Tuple key(Dest IP/port, Source IP/port)를 기준 삼아 패킷을 전송하는 주체의 프로세스 정보(aegis_process_info)를 LRU Hash Map인 map_process에 저장

- __2. Traffic Accounting (map_stats)__
    - TC Hook에서 Egress 패킷의 헤더를 파싱하여 L3, L4 정보를 추출
    - Per-CPU Hash Map인 map_stats을 사용하여 패킷 크기와 해당 시점의 타임스탬프를 Lock 없이 빠르게 추출 후 갱신.

- __3. Fast-Path Enforcement (map_enforcement)__
    - 패킷 송신 전, 정책 Map인 map_enforcment을 조회하여 flag == 1일 경우 TC_ACT_SHOT으로 패킷을 DROP.

### User Space(통계 분석 및 탐지 엔진)

- __1. Event Loop (epoll & timerfd)__
    - 
