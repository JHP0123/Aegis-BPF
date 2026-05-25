CC = gcc
CLANG = clang
INCLUDES = -I./include -I/usr/include/bpf
CFLAGS = -g -Wall -O2 $(INCLUDES)
LDFLAGS = -lbpf -lelf -lz -lm

all: aegis

# vmlinux.h 자동 생성 타겟 추가
include/vmlinux.h:
	@echo "  GEN      include/vmlinux.h"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

# bpf 객체 파일 컴파일 시 vmlinux.h에 의존성 부여
bpf/aegis.bpf.o: bpf/aegis.bpf.c include/vmlinux.h
	$(CLANG) -g -O2 -target bpf $(INCLUDES) -c $< -o $@

bpf/aegis.skel.h: bpf/aegis.bpf.o
	bpftool gen skeleton $< > $@

user/controller.o: user/controller.c bpf/aegis.skel.h
	$(CC) $(CFLAGS) -I./bpf -c $< -o $@

aegis: user/controller.o
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f bpf/*.o bpf/aegis.skel.h user/*.o aegis include/vmlinux.h
