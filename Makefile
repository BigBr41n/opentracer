CLANG := clang

ARCH := $(shell uname -m \
    | sed 's/x86_64/x86/' \
    | sed 's/aarch64/arm64/' \
    | sed 's/armv7l/arm/')

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
USER_CFLAGS := -O2 -g

all: prog.bpf.o opentracer

# BPF program
prog.bpf.o: prog.bpf.c common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -c prog.bpf.c -o prog.bpf.o

# Skeleton (auto-generate)
opentracer.skel.h: prog.bpf.o
	bpftool gen skeleton prog.bpf.o > opentracer.skel.h

# Userspace
opentracer: opentracer.c opentracer.skel.h
	$(CLANG) $(USER_CFLAGS) opentracer.c -o opentracer -lbpf

clean:
	rm -f *.o opentracer opentracer.skel.h