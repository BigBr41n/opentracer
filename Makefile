CLANG := clang

ARCH := $(shell uname -m \
    | sed 's/x86_64/x86/' \
    | sed 's/aarch64/arm64/' \
    | sed 's/armv7l/arm/')

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

all: prog.bpf.o

prog.bpf.o: prog.bpf.c common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -c prog.bpf.c -o prog.bpf.o

clean:
	rm -f *.o