// clang-format off
#include "vmlinux.h"
#include "common.h"
// clang-format on
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/**
 * -- MAPS
 * ============
 */

/**
 * events, a ring buffer for streaming events to userspace
 * type : RINGBUF
 * max_entries : must be power of 2
 */

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/**
 * prog array, holds tail call targets
 * type : PROG_ARRAY (values : BPF programs FDs)
 * max_entries : 1 slot
 * userspace fills this at startup before attaching
 */

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} prog_array SEC(".maps");

/**
 * scratch, per-CPU temp storage to pass data across tail call
 * "same stack frame" / "data needs to be preserved somewhere"
 * no locking needed, each CPU with it's slot
 * type : PERCPU_ARRAY
 * max_entries : 1 slot
 */

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct event));
} scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat") int handle_openat(void *ctx) {
  return 0;
}

char LICENSE[] SEC("license") = "GPL";