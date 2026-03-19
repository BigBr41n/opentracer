// clang-format off
#include "vmlinux.h"
#include "common.h"
// clang-format on
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/**
 * -- MAPS
 * ======================================
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

/**
 * =========================================
 */

/***
 * Prog A : capture and filter
 * ========================================
 */

SEC("tracepoint/syscalls/sys_enter_openat")
int prog_a_capture(struct trace_event_raw_sys_enter *ctx) {

  // tgid (pid)
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  // Skip PID 0
  if (pid == 0) {
    return 0;
  }

  // lookup our scratch slot
  // key=0 always exists !

  __u32 key = 0;
  struct event *e = bpf_map_lookup_elem(&scratch, &key);

  if (!e)
    return 0;

  e->uid = (__u32)bpf_get_current_pid_tgid();

  /**
   * ctx->args[2] = fmags argument passed to openat() / O_RDONLY ...
   */

  e->flags = (int)ctx->args[2];

  // safely read a null-terminated string from userspace
  // ctx->args[1] = cosnt char * filename & it lives in userspace

  bpf_probe_read_user_str(e->filename, sizeof(e->filename),
                          (const char *)ctx->args[1]);

  bpf_tail_call(ctx, &prog_array, TAIL_ENRICH_AND_EMIT);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";