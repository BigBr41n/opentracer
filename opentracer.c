#include "common.h"
#include "opentracer.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * Globals
 */

static volatile int running = 1;

/**
 * Signals
 */

static void sig_handler(int sig) {
  (void)sig;

  running = 0;
}

/**
 * Event callback called by ring_buffer__poll() for each event
 * ctx : user-provided context pointer -- NULL passed
 * data : pointer to raw bytes in the ring buffer slot
 * size : number of bytes (sizeof(struct event))
 * returns :
 *  0 : ok
 *  <0: stop polling
 */

static int handle_event(void *ctx, void *data, size_t size) {

  /**Sanity check: drop malformed events */
  if (size < sizeof(struct event)) {
    fprintf(stderr, "unexpected event size: %zu\n", size);
    return 0;
  }

  struct event *e = (struct event *)data;

  printf("PID: %-6u  UID: %-4u  COMM: %-16s  FLAGS: 0x%-4x  FILE: %s\n", e->pid,
         e->uid, e->comm, (unsigned)e->flags, e->filename);

  return 0;
}

int main(void) {
  int err = 0;

  /** register signals */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  struct prog_bpf *skel = prog_bpf__open_and_load();

  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton: %s\n",
            strerror(errno));
    return 1;
  }

  /** return the FD odf prog b and the fd of the map*/

  int prog_b_fd = bpf_program__fd(skel->progs.prog_b_emit);
  int map_fd = bpf_map__fd(skel->maps.prog_array);

  __u32 index = TAIL_ENRICH_AND_EMIT;

  err = bpf_map_update_elem(map_fd, &index, &prog_b_fd, BPF_ANY);

  if (err) {
    fprintf(stderr, "Failed to insert prog_b into prog_array: %s\n",
            strerror(-err));
    goto cleanup;
  }

  err = prog_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF programs: %s\n", strerror(-err));
    goto cleanup;
  }

  /** create an epoll-backed reader for the ringbuffer */
  struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                            handle_event, NULL, NULL);

  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer reader\n");
    err = 1;
    goto cleanup;
  }
  printf("Tracing openat()... Ctrl+C to stop.\n");
  printf("%-10s %-6s %-6s %-18s %-8s %s\n", "", "PID", "UID", "COMM", "FLAGS",
         "FILE");

  /** Poll loop */
  while (running) {
    err = ring_buffer__poll(rb, 100);
    if (err < 0 && err != -EINTR) {
      /* EINTR = interrupted by signal (e.g. Ctrl+C) — not a real error */
      fprintf(stderr, "ring_buffer__poll error: %d\n", err);
      break;
    }
    err = 0; /* reset — negative poll result is not a fatal exit code */
  }

  ring_buffer__free(rb);

cleanup:
  /*
   * opentracer__destroy():
   *   Detaches tracepoints, unloads BPF programs, destroys maps.
   *   Always call this — even on error paths — to avoid kernel resource leaks.
   */
  prog_bpf__destroy(skel);
  return err;
}