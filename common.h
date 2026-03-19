#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#define TASK_COMM_LEN 16 /* max length of process name (kernel constant)*/
#endif

/*

* common.h - shared between BPF side and userspace sied

* anything crosses the BPF <-> userspace boundry must be defined here, so both
sides agree on the layout

*/

#define FILENAME_LEN 128 /* max filename chars we capture*/

/*
 * struct event - one record emitted per openac() call
 *
 * BPF fills this and submit to ringbuf
 * Userspace reads it out and prints it
 */

struct event {
  __u32 pid; /* process ID that called openat()*/

  __u32 uid; /* user ID of that process*/

  char comm[TASK_COMM_LEN];    /* process names ... something like : "nginx",
                                "bash"*/
  char filename[FILENAME_LEN]; /* patch passed to openat()*/
  int flags;                   /* openat flags: O_RDONLY, O_WRONLY...*/
};
