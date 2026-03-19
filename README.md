# opentracer

Traces every openat() syscall system-wide and streams file open events to userspace in real time.


## What it does

Attaches to the sys_enter_openat tracepoint. For every file open:

- Captures PID, UID, process name, filename, and flags
- Streams events to userspace via ring buffer


## Architecture

```
openat() called
  → prog_a_capture   (tracepoint)
      filter PID 0
      fill scratch (percpu)
      tail call
  → prog_b_emit      (tail call target)
      add comm name
      submit to ringbuf
  → userspace handle_event()
      print event
```

## Maps 

- `scratch`: PERCPU_ARRAYpass data across tail call
- `prog_array`: PROG_ARRAYtail call dispatch
- `events`: RINGBUFstream events to userspace


## Build 

```
# Requirements: clang, bpftool, libbpf-dev
make
```

## Run 
```
sudo ./opentracer
```


## Output 

```
PID: 1234    UID: 1000  COMM: bash              FLAGS: 0x0     FILE: /etc/passwd
PID: 5678    UID: 0     COMM: nginx             FLAGS: 0x1     FILE: /var/log/nginx/access.log
```


## Key concepts

- Tracepoint vs kprobe: tracepoints are stable ABI, won't break across kernel versions
- Tail call: prog_a handles intake, prog_b handles emit — stages are independently swappable via prog_array at runtime
- PERCPU_ARRAY scratch: BPF stack is wiped on tail call entry; percpu map is the side channel
- Ringbuf vs array: ringbuf has epoll notification — userspace sleeps until data arrives instead of polling

