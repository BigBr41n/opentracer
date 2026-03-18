# opentracer

Traces every openat() syscall system-wide and streams file open events to userspace in real time.

---

## What it does

Attaches to the sys_enter_openat tracepoint. For every file open:

- Captures PID, UID, process name, filename, and flags
- Streams events to userspace via ring buffer

---
