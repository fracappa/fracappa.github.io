---
title: "Towards reducing manual intervention onto cluster with eghostbuster: Stale Lock File Cleanup with eBPF"
date: 2026-03-28
summary: "eghostbuster now detects and removes orphaned lock files left behind by crashed processes, using eBPF tracepoints to track file creation and process exit events"
tags:
  - BPF
  - Linux
  - Go
  - Systems Programming
authors:
  - me
featured: true
---

eghostbuster started as a tool to clean up TCP sockets stuck in `CLOSE_WAIT`. With v0.2.0, it now tackles another class of ghost resources: **stale lock files**.

## The Problem

Lock files (`.lock`, `.lck`) are a simple and widespread coordination mechanism. A process creates a lock file to signal exclusive access to a resource, and removes it when done. But when a process crashes, gets killed, or exits abnormally, the lock file stays behind. The result: other processes that respect the lock are blocked indefinitely, waiting for a lock holder that no longer exists.

This affects package managers, databases, build systems, and any application that relies on file-based locking.

## How It Works

The new feature hooks into two kernel tracepoints via eBPF:

1. **`sys_enter_openat/sys_enter_openat2`** -- intercepts file creation calls and checks if the filename ends in `.lock` or `.lck`. When a match is found, eghostbuster records the mapping between the creating process's PID and the filename in a BPF hash map.

2. **`sched_process_exit`** -- fires when any process exits. eghostbuster looks up the PID in the map and, if it was tracking a lock file for that process, emits an event to a ring buffer.

On the user-space side, a new `FileLocksMonitor` goroutine reads events from the ring buffer. When it receives a process exit notification for a tracked PID, it checks if the lock file still exists on disk and removes it.

```
    Process A                     Kernel                    eghostbuster
       |                            |                            |
       |-- openat("app.lock") ---->|                            |
       |                            |-- sys_enter_openat ------>|
       |                            |   (record PID -> file)    |
       |                            |                            |
       X  (crash / SIGKILL)         |                            |
       |                            |-- sched_process_exit ---->|
       |                            |   (emit exit event)       |
       |                            |                            |
       |                            |   check file exists?      |
       |                            |   rm app.lock             |
       |                            |                            |
    Process B                       |                            |
       |-- openat("app.lock") ---->|  (succeeds, lock is gone) |
```

## Architecture Changes

The original single-monitor design has been refactored to run multiple monitors concurrently using an `errgroup`. The existing stale socket monitor (`StartStaleSocketMonitor`) and the new lock file monitor (`StartFileLocksMonitor`) now run as independent goroutines under a shared context, so a signal or cancellation cleanly shuts down both.

New BPF maps introduced:

- **`file_process_map`** -- hash map associating PIDs with lock filenames
- **`exit_events`** -- ring buffer for delivering process exit events to user space
- **`file_info_scratch`** -- per-CPU array used as scratch space for reading filenames from user memory in the eBPF program

## Limitations and Next Steps

This is a first implementation. Some areas for future improvement:

- Only tracks files created with `O_CREAT` via `openat` -- files created through other syscalls or renamed into place are not yet covered
- Filename matching is suffix-based (`.lock` / `.lck`) -- configurable patterns would be more flexible
- No persistence across eghostbuster restarts -- if eghostbuster is restarted, tracking state is lost

## Resources

- [GitHub Repository](https://github.com/fracappa/eghostbuster)