---
title: "eghostbuster: An eBPF-based tool for detecting and cleaning up stale kernel resources"
date: 2026-02-14
summary: "Learn how eghostbuster uses eBPF to detect and automatically clean up stale kernel resources like stuck TCP sockets in Linux systems"
tags:
  - BPF
  - Linux
  - Go
  - Systems Programming
  - Networking
authors:
  - me
featured: true
---

Kernel resources can become trapped in problematic states, consuming memory, blocking processes, and potentially causing production failures. **eghostbuster** is an eBPF-based utility I built to detect and automatically clean up these "ghost" resources in Linux systems.

## The Problem

Stale kernel resources accumulate through various mechanisms:

- Unexpected process terminations without proper cleanup routines
- Applications failing to release sockets, locks, and other resources
- Network interruptions leaving connections in lingering states
- Resource lifecycle management bugs

A common example is TCP sockets stuck in the `CLOSE_WAIT` state. When the remote peer closes a connection but the local application never calls `close()`, the socket remains indefinitely, holding onto kernel memory and potentially exhausting available ports.

## The Solution

eghostbuster leverages eBPF technology to accomplish three key objectives:

1. **Real-time monitoring**: Intercepts kernel function calls to track resource state changes as they occur
2. **Stale resource identification**: Flags resources exceeding configurable timeout thresholds
3. **Automated cleanup**: Releases identified stale resources proactively

## How It Works

The tool attaches eBPF programs to kernel functions related to TCP socket state transitions. When a socket enters `CLOSE_WAIT`, eghostbuster starts tracking it. If the socket remains in that state beyond the configured timeout, it forcibly destroys the socket.

```
           Application           Remote Peer
                |                     |
                |   <-- FIN --------- |  (remote closes)
                |   --- ACK --------> |
                |                     |
           [CLOSE_WAIT]               |
                |                     |
                X  (app never closes) |
                |                     |
         eghostbuster detects         |
         and cleans up after          |
         timeout expires              |
```

## Requirements

- Linux kernel 5.8+ (BTF and CO-RE support required)
- BTF enabled at `/sys/kernel/btf/vmlinux`
- Root or elevated capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`)
- Go 1.21+, Clang/LLVM, bpftool, and iproute2

## Building and Running

```bash
# Generate vmlinux.h and Go structs
make generate

# Compile the binary
make build

# Build and execute with sudo
make run
```

## Basic Usage

```bash
sudo ./eghostbuster
```

The tool will start monitoring TCP sockets and automatically clean up any that get stuck in `CLOSE_WAIT` beyond the timeout threshold.

## Technical Implementation

The project is written in Go with eBPF programs in C. Key components:

- **eBPF programs**: Attach to kernel tracepoints/kprobes to monitor socket state transitions
- **User-space daemon**: Manages eBPF program lifecycle, processes events, and triggers cleanup
- **cilium/ebpf**: Go library for loading and interacting with eBPF programs

## Planned Enhancements

- File lock cleanup functionality
- Shared memory and IPC resource cleanup
- Configurable timeout thresholds via command-line flags
- Metrics export for monitoring systems

## Resources

- [GitHub Repository](https://github.com/fracappa/eghostbuster)
- [eBPF Documentation](https://ebpf.io/)
- [cilium/ebpf Library](https://github.com/cilium/ebpf)

---

Licensed under Apache 2.0.
