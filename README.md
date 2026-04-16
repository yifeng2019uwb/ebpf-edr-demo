# ebpf-edr-demo

A demonstration of a simple EDR (Endpoint Detection and Response) pipeline using eBPF for kernel-level process monitoring.

Built as a learning project while preparing for a security engineering role. The goal is to show how eBPF can serve as the data collection layer for an EDR system.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Linux Kernel                      │
│                                                     │
│   execve() syscall ──► eBPF tracepoint hook         │
│                              │                      │
│                              ▼                      │
│                    { pid, parent, path }             │
└──────────────────────────────┼──────────────────────┘
                               │ JSON stream (stdout)
                               ▼
┌─────────────────────────────────────────────────────┐
│               Python Agent (userspace)              │
│                                                     │
│   1. Parse JSON event                               │
│   2. Check baseline suppression (known safe procs)  │
│   3. Match against detection rules (rules.yaml)     │
│   4. Print alert + append to alerts/alert.log       │
└─────────────────────────────────────────────────────┘
```

**bpftrace** attaches to the `execve` syscall tracepoint and emits a JSON event every time a new process is spawned — systemwide, in real time.

The **Python agent** reads that stream, applies detection rules, suppresses known baseline processes, and generates structured alerts.

---

## Project Structure

```
ebpf-edr-demo/
├── kernel/
│   ├── execsnoop.bpf.c     # eBPF kernel program (C) — credited below
│   └── execsnoop.h         # eBPF header
├── agent/
│   └── main.py             # Python rules engine (original)
├── rules/
│   └── rules.yaml          # Detection rules + baseline suppression
├── alerts/
│   └── alert.log           # Generated at runtime
├── screenshots/            # CLI output screenshots from GCP VM
├── Makefile                # compile / run / test
└── README.md
```

---

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `shell_spawned_from_server` | CRITICAL | Shell spawned by nginx/apache/python3 — potential RCE |
| `execution_from_tmp` | HIGH | Binary executed from `/tmp` — common malware staging |
| `execution_from_dev_shm` | HIGH | Binary executed from `/dev/shm` — memory-based evasion |

Rules are configurable in `rules/rules.yaml`. Known safe processes can be suppressed via the `baseline` section.

---

## Example Alert Output

```
[EDR Agent] Started — reading bpftrace events from stdin...
[2026-04-16 10:23:41] ALERT severity=HIGH rule=execution_from_tmp pid=12345 parent=bash path=/tmp/test_edr_ls
```

---

## Requirements

- Linux kernel 4.18+ (tested on Debian 12, kernel 6.1.0-44-cloud-amd64)
- bpftrace v0.17.0+
- Python 3.8+
- `pyyaml`: `pip install pyyaml`
- For kernel compile: `clang`, `libbpf-dev`

---

## Usage

**Run the EDR pipeline (bpftrace → Python agent):**
```bash
make run
```

**Trigger a test alert (executes a binary from /tmp):**
```bash
make test
```

**Compile the eBPF kernel C program to BPF bytecode:**
```bash
make compile
```

---

## Screenshots

See [screenshots/](screenshots/) for CLI output captured on a GCP VM (Debian 12):
- Live bpftrace event stream
- Compiled BPF bytecode (`file execsnoop.bpf.o`)
- Triggered alert in terminal

---

## Notes on the Kernel C Code

The files in `kernel/` (`execsnoop.bpf.c`, `execsnoop.h`) are copied from the [eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) (src/7-execsnoop), used here for educational purposes with credit to the original authors.

The bpftrace one-liner used for runtime monitoring is original and designed for portability across kernel versions. A production EDR implementation would replace the bpftrace layer with a compiled libbpf program in C (the `kernel/execsnoop.bpf.c` file demonstrates what that looks like at the kernel level).

---

## What This Demonstrates

- How eBPF attaches to kernel syscall tracepoints without modifying kernel code
- How process execution events flow from kernel to userspace
- A basic rules engine pattern used in real EDR systems
- Defense-in-depth thinking: kernel visibility → userspace analysis → structured alerting
