# ebpf-edr-demo

eBPF-based runtime security monitor for containerized services, built for endpoint security and EDR (Endpoint Detection and Response) research.

---

## Background

This project monitors [cloud-native-order-processor](https://github.com/yifeng2019uwb/cloud-native-order-processor) — a production-style microservices platform deployed on a GCP VM (Debian 12, kernel 6.1).

The order processor runs 8 Docker containers:

| Container           | Role                                          |
|---------------------|-----------------------------------------------|
| `gateway`           | Go API gateway, port 8080                     |
| `auth_service`      | Python/uvicorn, JWT authentication            |
| `user_service`      | Python/uvicorn, balance and portfolio         |
| `inventory_service` | Python/uvicorn, asset catalog                 |
| `order_service`     | Python/uvicorn, trade execution               |
| `insights_service`  | Python/uvicorn, AI portfolio insights         |
| `redis`             | Rate limiting, IP blocking, distributed locks |
| `localstack`        | DynamoDB (local AWS emulation)                |

The goal: attach eBPF probes to the running kernel on the GCP VM, observe all 8 services at the syscall and network level, and generate security alerts — without modifying any service code.

---

## What It Does

Three eBPF monitors run concurrently, each sending events to Go userspace via ring buffer:

| Monitor | Hook | Detects |
|---|---|---|
| `execsnoop` | `sys_enter_execve` | Shell spawns, network tools inside containers |
| `opensnoop` | `sys_enter/exit_openat` | Sensitive file access — shadow, SSH keys, secrets |
| `exitsnoop` | `sched_process_exit` | Short-lived failures — possible crashed exploits |
| `lsm-connect` _(planned)_ | `lsm/socket_connect` | Unauthorized outbound network connections |

### Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| `unknown_namespace_process` | Process in unrecognized namespace — container escape | CRITICAL |
| `shell_spawn_container` | bash/sh/zsh/dash spawned inside container | CRITICAL |
| `host_reads_container_fs` | Host process reads `/var/lib/docker/overlay2/` | CRITICAL |
| `sensitive_file_access` | `/etc/shadow`, `.ssh/`, `.key`, secrets | HIGH |
| `network_tool_container` | nc, ncat, wget inside container | HIGH |
| `sensitive_file_access` | `/etc/passwd`, `/etc/group` | MEDIUM |
| `short_lived_failure` | Non-zero exit + duration < 100ms | LOW |

### Container Correlation

Every alert is tagged with the container name (`order-processor-auth_service`, etc.) using mount namespace IDs — no agent inside containers required.

Namespace resolution uses a three-tier strategy:
- **`host`** — PID 1 namespace
- **`order-processor-xxx`** — known Docker container
- **`unknown-ns`** — unrecognized namespace after fresh `/proc` rescan → escape alert

---

## Architecture

```
  KERNEL (BPF programs)
  ─────────────────────────────────────────────
  execsnoop         opensnoop          exitsnoop
  sys_enter_execve  enter+exit_openat  sched_process_exit
       │                  │                 │
       └──────────────────┴─────────────────┘
                          │
                   BPF Ring Buffer
                          │
  USERSPACE (Go — main.go)
  ─────────────────────────────────────────────
  3 goroutines read events concurrently
       │
  resolve container (mnt_ns → docker ps → name)
       │
  match detection rules (rules.go)
       │
  emit alert → stdout + alerts/alert.log
```

---

## How to Run

**Requires**: Linux, kernel 5.8+, Go 1.21+, clang/llvm, Docker

```bash
# on the GCP VM
cd ~/workspace/ebpf-edr-demo

# compile eBPF programs and generate Go wrappers
go generate ./...

# build
go build

# run (requires root for eBPF)
sudo ./ebpf-edr-demo
```

Alerts are written to stdout and `alerts/alert.log`.

---

## Project Structure

```
kernel/
  execsnoop.bpf.c   — process execution monitor
  execsnoop.h       — shared struct (C + Go)
  exitsnoop.bpf.c   — process exit monitor
  exitsnoop.h       — shared struct
  opensnoop.bpf.c   — file access monitor (two-probe enter+exit)
  opensnoop.h       — shared struct
main.go             — loads BPF, reads events, dispatches to rules
rules.go            — all detection logic
container.go        — namespace → container name resolver + pid cache
alert.go            — alert struct and log writer
```

---

## Key Design Decisions

- **BPF = wide net** — collect all events, minimal kernel-side filtering
- **Go = smart rules** — all detection logic in userspace with full context
- **Two-probe opensnoop** — entry captures filename, exit checks return code; drops `ENOENT` (probe noise) but keeps `EACCES`/`EPERM` (real access attempts)
- **curl excluded from process rules** — health checks and tests all use curl on localhost; destination-aware detection belongs in lsm-connect
- **No host whitelist** — hybrid namespace strategy catches escapes without enumerating every legitimate host process
- **Audit mode only** — alerts only, no blocking; safe for a live demo environment

---

## Legacy

Original learning project using bpftrace + Python. See [legacy/](legacy/).
