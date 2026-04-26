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
| `lsm-connect` | `lsm/socket_connect` | Unauthorized outbound network connections |

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

### Workload Identity

Every alert is tagged with a `WorkloadIdentity` using mount namespace IDs — no agent inside containers required.

| Field | Docker | GKE (Phase 2) |
|-------|--------|---------------|
| `Service` | `inventory-service` | `inventory-service` |
| `Pod` | container name | `inventory-service-68ccd-abc` |
| `Namespace` | `""` | `order-processor` |
| `Runtime` | `docker` | `k8s` |

`Service` is the stable logical name used by all detection rules — consistent across runtimes.

Sentinel values for `Service`:
- **`host`** — PID 1 namespace (host process)
- **`unknown-ns`** — unrecognized namespace → possible container escape → CRITICAL alert

---

## Architecture

```
  KERNEL (BPF programs)
  ─────────────────────────────────────────────
  execsnoop         opensnoop         lsm-connect
  sys_enter_execve  enter+exit_openat lsm/socket_connect
       │                  │                 │
       └──────────────────┴─────────────────┘
                          │  RawEvent{Source, Data}
                   rawCh (4096)
                          │
  USERSPACE (Go — buffered pipeline)
  ─────────────────────────────────────────────
  Enricher: parse bytes + resolve WorkloadIdentity (mnt_ns_id → service name)
                          │  EnrichedEvent{Type, Process/File/Net, Workload}
                   enrichedCh (1024)
                          │
  Detector: apply detection rules (pkg/detector)
                          │  Alert{Level, Rule, Workload, ...}
                   alertCh (64)
                          │
  AlertHandler: stdout + alerts/alert.log
```

---

## How to Run

**Requires**: Linux, kernel 5.8+, Go 1.24+, clang/llvm, Docker

```bash
# on the GCP VM
cd ~/workspace/ebpf-edr-demo

# compile eBPF programs and generate Go wrappers (only after editing .bpf.c files)
make generate

# build binary (cross-compiles to linux/amd64 from any host)
make build

# run (requires root for eBPF)
sudo ./ebpf-edr-demo --runtime=docker   # Docker VM
sudo ./ebpf-edr-demo --runtime=k8s      # GKE DaemonSet (Phase 2)
```

Alerts are written to stdout and `alerts/alert.log`.

---

## Project Structure

```
cmd/edr-monitor/
  main.go           — buffered pipeline wiring + --runtime flag
kernel/
  execsnoop.bpf.c   — process execution monitor
  opensnoop.bpf.c   — file access monitor (two-probe enter+exit)
  lsm-connect.bpf.c — network connection monitor
pkg/
  bpf/              — generated BPF loaders (bpf2go output)
  workload/
    identity.go     — WorkloadIdentity struct
    resolver.go     — WorkloadResolver interface + NewResolver()
    docker_resolver.go — Docker implementation (mnt_ns → service name)
  pipeline/
    event.go        — RawEvent, EnrichedEvent, core interfaces
  detector/
    rules.go        — detection rule implementations (RuleDetector)
    policy.go       — allow/block lists (edit here to tune rules)
internal/
  alert/
    alert.go        — Alert struct + Handler (stdout + file)
  processor/
    processor.go    — kernel event structs (must match .h files exactly)
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
