# cnop-ebpf-monitor — Project Report

## What This Project Is

A working EDR (Endpoint Detection and Response) agent built with Go + eBPF, monitoring containerized services running on a Linux host. The agent captures security-relevant events from the kernel and emits structured alerts.

Target workload: [cloud-native-order-processor](https://github.com/yifeng2019uwb/cloud-native-order-processor) — 8 Docker containers running on GCP VM (Debian 12, kernel 6.1).

---

## What Was Built

### eBPF Kernel Programs

| Program | Hook | Captures |
|---------|------|----------|
| `execsnoop.bpf.c` | `tracepoint/syscalls/sys_enter_execve` | Process execution — pid, ppid, uid, full executable path |
| `exitsnoop.bpf.c` | `tracepoint/sched/sched_process_exit` | Process exit — pid, exit code, duration |

Both compiled via `bpf2go` → Go wrappers auto-generated.

### Go Userspace Agent (`main.go`)

- Loads and attaches all eBPF programs using `cilium/ebpf`
- Reads process events via **perf buffer** (`execsnoop`)
- Reads exit events via **ring buffer** (`exitsnoop`) — modern pattern
- Two concurrent goroutines, one per monitor
- Graceful shutdown on `Ctrl+C`

### Detection Rules (`rules.go`)

| Rule | Trigger | Severity |
|------|---------|----------|
| `shell_spawn_container` | `bash`, `sh`, `zsh`, `dash` inside any container | CRITICAL |
| `network_tool_container` | `nc`, `ncat`, `wget` inside any container | HIGH |
| `curl_from_container` | `curl` from non-allowed container | MEDIUM |
| `short_lived_failure` | Process exits < 100ms with non-zero code | LOW |

- Whitelist: `sshd`, `runc`, `dockerd`, `containerd` — never alert
- Host processes filtered via `mnt_ns` — no host-level false positives
- `curlAllowedContainers` list: `inventory_service` allowed (calls CoinGecko). Easy to extend.
- `allowedMarketAPI = "api.coingecko.com"` reserved for lsm-connect network enforcement

### Container Correlation (`container.go`)

- Reads `mnt_ns_id` from kernel via `BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)`
- At startup: calls `docker ps --no-trunc` to build container ID → name map
- Resolves `mnt_ns_id → "order-processor-auth_service"` for every alert
- Refreshes every 30s to catch new/stopped containers

### Alert Output (`alert.go`)

- Structured alert format: `timestamp, level, rule, container, pid, ppid, uid, comm, message`
- Writes to stdout (live monitoring)
- Writes to `alerts/alert.log` (persistent record)
- Extensible: TODO slots for Slack webhook and email

---

## Validation

### Detection confirmed working

- Triggered `curl` inside `order-processor-auth_service` container
- Agent fired `curl_from_container` MEDIUM alert within milliseconds
- Alert correctly logged to `alerts/alert.log` with all fields

### No false positives during normal operation

- Ran full CNOP integration test suite while agent was running
- All integration tests passed
- No spurious alerts from normal container-to-container traffic

### Evidence

- `legacy/screenshots/ebpf-alert1.png` — alert firing alongside integration tests
- `alerts/alert.log` — sample alert output

---

## Key Technical Decisions

| Decision | Reason |
|----------|--------|
| `cilium/ebpf` + `bpf2go` | Production Go eBPF library, type-safe generated wrappers |
| Ring buffer for exitsnoop | Modern pattern — lower overhead, no per-CPU waste |
| uid-based filtering (uid=0) | Practical container detection before full `mnt_ns` correlation |
| Audit mode only | Safe for personal project — no risk of killing legitimate processes |
| Rules in separate `rules.go` | Easy to add/remove rules without touching event pipeline |

---

## What's Next

- Rewrite `opensnoop.bpf.c` with ring buffer — file access monitoring (credential theft detection)
- Rewrite `lsm-connect.bpf.c` with ring buffer — network enforcement layer (block + log connections)
- Go unit tests — `rules_test.go`, `container_test.go`
- Final validation: run all integration tests + trigger all detection rules
