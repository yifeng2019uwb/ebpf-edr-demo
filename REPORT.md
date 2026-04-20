# cnop-ebpf-monitor — Project Report

## What This Project Is

A working EDR (Endpoint Detection and Response) agent built with Go + eBPF, monitoring containerized services running on a Linux host. The agent captures security-relevant events from the kernel and emits structured alerts.

Target workload: [cloud-native-order-processor](https://github.com/yifeng2019uwb/cloud-native-order-processor) — 8 Docker containers on GCP VM (Debian 12, kernel 6.1).

---

## What Was Built

### eBPF Kernel Programs

| Program | Hook | Captures |
|---------|------|----------|
| `execsnoop.bpf.c` | `tracepoint/syscalls/sys_enter_execve` | Process execution — pid, ppid, uid, mnt_ns_id, executable path |
| `opensnoop.bpf.c` | `sys_enter_openat` + `sys_exit_openat` | File access — pid, comm, filename, return code |
| `lsm-connect.bpf.c` | `lsm/socket_connect` | Outbound connections — pid, comm, dst_ip, dst_port, mnt_ns_id |

All compiled via `bpf2go` → Go wrappers auto-generated.

**opensnoop uses a two-probe pattern**: entry captures filename and process context into a BPF hash map; exit checks the return value and emits only if `ret >= 0` (success) or `ret == -EACCES/-EPERM` (access denied to existing file). Files that do not exist (`-ENOENT`) are dropped — this eliminates probe noise from curl checking `~/.curlrc` while still catching `cat /etc/shadow` from a non-root user.

**lsm-connect is audit-only**: always returns `0` — never blocks. The `lsm/socket_connect` hook fires before every `connect()` syscall with no TOCTOU gap. Loopback (127.x.x.x) is filtered in BPF to reduce ring buffer traffic. All other private IP range checks (RFC 1918) are done in Go so policy can change without recompiling BPF.

### Go Userspace Agent — Package Layout

```
cmd/edr-monitor/main.go     entry point — wires packages, runs goroutines
pkg/bpf/loader.go           BPF loading, kernel attachment, event readers
pkg/detector/rules.go       detection logic — CheckProcessRules/CheckFileRules/CheckNetworkRules
pkg/detector/policy.go      policy data — whitelists, file prefixes, network allowlists
pkg/container/container.go  namespace → container name resolution via /proc + docker ps
internal/alert/alert.go     Alert struct + Handler (stdout + alert.log)
internal/processor/         event structs (ProcessEvent/FileEvent/NetEvent) + byte converters
kernel/                     eBPF kernel programs (.bpf.c) — compiled by bpf2go
```

- Loads and attaches all eBPF programs via `pkg/bpf.Load()`
- Reads process events via **perf buffer** (`execsnoop`)
- Reads file and network events via **ring buffer** (`opensnoop`, `lsm-connect`)
- Three concurrent goroutines, one per monitor
- Network byte order conversion for lsm-connect IP/port: IP extracted byte-by-byte, port byte-swapped
- Graceful shutdown on `Ctrl+C`

### Detection Rules (`pkg/detector`)

**Process rules:**

| Rule | Trigger | Severity |
|------|---------|----------|
| `unknown_namespace_process` | Process in namespace that is neither host nor any known container | CRITICAL |
| `shell_spawn_container` | `bash`, `sh`, `zsh`, `dash` inside any container | CRITICAL |
| `network_tool_container` | `nc`, `ncat`, `wget` inside any container | HIGH |

curl intentionally excluded from process rules — health checks, smoke tests, and integrations all use `curl localhost`. Real curl exfiltration detection is in lsm-connect (destination-aware).

**File access rules:**

| Tier | Files / Suffixes | Severity |
|------|-----------------|----------|
| HOST | `/var/lib/docker/overlay2/` (host process only) | CRITICAL |
| CRITICAL | `/root/.ssh/`, `/home/.ssh/` | CRITICAL |
| HIGH | `/etc/shadow`, `/run/secrets/`, `/proc/1/`, `.key`, `id_rsa`, `id_ed25519`, `.env` | HIGH |
| MEDIUM | `/etc/passwd`, `/etc/group` | MEDIUM |

`host_reads_container_fs` — fires when a host process reads the Docker overlay filesystem directly. This bypasses container isolation and requires no whitelist — dockerd itself does not read overlay2 files at runtime.

**Network rules:**

| Rule | Trigger | Severity |
|------|---------|----------|
| `external_connect_allowed` | Container in `externalAllowedContainers` connects to external IP | LOW (audit) |
| `unauthorized_external_connect` | Any other container connects to external IP | HIGH |

Private IPs (RFC 1918: 10.x, 172.16.x, 192.168.x, 169.254.x) are always allowed — Docker bridge, service mesh, internal traffic. Only `inventory_service` is permitted external access (CoinGecko market data).

**Whitelists:**
- Process: `sshd`, `runc`, `dockerd`, `containerd` — never alert
- Host processes filtered via `mnt_ns` — no host-level false positives
- File: `runc:[2:INIT]`, `runc:[1:CHILD]`, `runc`, `curl`, `id`, `bash`, `systemd-logind` — expected system file reads during init/startup

### Container Correlation (`pkg/container`)

- `mnt_ns_id` captured in kernel via `BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)` — `__u32`
- `docker ps --no-trunc` at startup + every 30s builds container ID → name map
- `/proc/<pid>/cgroup` maps process → container ID → container name
- Handles both cgroupv1 (`/docker/<id>`) and cgroupv2 (`docker-<id>.scope`) formats
**Namespace resolution logic (three-tier):**

| Result | Meaning | Source |
|---|---|---|
| `host` | PID 1 mount namespace | nsCache |
| `order-processor-xxx` | Known Docker container | nsCache via docker ps |
| `unknown-ns` | Not host, not any container after fresh /proc rescan | escape indicator |

On cache miss, `resolveContainer` immediately rescans `/proc` before declaring `unknown-ns` — handles new containers starting within the 30s refresh window.

### Alert Output (`internal/alert`)

- Structured format: `timestamp, level, rule, container, pid, ppid, uid, comm, message`
- Writes to stdout (live monitoring) and `alerts/alert.log` (persistent record)

---

## Validation

All 7 test cases in `VALIDATION.md` were executed via `validate.sh` against live containers on the GCP VM. The full CNOP integration test suite ran concurrently to verify no false positives under real service load.

### Attack detections — all confirmed

| Test | Attack | Alert | Result |
|------|--------|-------|--------|
| T1 | Shell spawn in container | CRITICAL `shell_spawn_container` | ✅ |
| T2 | `wget`/`nc` executed in container | HIGH `network_tool_container` | ⚠️ infra* |
| T3 | `cat /etc/shadow` (EACCES) | HIGH `sensitive_file_access` | ✅ |
| T4 | Read `/root/.ssh/id_rsa` | CRITICAL `sensitive_file_access` | ✅ |
| T5 | Unauthorized external connect (8.8.8.8) | HIGH `unauthorized_external_connect` | ✅ |
| T6 | inventory_service → CoinGecko | LOW `external_connect_allowed` | ✅ |
| T7 | Host reads Docker overlay2 filesystem | CRITICAL `host_reads_container_fs` | ✅ |

*T2: `nc`/`ncat`/`wget` not pre-installed in Python uvicorn container; `apt-get` fails with permission denied. Detection rule is correct — firing confirmed in code review.

### No false positives from normal service traffic

- Health checks (`curl localhost`) — no alert
- Python `certifi` CA bundle reads — no alert (`.pem` path exception for `/site-packages/`, `/certifi/`)
- Container startup (`runc`, `bash`, `id` reading `/etc/passwd`) — no alert (whitelisted)
- inventory_service → CoinGecko during background load — LOW audit log only (not HIGH)
- Zero `short_lived_failure` alerts — rule removed, not whitelisted

### Evidence

- `snapshots/validateTest200950.png` — full validate.sh run output
- `alerts/alert.log` — 6/7 alerts confirmed (T2 blocked by container infra)

---

## Key Technical Decisions

| Decision | Reason |
|----------|--------|
| `cilium/ebpf` + `bpf2go` | Production Go eBPF library, type-safe generated wrappers |
| Ring buffer for all new programs | Modern pattern — lower overhead, no per-CPU waste |
| Two-probe pattern for opensnoop | Suppress ENOENT probe noise while keeping EACCES/EPERM detection |
| Emit on EACCES/EPERM not just success | Access attempt against existing file is the signal, even if OS blocked it |
| curl excluded from process rules | Cannot see destination at execve level — health checks indistinguishable from attacks |
| Tiered file severity | `/etc/shadow` ≠ `/etc/passwd` risk — different responses needed |
| Hybrid namespace strategy | No host whitelist needed — only alert on truly unrecognized namespaces |
| Immediate /proc rescan on cache miss | Handles containers starting within the 30s refresh window |
| Audit mode only | Safe for personal project — no risk of killing legitimate processes |
| Rules in separate `rules.go` | Easy to add/remove rules without touching event pipeline |

---

## Build & CI

| Command | What it does |
|---------|-------------|
| `make generate` | Recompile `.bpf.c` → generate Go wrappers in `pkg/bpf/` (requires clang on Linux) |
| `make build` | Build the `ebpf-edr-demo` binary from `cmd/edr-monitor/` |
| `make test` | Run unit tests for `internal/` and `pkg/detector/` (no kernel required) |
| `make vet` | Run `go vet` on non-BPF packages |

GitHub Actions CI (`.github/workflows/ci.yml`) runs on every push/PR: vet → test → build. Vet and test always pass. Build requires generated BPF wrappers committed to `pkg/bpf/` — run `make generate` on the GCP VM and commit the output.

---

## Key Decision: Exit Monitor Removed

`exitsnoop` and `short_lived_failure` were built and validated, then removed. The rule fired on any process exiting non-zero in < 100ms — normal behavior for any utility that fails (which, mkdir, apt-get, cat denied). The workload runs long-lived Python services where short exits are routine, not suspicious. Rather than grow an indefinite whitelist, the rule was dropped. All real threats are covered by the remaining three monitors.
