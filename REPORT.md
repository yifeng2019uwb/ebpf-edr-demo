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
| `exitsnoop.bpf.c` | `tracepoint/sched/sched_process_exit` | Process exit — pid, exit code, duration |
| `opensnoop.bpf.c` | `sys_enter_openat` + `sys_exit_openat` | File access — pid, comm, filename, return code |

All compiled via `bpf2go` → Go wrappers auto-generated.

**opensnoop uses a two-probe pattern**: entry captures filename and process context into a BPF hash map; exit checks the return value and emits only if `ret >= 0` (success) or `ret == -EACCES/-EPERM` (access denied to existing file). Files that do not exist (`-ENOENT`) are dropped — this eliminates probe noise from curl checking `~/.curlrc` while still catching `cat /etc/shadow` from a non-root user.

### Go Userspace Agent (`main.go`)

- Loads and attaches all eBPF programs using `cilium/ebpf`
- Reads process events via **perf buffer** (`execsnoop`)
- Reads exit and file events via **ring buffer** (`exitsnoop`, `opensnoop`)
- Three concurrent goroutines, one per monitor
- pid→container cache: populated at exec time, consumed at exit time — fixes `container=unknown` in exit alerts
- Graceful shutdown on `Ctrl+C`

### Detection Rules (`rules.go`)

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

**Exit rules:**

| Rule | Trigger | Severity |
|------|---------|----------|
| `short_lived_failure` | Non-zero exit + duration < 100ms | LOW |

**Whitelists:**
- Process: `sshd`, `runc`, `dockerd`, `containerd` — never alert
- Host processes filtered via `mnt_ns` — no host-level false positives
- File: `runc:[2:INIT]`, `runc:[1:CHILD]`, `curl` — skip `/etc/passwd` (runtime user resolution)
- Exit: `gpasswd`, `cmp`, `https` — expected non-zero exits

### Container Correlation (`container.go`)

- `mnt_ns_id` captured in kernel via `BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)` — `__u32`
- `docker ps --no-trunc` at startup + every 30s builds container ID → name map
- `/proc/<pid>/cgroup` maps process → container ID → container name
- Handles both cgroupv1 (`/docker/<id>`) and cgroupv2 (`docker-<id>.scope`) formats
- `pidCache` (`sync.Map`): caches `pid → {container, ppid}` at exec time for reliable exit event resolution

**Namespace resolution logic (three-tier):**

| Result | Meaning | Source |
|---|---|---|
| `host` | PID 1 mount namespace | nsCache |
| `order-processor-xxx` | Known Docker container | nsCache via docker ps |
| `unknown-ns` | Not host, not any container after fresh /proc rescan | escape indicator |

On cache miss, `resolveContainer` immediately rescans `/proc` before declaring `unknown-ns` — handles new containers starting within the 30s refresh window.

**Known limitation — exit events for pre-EDR processes:**
Exit events use the pid cache (populated at exec time). Processes running before the EDR agent started have no cache entry → exit shows `container=unknown`. Not `unknown-ns` — these are a different code path (cache miss vs namespace miss). Proper fix: add `mnt_ns_id` to `exitsnoop.h` and use `resolveContainer` as fallback. Deferred — out of scope for this project.

### Alert Output (`alert.go`)

- Structured format: `timestamp, level, rule, container, pid, ppid, uid, comm, message`
- Writes to stdout (live monitoring) and `alerts/alert.log` (persistent record)

---

## Validation

### Detections confirmed working

| Attack | Expected Alert | Status |
|--------|---------------|--------|
| `docker exec auth_service cat /etc/shadow` | HIGH `sensitive_file_access` | ✅ |
| `cat /etc/shadow` as uid=1000 (EACCES) | HIGH `sensitive_file_access` | ✅ |
| Shell spawn inside container | CRITICAL `shell_spawn_container` | ✅ |
| Container name resolved correctly | `container=order-processor-auth_service` | ✅ |

### No false positives during normal operation

- Ran full CNOP integration test suite while agent running — no spurious alerts
- Health checks (`curl localhost`) — no alert (correctly excluded from process rules)
- Python `certifi` CA bundle reads — no alert (`.pem` not in suffix list)
- Container startup (`runc` reading `/etc/passwd`) — no alert (whitelisted)

### Evidence

- `legacy/screenshots/` — alert firing alongside integration tests
- `alerts/alert.log` — sample alert output

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
| pid→container cache | Process gone from /proc by exit time; real_parent may reparent to init |
| Hybrid namespace strategy | No host whitelist needed — only alert on truly unrecognized namespaces |
| Immediate /proc rescan on cache miss | Handles containers starting within the 30s refresh window |
| Audit mode only | Safe for personal project — no risk of killing legitimate processes |
| Rules in separate `rules.go` | Easy to add/remove rules without touching event pipeline |

---

## What's Next

- Restore `.pem` rule with `/site-packages/` path exception
- `lsm-connect.bpf.c` — network enforcement: only `inventory_service` → `api.coingecko.com`
- Wire lsm-connect into `main.go`
- Go unit tests — `rules_test.go`, `container_test.go`
- Final validation — all rules trigger + integration tests pass simultaneously
