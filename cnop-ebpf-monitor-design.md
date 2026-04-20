# cnop-ebpf-monitor — Design Doc

> Reference detail: `cnop-ebpf-monitor-design-detail.md`

## References
- [cilium/ebpf](https://github.com/cilium/ebpf) — Go library used to load and manage BPF programs
- [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) — eBPF learning resource

---

## 1. Scope & Requirements

### Goal
Personal learning project to practice eBPF and EDR concepts using a real running workload.
Build a working EDR agent that monitors containerized services using Go + cilium/ebpf.

### What we build
- 2 detection monitors: process monitor (execsnoop) + file monitor (opensnoop)
- 1 network monitor: lsm-connect (audit outbound connections at kernel level — audit mode, not blocking)
- Go userspace agent that reads events, matches detection rules, and emits structured alerts
- Each monitor validated against real container behavior before moving on

### Out of scope
- Production hardening, scalability, dashboards
- Android or embedded targets

## 2. Environment

### Host
- GCP VM, Debian 12, kernel 6.1.0-44-cloud-amd64
- Toolchain: Go + cilium/ebpf + bpf2go + clang/llvm (verified working)
- Repo: [ebpf-edr-demo](https://github.com/yifeng2019uwb/ebpf-edr-demo) at `~/workspace/ebpf-edr-demo`

### Target workload
- Repo: [cloud-native-order-processor](https://github.com/yifeng2019uwb/cloud-native-order-processor) at `~/workspace/cloud-native-order-processor`
- 8 Docker containers, all on internal bridge network

| Container | Language | Port | Role |
|-----------|----------|------|------|
| `order-processor-gateway` | Go | 8080 | API gateway — only public entry point |
| `order-processor-auth_service` | Python | internal | JWT auth |
| `order-processor-user_service` | Python | internal | Balance / portfolio |
| `order-processor-inventory_service` | Python | internal | Asset catalog |
| `order-processor-order_service` | Python | internal | Trade execution |
| `order-processor-insights_service` | Python | internal | AI insights |
| `order-processor-redis` | Redis | internal | Rate limiting, locks |
| `order-processor-localstack` | Java | internal | DynamoDB emulation |

### Accessing services from local laptop
GCP VM only exposes SSH. Use port forwarding to reach the gateway:
```bash
ssh -L 8080:localhost:8080 <user>@<GCP_VM_IP>
# then: curl http://localhost:8080/health
```

## 3. Architecture

### High-level: Kernel Plane → User Plane

```
  Build time
  ──────────────────────────────────────────────────
  write .bpf.c (kernel program)
      ↓
  go generate  →  bpf2go compiles .c → .o + Go wrapper
      ↓
  write main.go using generated wrapper
      ↓
  go build && sudo ./cnop-ebpf-monitor

  Runtime
  ──────────────────────────────────────────────────
┌─────────────────────────────────────────────────┐
│  KERNEL  (.bpf.c programs)                      │
│                                                 │
│  process_monitor         file_monitor           │
│  sys_enter_execve        sys_enter_openat       │
│  (detect)                (detect)               │
│                                                 │
│  lsm/socket_connect                             │
│  (audit — always returns 0)                     │
│         │                    │                  │
│         └────────────────────┘                  │
│                          │                      │
│               BPF Ring Buffer                   │
└──────────────────────────┼──────────────────────┘
                           │
┌──────────────────────────▼──────────────────────┐
│  USERSPACE  (main.go)                           │
│                                                 │
│  load & attach via bpf2go generated wrapper     │
│         │                                       │
│         ▼                                       │
│  read events from ring buffer                   │
│         │                                       │
│         ▼                                       │
│  resolve container name                         │
│  (mnt_ns → /proc/<pid>/cgroup)                  │
│         │                                       │
│         ▼                                       │
│  match detection rules                          │
│         │                                       │
│         ▼                                       │
│  print JSON alert to stdout                     │
└─────────────────────────────────────────────────┘
```

> All monitors are audit-only — alerts emitted, no blocking. Safe for a live demo environment.

**What to learn for each part (from [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)):**

Batch 1 — detection monitors:

| Lesson | Topic    | Covers                          |
|--------|----------|---------------------------------|
| 07    | execsnoop | process_monitor — `execve` hook |
| 04    | opensnoop | file_monitor — `openat` hook |
| 08    | ringbuf   | migrate both to ring buffer |

Batch 2 — enforcement:

| Lesson | Topic | Covers |
|--------|-------|--------|
| 19 | lsm-connect | block connections at kernel level — no TOCTOU gap |

### Why these 3 monitors

The order processor runs 5 Python services + 1 Go gateway. Normal operation:
- Services talk to each other on the Docker bridge — no external connections
- No service should spawn a shell or run system commands
- JWT keys and `.env` credentials sit on disk — services read them once at startup, not repeatedly at runtime

So any of these happening at runtime is suspicious:

| If we see... | Monitor | What it likely means |
|---|---|---|
| `auth_service` spawns `bash` or `nc` | process_monitor | Code execution — attacker got in |
| Any service reads `/etc/shadow` or `*.key` | file_monitor | Credential theft attempt |
| Service connects to blocked IP | lsm-connect | Exfiltration attempt — blocked at kernel level |

### What file_monitor watches
- Credential files, private keys, environment secrets, Docker socket
- Specific paths TBD during implementation

### Container Correlation
- `mnt_ns_id` captured in kernel via `BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)` — `__u32`
- Userspace: `docker ps --no-trunc` at startup builds container ID → name map
- `/proc/<pid>/cgroup` maps process → container ID → container name
- Host processes identified by PID 1 namespace — silently skipped in rules

### Detection Engine
- Rules in Go userspace: ID, severity, MITRE technique, match condition
- TBD during implementation

### Response Mode
Audit only — structured alert to stdout and `alerts/alert.log`.
No blocking. Safe for a live demo environment.

## 4. Threat Model

### Detection Rules

| Rule | Hook | Trigger | Severity |
|------|------|---------|----------|
| `shell_spawn_container` | execsnoop | bash/sh/zsh/dash spawned inside container | CRITICAL |
| `unknown_namespace_process` | execsnoop | Process in namespace that is neither host nor any known container | CRITICAL |
| `host_reads_container_fs` | opensnoop | Host process reads `/var/lib/docker/overlay2/` | CRITICAL |
| `sensitive_file_access` | opensnoop | SSH keys (`/root/.ssh/`, `/home/.ssh/`) | CRITICAL |
| `network_tool_container` | execsnoop | nc, ncat, wget executed inside container | HIGH |
| `sensitive_file_access` | opensnoop | `/etc/shadow`, `/run/secrets/`, `/proc/1/`, `.key`, `id_rsa`, `.env` | HIGH |
| `unauthorized_external_connect` | lsm-connect | Container connects to external IP — not in allowlist | HIGH |
| `sensitive_file_access` | opensnoop | `/etc/passwd`, `/etc/group` | MEDIUM |
| `external_connect_allowed` | lsm-connect | `inventory_service` connects to external IP (CoinGecko audit log) | LOW |

### Known False Positives / Whitelists

| Whitelist | Suppresses |
|-----------|-----------|
| `whitelistComm` (process) | `sshd`, `runc`, `dockerd`, `containerd` — never alert on process rules |
| `fileCommWhitelist` | `runc`, `runc:[1:CHILD]`, `runc:[2:INIT]`, `curl` — read `/etc/passwd` during init |
| `externalAllowedContainers` | `inventory_service` — only container permitted external API access |
| Host namespace filter | All `container=host` processes skipped in process and file rules |
| ENOENT drop in opensnoop | Files that don't exist never emit — suppresses config file probing noise |

## 5. Implementation Plan

- [x] Process monitor — execsnoop (execve hook, perf buffer)
- [x] Exit monitor — exitsnoop built then removed: short_lived_failure too noisy for long-lived service containers
- [x] Container correlation — mnt_ns_id via CO-RE, resolved to container name ✅ validated
- [x] Detection rules — shell spawn, network tools, tiered file access
- [x] Alert output — structured log with container, pid, uid, comm, message
- [x] File monitor — opensnoop (two-probe enter+exit, ring buffer) ✅ validated
- [x] Hybrid namespace strategy — unknown-ns CRITICAL, host overlay CRITICAL, immediate rescan on miss
- [x] Network monitor — lsm-connect (socket_connect LSM hook, ring buffer, audit mode) ✅ validated
- [x] Network rules — RFC 1918 filter, externalAllowedContainers allowlist, unauthorized external HIGH
- [x] Named constants — `nsRefreshInterval`, `externalAllowedContainers`
- [x] Validation suite — VALIDATION.md + validate.sh, 7 test cases, concurrent integration traffic ✅
- [x] Noise fixes — fileCommWhitelist (`id`, `bash`, `systemd-logind`), drop `short_lived_failure` rule ✅
- [x] Restore .pem rule with path exception for `/site-packages/` and `/certifi/` ✅
- [x] Refactor Go structure — clean package layout (`cmd/`, `pkg/`, `internal/`, `kernel/`) ✅
- [x] CI pipeline — GitHub Actions: vet + test (non-BPF) + build; Makefile with generate/build/test targets ✅

## 6. Validation

See `VALIDATION.md` for full test procedure and `validate.sh` for automated execution.

### Manual test scenarios

| Test | Command | Expected | Result |
|------|---------|----------|--------|
| T1 Shell spawn | `docker exec auth_service bash -c "id"` | CRITICAL `shell_spawn_container` | ✅ |
| T2 Network tool | `docker exec auth_service nc/wget ...` | HIGH `network_tool_container` | ⚠️ infra* |
| T3 Shadow file | `docker exec auth_service cat /etc/shadow` | HIGH `sensitive_file_access` | ✅ |
| T4 SSH key | `docker exec auth_service cat /root/.ssh/id_rsa` | CRITICAL `sensitive_file_access` | ✅ |
| T5 Unauthorized connect | python3 socket to 8.8.8.8:80 from auth_service | HIGH `unauthorized_external_connect` | ✅ |
| T6 Authorized connect | inventory_service → CoinGecko | LOW `external_connect_allowed` | ✅ |
| T7 Host reads container FS | `cat /var/lib/docker/overlay2/.../etc/hostname` | CRITICAL `host_reads_container_fs` | ✅ |

*T2: `nc`/`ncat`/`wget` not installed in Python uvicorn container; `apt-get` fails with permission denied on `/var/lib/apt/lists/partial`. Detection rule is correct — pre-installing the binary would confirm it.

### Integration test validation ✅

- Run `run_all_tests.sh all` concurrently while attack tests fire
- No CRITICAL or HIGH alerts from normal service traffic
- inventory_service → CoinGecko generates LOW audit log only

### Evidence
- `snapshots/validateTest200950.png` — full validate.sh terminal output
- `alerts/alert.log` — 6/7 alerts confirmed in real output (T2 blocked by container infra)


