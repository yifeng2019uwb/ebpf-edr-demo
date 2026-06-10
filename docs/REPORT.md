# eBPF EDR Demo — Project Report

## What This Project Is

A working EDR (Endpoint Detection and Response) agent built with Go + eBPF, monitoring containerized services at the kernel level. The agent detects and responds to threats in real time — no agent inside containers, no application changes required.

Two target workloads:
- **order-processor** — cloud-native microservices running on a GCP Docker VM (Debian 12, kernel 6.1)
- **health-ai** — healthcare AI microservices running on GKE (Ubuntu 24.04, kernel 6.8)

---

## Architecture

### eBPF Kernel Programs

| Program | Hook | Captures |
|---------|------|----------|
| `execsnoop.bpf.c` | `tracepoint/syscalls/sys_enter_execve` | Process execution — pid, ppid, uid, mnt_ns_id, executable path |
| `lsm-file.bpf.c` | `lsm.s/file_open` + `bpf_d_path()` | File access — pid, comm, full resolved path, mnt_ns_id |
| `lsm-connect.bpf.c` | `lsm/socket_connect` | Outbound connections — pid, comm, dst_ip, dst_port, mnt_ns_id |

All compiled via `bpf2go` — Go wrappers auto-generated and committed to `pkg/bpf/`.

**Why `lsm/file_open` instead of tracepoint openat:**
Alpine Linux's busybox (`sh`, `cat`) calls `SYS_open` (syscall 2) directly; the old opensnoop tracepoint only hooked `SYS_openat` (syscall 257) — a completely different syscall, so busybox was never captured. `lsm/file_open` fires for every file open regardless of syscall variant (open, openat, openat2, io_uring), catching busybox, glibc, musl, and all runtimes uniformly. `bpf_d_path()` extracts the full resolved path from the kernel `struct file *` in a single call — no two-probe enter/exit hash map needed. The `.s` (sleepable) designation is required for `bpf_d_path()` and supported on GKE kernel 6.8 (requires 5.11+).

**lsm-connect is audit-only**: always returns `0` — never blocks at kernel level (BPF verifier complexity limit on GKE removed the LPMTrie enforcement). The `lsm/socket_connect` hook fires before every `connect()` syscall. Loopback is filtered in BPF; all RFC 1918 checks are in Go so policy changes without recompiling BPF.

### Go Userspace Pipeline

```
cmd/edr-monitor/main.go   — entry point, pipeline wiring, goroutines
pkg/bpf/loader.go         — BPF loading, kernel attachment, ring buffer readers
pkg/workload/             — WorkloadResolver: DockerResolver + K8sResolver
pkg/detector/rules.go     — MITRE-mapped detection logic
pkg/detector/policy.go    — whitelists, file prefixes, network allowlists (data only)
pkg/pipeline/             — EnrichedEvent types, channel plumbing
internal/alert/           — AlertHandler: local file + Cloud Logging + Pub/Sub
internal/processor/       — event structs (ProcessEvent/FileEvent/NetEvent)
```

**Pipeline stages:**
1. Three goroutines read ring buffers (process / file / network) → `rawCh`
2. Enricher: `mnt_ns_id` → `WorkloadIdentity` (service / pod / namespace / cluster) → `enrichedCh`
3. File dedup: `comm:pid:filename` key, 1-second window — collapses duplicate LSM hook fires
4. Detector: applies all MITRE rules → `alertCh`
5. Responder: `kill_process` (SIGKILL) or `block_ip`
6. AlertHandler: stdout + `alerts/alert.log` + Cloud Logging + Pub/Sub

**Workload resolution:**
- `mnt_ns_id` captured in kernel via `BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)`
- Docker: `docker ps` at startup + every 30s → container ID → service name map
- K8s: `crictl ps` → pod metadata → service/namespace/cluster from pod labels
- StatePending retry loop (3s interval, 60s max) handles slow-starting pods

### Alert Output

Structured JSON to three destinations simultaneously:
```json
{
  "schema_version": 1,
  "ts": "2026-06-10T17:59:06.000000Z",
  "level": "HIGH",
  "rule": "T1041_exfiltration_over_c2",
  "service": "gateway",
  "namespace": "health-ai",
  "runtime": "k8s",
  "dst_ip": "8.8.8.8",
  "dst_port": 80,
  "response_action": "none"
}
```

- `stdout` + `alerts/alert.log` — always-on, no external dependency
- **Google Cloud Logging** — structured JSON, 365-day retention, queryable
- **Pub/Sub `edr-alerts`** → Alert Router → WebSocket → browser dashboard (<1s latency)

---

## Detection Rules

### Process Rules (14 total across 3 categories)

| Rule | MITRE | Severity | Response |
|------|-------|----------|----------|
| `T1059_unix_shell_execution` | T1059.004 · T1609 | CRITICAL | kill_process |
| `T1105_ingress_tool_transfer` | T1105 · T1095 | HIGH | kill_process |
| `T1611_escape_to_host_ns` | T1611 | CRITICAL | — |
| `T1036_masquerading` | T1036 | HIGH | — |
| `T1613_container_resource_discovery` | T1613 | HIGH | — |
| `T1611_escape_to_host_fs` | T1611 | CRITICAL | kill_process |
| `T1611_escape_to_host_proc` | T1611 | HIGH | — |
| `T1552_004_private_keys` | T1552.004 | CRITICAL/HIGH | kill_process |
| `T1552_001_credentials_in_files` | T1552.001 | HIGH | kill_process |
| `T1003_008_os_credential_dumping` | T1003.008 | HIGH | kill_process |
| `T1082_system_info_discovery` | T1082 | MEDIUM | — |
| `T1053_003_scheduled_task_cron` | T1053.003 | HIGH | — |
| `T1070_003_clear_command_history` | T1070.003 | MEDIUM | — |
| `T1041_exfiltration_over_c2` | T1041 · T1048 | HIGH | block_ip (alert-only on GKE) |

All single-event-detectable MITRE techniques for containerized workloads are covered.

### Policy Design

- **fileCommWhitelist** — processes that legitimately read system files at startup (`runc`, `bash`, `containerd`, `curl`). Suppresses file rules only; process events still monitored.
- **whitelistComm** — infrastructure daemons suppressed entirely (`sshd`, `dockerd`, `containerd`).
- **unknownNsCommsWhitelist** — GKE node-level infrastructure in host namespace (`kube-proxy`, `iptables`, `pause`).
- **System namespace suppression** — `kube-system`, `gmp-system`, `gke-managed-cim` filtered entirely (constant high-frequency noise, no actionable signal).
- **externalAllowedDstPorts** — port 6543 (Supabase pgbouncer) allowed for all health-ai services.
- **externalAllowedServices** — `inventory_service` (CoinGecko), `ai-service` (Gemini API).

---

## Validation Results

### Docker VM — 11/11 pass

Tests distributed across 4 services: `auth_service` (T2/T5), `user_service` (T1/T4/T10), `order_service` (T3/T7/T9), `insights_service` (T8/T11).

| Test | Service | Rule | Result |
|------|---------|------|--------|
| T1 Shell spawn | user_service | `T1059_unix_shell_execution` CRITICAL | ✅ |
| T2 Network tool | auth_service | `T1105_ingress_tool_transfer` HIGH | ✅ |
| T3 `/etc/shadow` | order_service | `T1003_008_os_credential_dumping` HIGH | ✅ |
| T4 SSH private key | user_service | `T1552_004_private_keys` HIGH | ✅ |
| T5 External connect + block | auth_service | `T1041_exfiltration_over_c2` HIGH | ✅ |
| T6 Allowlisted connect | inventory_service | — no alert | ✅ |
| T7 Host reads container FS | order_service | `T1611_escape_to_host_fs` CRITICAL | ✅ |
| T8 `/etc/passwd` | insights_service | `T1082_system_info_discovery` MEDIUM | ✅ |
| T9 Masquerading `/tmp/sshd` | order_service | `T1036_masquerading` HIGH | ✅ |
| T10 Cron config | user_service | `T1053_003_scheduled_task_cron` HIGH | ✅ |
| T11 Shell history | insights_service | `T1070_003_clear_command_history` MEDIUM | ✅ |

Block verification (T5): second connect to blocked IP returns `EPERM`; private IPs remain unaffected.

### GKE — 9/9 pass

Tests distributed across all 4 health-ai services — confirms eBPF resolver maps mount-namespace IDs correctly for every pod, not just one.

| Test | Service | Rule | Result |
|------|---------|------|--------|
| V2 Shell spawn | provider-service | `T1059_unix_shell_execution` CRITICAL | ✅ |
| V3 `/etc/shadow` | auth-service | `T1003_008_os_credential_dumping` HIGH | ✅ |
| V4 External connect | gateway | `T1041_exfiltration_over_c2` HIGH | ✅ |
| V5 Allowlist check | ai-service | — no alert | ✅ |
| V6 No FP normal traffic | all services | — no alert | ✅ |
| V7 SSH private key | provider-service | `T1552_004_private_keys` CRITICAL | ✅ |
| V8 Network tool | auth-service | `T1105_ingress_tool_transfer` HIGH | ✅ |
| V9 `/etc/passwd` | gateway | `T1082_system_info_discovery` MEDIUM | ✅ |
| V10 Reverse shell | auth-service | `T1059` CRITICAL + `T1041` HIGH | ✅ |

### False Positive Policy

- No CRITICAL or HIGH alerts from normal service traffic (confirmed with concurrent integration test suite)
- Known suppressed noise: Supabase port 6543, GKE monitoring sidecars reading `/proc/1/stat`

---

## Key Technical Decisions

| Decision | Reason |
|----------|--------|
| `lsm/file_open` over tracepoint openat | Catches busybox `SYS_open` which tracepoint `SYS_openat` misses — confirmed root cause of 3 always-failing tests |
| `bpf_d_path()` for path extraction | Single call replaces two-probe enter/exit pattern + hash map; returns full resolved path from `struct file *` |
| `comm:pid:filename` dedup key | `runc:[2:INIT]` and `cat` share the same PID during exec — plain `pid:filename` caused dedup collision dropping valid alerts |
| `cilium/ebpf` + `bpf2go` | Production Go eBPF library, type-safe generated wrappers, CO-RE support |
| Ring buffer for all programs | Lower overhead than perf buffer, no per-CPU waste |
| All policy in Go, not C | BPF C files are sensors only — policy changes (whitelists, thresholds) require no kernel rebuild |
| `mnt_ns_id` for workload identity | Unique per container, visible from kernel, no container runtime API needed in BPF |
| StatePending retry with 60s max | K8s pods can take 30–60s to appear in `crictl ps` after exec — naive immediate lookup drops real alerts |
| System namespace suppression | `kube-system` etc. generate constant noise (kube-proxy iptables, prometheus /proc reads) with no actionable signal for application threat detection |

---

## Container Registry

All images at `ghcr.io/yifeng2019uwb/` (public, free, no expiry):
- `ebpf-edr:latest` — EDR agent
- `auth-service`, `provider-service`, `ai-service`, `gateway` — health-ai services

Build workflow:
- Go-only changes: `make build` on Mac → `make docker-push-ghcr-prebuilt` → redeploy
- BPF C changes: `make generate && make rebuild` on Linux VM → commit generated files → pull to Mac → push image
