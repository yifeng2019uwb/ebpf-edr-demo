# Session Handoff — 2026-06-10

## Current State

**GCP Docker VM: ACTIVE** — eBPF agent running, all 13 validate.sh tests passing.
**Health-AI GKE Cluster: ACTIVE** — deployed, all 11 validate-gke.sh tests passing ✅.
**Health-AI DigitalOcean: PLANNED** — next permanent always-on deploy target. Migrate before GCP expiry.
GCP credits expire 2026-06-17 (~7 days). Resources on project `ebpfagent`.

---

## What Changed This Session (2026-06-10)

### Supabase T1041 false positives — fixed ✅

Added port 6543 (Supabase pgbouncer) to `externalAllowedDstPorts` in `pkg/detector/policy.go` and `checkNetworkRules` in `pkg/detector/rules.go`. All health-ai services connect to Supabase — the HIGH T1041 alerts were false positives. Confirmed working.

### Debug log cleanup ✅

Removed `DEBUG file-enrich` and `DEBUG file-detect` log lines from `cmd/edr-monitor/main.go`. Also removed the now-unused `comm` and `filename` locals from the `opensnoop` enrich case. Build verified clean (`GOOS=linux GOARCH=amd64 go build ./cmd/edr-monitor/`).

### Image rebuilt and pushed to ghcr.io ✅

Full rebuild on GCP VM (`make generate && make rebuild`) regenerated `pkg/bpf/file_bpfel.go` from `lsm-file.bpf.c` — `HandleFileOpen` is now the live BPF program (replacing the old `HandleEnter`/`HandleExit` from opensnoop). Pulled generated files back to Mac, pushed `ghcr.io/yifeng2019uwb/ebpf-edr:latest`. Image reflects all changes this session: lsm/file_open hook, dedup fix, Redis T1611 exclusion, debug log removal.

### Test distribution across services ✅

Both `validate.sh` (Docker) and `validate-gke.sh` (GKE) now spread tests across all available services instead of targeting a single container. This confirms the eBPF resolver correctly maps mount-namespace IDs to service identities for every service, not just auth-service.

**validate-gke.sh** — auth-service (V3/V8/V10), provider-service (V2/V7/V11), gateway (V4/V9/V12), ai-service (V5).

**validate.sh** — auth_service (T2/T5/T13), user_service (T1/T4/T10/T12), order_service (T3/T7/T9), insights_service (T8/T11), inventory_service (T6).

### V3/V7/V9 root cause confirmed and fixed ✅

Root cause: busybox (`sh`/`cat` on Alpine) uses `SYS_open` (syscall 2); our probe covered only `SYS_openat` (syscall 257). Fix: replaced `opensnoop.bpf.c` with `lsm-file.bpf.c` using `SEC("lsm.s/file_open")` + `bpf_d_path()`. Single LSM hook fires for all file-open syscall variants. Also fixed V9 dedup collision: changed key from `pid:filename` to `comm:pid:filename` to handle the runc→cat exec pattern (both share the same PID). All 9 GKE tests now pass.

### Container Registry — migrated from GCP AR to ghcr.io

GCP Artifact Registry expires with credits on 2026-06-17 and requires extra auth on non-GCP clusters. Replaced with ghcr.io which is free and works from any cluster.

- All images at **ghcr.io/yifeng2019uwb/**: `ebpf-edr`, `auth-service`, `provider-service`, `ai-service`, `gateway`
- All packages set to **public** — any K8s cluster pulls without auth
- Login: `docker login ghcr.io -u yifeng2019uwb` with classic PAT (`write:packages` scope — fine-grained PAT does NOT work for packages)
- `make docker-push-ghcr-prebuilt` — uses committed binary, builds image, pushes (safe on Mac)
- `make docker-push-ghcr` — full build + push (requires Linux / GCP VM)

### health-ai deploy.sh and deployment.yaml updated

- `IMAGE_PREFIX` changed from GCP AR path to `ghcr.io/yifeng2019uwb`
- `gcloud auth configure-docker` removed from `build_images()`
- All 4 service images in `deployment.yaml` updated to ghcr.io paths
- `_apply_daemonset` re-enabled (was disabled when image was `TO_BE_SET`)

### eBPF DaemonSet YAML updated

- `k8s/ebpf-edr-ds.yaml` image set to `ghcr.io/yifeng2019uwb/ebpf-edr:latest`
- `${REGION}`, `${CLUSTER_NAME}`, `${GOOGLE_CLOUD_PROJECT}` substituted via `envsubst` in deploy.sh (already correct)

---

## BPF C Files — Scope Review

**Rule: Do NOT change .bpf.c files unless truly necessary. All detection/policy logic belongs in Go.**

| File | Status | C changes needed |
|------|--------|-----------------|
| `execsnoop.bpf.c` | ✅ Correct | None |
| `lsm-connect.bpf.c` | ✅ Correct | None |
| `opensnoop.bpf.c` | ❌ Replace | Being replaced by `lsm-file.bpf.c` — see decision below |

### What each C file does (and should only do)
- **C responsibility**: capture raw kernel events, minimal performance filtering (skip loopback), emit to ring buffer
- **Go responsibility**: all detection policy, workload resolution, alerting, response actions

### opensnoop — Root Cause Confirmed + Decision

**Root cause (confirmed 2026-06-10)**:

`opensnoop.bpf.c` hooks `sys_enter_openat` (syscall 257). Alpine Linux's busybox (`eclipse-temurin:21-jre-alpine` base image) calls `SYS_open` (syscall 2) directly — a completely different syscall. Our tracepoint never fires for `sh` or `cat`.

Evidence from debug logs:
- `runc:[2:INIT]` (Go binary, uses `openat`) → ✅ appears in logs
- `sshd` (glibc, uses `openat`) → ✅ appears in logs
- `sh`, `cat`, `busybox` → ❌ never appear, for any filename

This explains why V3/V7/V9 have always failed. The `tgid != tid` theory from the previous handoff was wrong — the ring buffer IS active (~1000 events/sec), but all events are from non-busybox processes.

**Industry research (2026-06-10)**:
- **Falco** solves this by hooking `open + openat + openat2` — all three syscall tracepoints
- **Tetragon** solves this by hooking `security_file_open` (kernel internal function via kprobe), which fires for ALL file-open syscall variants regardless of which one was called

**Decision: Replace opensnoop.bpf.c with lsm-file.bpf.c using `lsm.s/file_open`**

Chosen approach: **Option B — `SEC("lsm.s/file_open")` + `bpf_d_path()`**

Rationale:
- `lsm/file_open` fires for every file open regardless of syscall variant (open, openat, openat2, io_uring) — catches busybox, glibc, musl, everything
- `bpf_d_path()` extracts the full resolved path from `struct file *` — single call, no two-probe hash map needed
- Mirrors our existing `lsm/socket_connect` pattern in `lsm-connect.bpf.c` exactly
- The `.s` (sleepable) designation is required for `bpf_d_path()` and is safe — `bpf_lsm_file_open` is in the kernel's sleepable LSM hooks set; `BPF_MAP_TYPE_RINGBUF` is allowed in sleepable programs
- GKE kernel 6.8 supports sleepable LSM programs (5.10+) and `bpf_d_path()` (5.11+) ✅
- Eliminates the two-probe enter/exit pattern and `pending_opens` hash map entirely — LSM hook fires after kernel validates the open (file exists, permissions checked), so ENOENT events are naturally absent with no extra filter needed

Why not Tetragon's exact approach (kprobe/security_file_open + manual dentry walk):
- Tetragon uses manual dentry walking in BPF to avoid the sleepable requirement — ~100 lines of complex BPF loop code
- On GKE 6.8 we have `bpf_d_path()` available, making that complexity unnecessary

**Implementation plan**:
1. Create `kernel/lsm-file.bpf.c` — `SEC("lsm.s/file_open")` hook, `bpf_d_path()` for path, emit `file_event` to ring buffer
2. Reuse existing `kernel/opensnoop.h` struct (`file_event`) — Go side unchanged
3. Update `pkg/bpf/loader.go` — load and attach `lsm-file` instead of `opensnoop`
4. Delete `kernel/opensnoop.bpf.c` (or keep as reference, rename)
5. Remove `pending_opens` map and two-probe logic from the new C file
6. Add V9 dedup fix in Go: change key from `pid:filename` to `comm:pid:filename` to handle runc→cat exec pattern
7. Rebuild on GCP VM (`make rebuild`), push, redeploy

**Confirmed working — log analysis (2026-06-10)**:

Detection pipeline for V9 (`cat /etc/passwd`) as seen in EDR logs:
```
file-enrich: comm="cat" filename="/etc/passwd" svc=auth-service  ← lsm captures busybox
file-enrich: comm="cat" filename="/etc/passwd" svc=auth-service  ← duplicate (lsm fires twice per open)
file-detect: comm="cat" filename="/etc/passwd" svc=auth-service  ← dedup collapses to one
→ Alert: MEDIUM T1082_system_info_discovery /etc/passwd ✅
```

`comm="sh"` and `comm="cat"` both appear — busybox fully captured. `comm:pid:filename` dedup key correctly separates runc:[2:INIT]'s `/etc/passwd` from cat's.

**Known bpf_d_path quirk — truncated procfs paths**:
Some `/proc/<pid>/...` virtual filesystem paths are returned without the `/proc` prefix:
```
filename="/410/setgroups"           ← should be /proc/410/setgroups
filename="/410/task/410/attr/..."   ← should be /proc/410/task/...
```
`bpf_d_path` does not fully resolve paths under certain virtual filesystems (procfs, sysfs). These truncated paths do not match any detection rules so cause no false positives. If `/proc/<pid>/` monitoring is ever needed, this will require a different path-extraction approach (manual dentry walk).

**Cleanup status**:
- ✅ `DEBUG file-enrich` and `DEBUG file-detect` log lines removed from `cmd/edr-monitor/main.go`
- ✅ `pkg/bpf/file_bpfel.go` regenerated — `HandleFileOpen` is live, old `HandleEnter`/`HandleExit` gone
- 🔲 `kernel/opensnoop.bpf.c` — still present, kept for reference; safe to delete when convenient

---

## Go Fixes Needed

### Fix 1 — File reader goroutine restart ✅ DONE

Already implemented in `cmd/edr-monitor/main.go`. All three readers have `os.ErrClosed` guard + `time.Sleep(time.Second)` + `continue` restart loop. Binary rebuilt and deployed to GKE this session.

### Fix 2 — StateUnknown false positives (deferred)

**File:** `pkg/workload/k8s_resolver.go`

`containerIDFromK8sCgroup()` returns `""` for two cases:
- Case A: no "kubepods" in cgroup → host process (safe, should not alert)
- Case B: "kubepods" in cgroup but can't parse → legitimately suspicious

Both cases reach StatePending → StateUnknown → 🚨 CRITICAL T1611 false positive for host daemons.

**Fix:**
```go
// In containerIDFromK8sCgroup:
if !strings.Contains(line, "kubepods") {
    return "HOST"  // sentinel — not a k8s pod
}
// In buildCache:
if containerID == "HOST" {
    m[nsID] = r.bareResult(StateHost)
    continue
}
```

Deferred — implement after opensnoop issue resolved.

---

## validate-gke.sh — Current Results

Tests are distributed across all 4 services to confirm the K8s resolver maps mnt_ns_id correctly for each:

| Test | Service | Result | Notes |
|------|---------|--------|-------|
| V2 Shell spawn | provider-service | ✅ PASS | Process sensor (execsnoop) working |
| V3 Shadow read | auth-service | ✅ PASS | Fixed: lsm/file_open captures busybox cat |
| V4 External connect | gateway | ✅ PASS | Network sensor (lsm-connect) working |
| V5 ai-service allowlist | ai-service | ✅ PASS | |
| V6 No FP gateway traffic | all services | ✅ PASS | |
| V7 SSH private key | provider-service | ✅ PASS | Fixed: lsm/file_open captures busybox cat |
| V8 Network recon tool | auth-service | ✅ PASS | Process sensor working |
| V9 /etc/passwd recon | gateway | ✅ PASS | Fixed: comm:pid:filename dedup key separates runc→cat exec pattern |
| V10 Reverse shell | auth-service | ✅ PASS | Process + network sensors working |
| V11 .env credentials file | provider-service | ✅ PASS | T1552_001_credentials_in_files confirmed |
| V12 Container mgmt tool | gateway | ✅ PASS | T1613_container_resource_discovery confirmed |

**11 passed · 0 failed · 0 skipped** ✅ (2026-06-09/10)

Service coverage: auth-service (V3/V8/V10), provider-service (V2/V7/V11), gateway (V4/V9/V12), ai-service (V5).

---

## Full Rule Coverage

### Implemented (✅) — Validated on GCP Docker VM

| Rule | MITRE | Level | Response | Source |
|------|-------|-------|----------|--------|
| `T1059_unix_shell_execution` | T1059.004 · T1609 | CRITICAL | none (alert only) | process |
| `T1105_ingress_tool_transfer` | T1105 · T1095 | HIGH | none (alert only) | process |
| `T1611_escape_to_host_ns` | T1611 | CRITICAL | none (Podman FP) | process |
| `T1036_masquerading` | T1036 | HIGH | none | process |
| `T1613_container_resource_discovery` | T1613 | HIGH | none | process |
| `T1611_escape_to_host_fs` | T1611 | CRITICAL | kill_process | file |
| `T1611_escape_to_host_proc` | T1611 | HIGH | none (GKE sidecar FP) | file |
| `T1552_004_private_keys` | T1552.004 | CRITICAL/HIGH | kill_process | file |
| `T1552_001_credentials_in_files` | T1552.001 | HIGH | none (alert only) | file |
| `T1003_008_os_credential_dumping` | T1003.008 | HIGH | kill_process | file |
| `T1082_system_info_discovery` | T1082 | MEDIUM | none | file |
| `T1053_003_scheduled_task_cron` | T1053.003 | HIGH | none | file |
| `T1070_003_clear_command_history` | T1070.003 | MEDIUM | none | file |
| `T1041_exfiltration_over_c2` | T1041 · T1048 | HIGH | block_ip (disabled) | network |

### Planned (🔲)

| Rule | MITRE | Notes |
|------|-------|-------|
| `T1059_scripting_interpreter` | T1059 | Needs parent-process context — high FP risk |
| `T1046_network_service_scanning` | T1046 | Stateful burst detection |
| `T1554_compromise_binary` | T1554 | ETXTBSY detection — future, low priority |

---

## IP Blocking — Disabled

`block_ip` response disabled — `blocked_ips` LPMTrie removed from `lsm-connect.bpf.c` (BPF verifier complexity limit on GKE). Alert T1041 still fires; only enforcement is disabled.
`NewResponder(nil)` in `main.go`. Re-enable path requires C changes (avoid for now).

---

## Key Facts

### GCP Credits
- Expire: 2026-06-17 (~9 days)
- Resources on `ebpfagent`: Docker VM `instance-20260318-023006` (~$43/mo)
- Health-AI GKE kept OFF — bring up only for eBPF testing
- After expiry: Cloud Logging free tier remains

### Container Registry (ghcr.io — free, no expiry)
- eBPF agent: `ghcr.io/yifeng2019uwb/ebpf-edr:latest` (public)
- health-ai services: `ghcr.io/yifeng2019uwb/{auth-service,provider-service,ai-service,gateway}:latest` (public)
- Login: `docker login ghcr.io -u yifeng2019uwb` + classic PAT with `write:packages` scope

### eBPF Agent Binary
- Go-only changes: `make build` on Mac → `make docker-push-ghcr-prebuilt` → redeploy DaemonSet
- BPF C changes: `make rebuild` on GCP VM → commit generated files + binary → pull on Mac → `make docker-push-ghcr-prebuilt`
- **Avoid C changes** — diagnose with Go diagnostic first

### Health-AI GKE (on-demand)
- Cluster: `health-ai-cluster-us-west1`, namespace: `health-ai`, project: `ebpfagent`
- Pulumi: `github_projects/health-ai/healthcare-ai-microservices/kubernetes/pulumi/` stack `gke-dev`
- Bring up cluster: `cd kubernetes/pulumi && pulumi up`
- Deploy everything: `cd kubernetes && ./deploy.sh all` (builds images + infra + services + eBPF DaemonSet)
- Destroy: `./deploy.sh destroy`
- DB: Supabase (external, always on) — credentials in `github_projects/health-ai/healthcare-ai-microservices/docker/.env`

### Alert Router (Mac)
- `make run-alert-router` — requires `gcloud auth application-default set-quota-project ebpfagent`

### Known False Positives
- `T1611_escape_to_host_ns` from Podman health checks — excluded from kill response
- `T1611_escape_to_host_proc` on GKE — monitoring sidecars read `/proc/1/`; response set to none
- `docker cp` during validate.sh creates `state=unknown / comm=exe` alerts — test-setup artifact
- `ai-service` external Gemini calls — add to `externalAllowedServices` in `policy.go` if HIGH alerts appear

### Known Limitations (minor, no action needed)
- T2 (T1105) skips silently in Docker if nc/wget not installed in auth_service — rule confirmed working via GKE V8
- block_ip is disabled everywhere (`NewResponder(nil)`) — T1041 alerts fire but no kernel enforcement; re-enable requires C changes
- T1611_escape_to_host_ns and T1611_escape_to_host_proc not testable via validate.sh (need real escape scenario or --pid=host container)
- `kernel/opensnoop.bpf.c` still present — dead code, safe to delete anytime

---

## Upcoming Tasks

### Phase 1: MITRE Deep Review + Rules Refactoring (Next)

**Goal:** Move rules from hardcoded Go to YAML format while learning MITRE attack patterns.

**Context:** 
- Currently rules/policies are hardcoded in `pkg/detector/policy.go` (lists of paths, binaries, whitelists)
- Learning MITRE patterns in `/workspace/learning/ebpf-edr/` (separate from project)
- Each technique should be documented and reviewable
- YAML format enables per-service customization (future Phase 3)

**Plan:**
1. Create `pkg/rules/` package — YAML loader + applier
2. Add `rules/common.yaml` — move all rules from policy.go into structured YAML
3. Refactor `pkg/detector/` to load rules from YAML instead of hardcoded slices
4. Test: ensure behavior identical to before (same alerts on same tests)
5. Document each rule in `/workspace/learning/ebpf-edr/MITRE-STUDY.md` while refactoring

**YAML Structure (example):**
```yaml
rules:
  whitelist:
    processes: [sshd, runc, dockerd, containerd, getconf]
    unknown_namespace: [iptables, kube-proxy, pause, systemd-sysctl]
  
  detections:
    T1552_private_keys:
      dir_prefixes: [/root/.ssh/, /home/.ssh/]
      suffixes: [.key, .pem, id_rsa, id_ed25519]
      exclude_paths: [/site-packages/, /certifi/]
    
    T1036_masquerading:
      suspicious_paths: [/tmp/, /dev/shm/, /var/tmp/, /run/user/]
    
    # ... (all other rules follow similar structure)
  
  network:
    allowed_ports: [6543]  # Supabase pgbouncer
    allowed_services: [inventory-service, inventory_service]
  
  ignore_namespaces: [kube-system, gmp-system, gke-managed-cim]
```

**Benefits:**
- Rules become readable data (not buried in code)
- Can review each MITRE technique independently
- Easier to add per-service exceptions (Phase 3)
- Learning MITRE patterns while refactoring improves understanding

**Start:** See `/workspace/learning/ebpf-edr/LEARNING_PLAN.md` and `/workspace/learning/ebpf-edr/MITRE-STUDY.md` for study structure and YAML examples.

### Phase 2: Behavioral Detection (Later)

**Goal:** Add stateful detection (baselines, anomaly, multi-event correlation) in Central Control Service.

**Dependencies:** Phase 1 complete + solid understanding of false positives per rule

### Phase 3: Configurable Rules Framework (Last)

**Goal:** Allow clients to customize rules via YAML at agent deployment.

**Dependencies:** Phase 1 (rules in YAML) + Phase 2 (behavioral baseline understanding)
