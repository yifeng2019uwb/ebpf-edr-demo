# Session Handoff — 2026-06-10

## Current State

**GCP Docker VM: ACTIVE** — eBPF agent running, all 11 validate.sh tests passing.
**Health-AI GKE Cluster: ACTIVE** — deployed, V2/V4/V5/V6/V8/V10 passing; V3/V7/V9 pending lsm-file fix.
**Health-AI DigitalOcean: PLANNED** — next permanent always-on deploy target. Migrate before GCP expiry.
GCP credits expire 2026-06-17 (~7 days). Resources on project `ebpfagent`.

---

## What Changed This Session (2026-06-10)

### Supabase T1041 false positives — fixed ✅

Added port 6543 (Supabase pgbouncer) to `externalAllowedDstPorts` in `pkg/detector/policy.go` and `checkNetworkRules` in `pkg/detector/rules.go`. All health-ai services connect to Supabase — the HIGH T1041 alerts were false positives. Confirmed working.

### V3/V7/V9 root cause confirmed — fix planned

Confirmed via debug logs that `sh`/`cat` (busybox on Alpine) never appear in the opensnoop ring buffer for any filename. Root cause: busybox uses `SYS_open` (syscall 2), our probe covers only `SYS_openat` (syscall 257). Fix decided: replace `opensnoop.bpf.c` with `lsm-file.bpf.c` using `lsm.s/file_open` hook. Rebuild required on GCP VM — not yet done.

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

**Also needed (Go only, no rebuild)**:
- Remove existing debug logs (`DEBUG file-target`, `DEBUG opensnoop ringbuf`) once V3/V7/V9 pass

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

> **GKE is currently DOWN** — bring up with `pulumi up` + `deploy.sh all` before running. Results below are from the last run before teardown.

| Test | Result | Root cause |
|------|--------|------------|
| V2 Shell spawn | ✅ PASS | Process sensor (execsnoop) working |
| V3 Shadow read | ❌ FAIL | **Root cause confirmed**: busybox uses SYS_open, probe covers SYS_openat only |
| V4 External connect | ✅ PASS | Network sensor (lsm-connect) working |
| V5 ai-service allowlist | ✅ PASS | |
| V6 No FP gateway traffic | ✅ PASS | |
| V7 SSH private key | ❌ FAIL | Same root cause as V3 |
| V8 Network recon tool | ✅ PASS | Process sensor working |
| V9 /etc/passwd recon | ❌ FAIL | Same root cause as V3 + dedup collision (runc→cat same PID) |
| V10 Reverse shell | ✅ PASS | Process + network sensors working |

**6 passed · 3 failed · 0 skipped**

Fix in progress: replacing `opensnoop.bpf.c` (SYS_openat tracepoint) with `lsm-file.bpf.c` (`lsm.s/file_open` + `bpf_d_path`). See BPF C Files section above.

Note: validate-gke.sh targets `auth-service`. Consider switching GKE target to `provider-service` in a future session to verify resolver correctness across services.

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
