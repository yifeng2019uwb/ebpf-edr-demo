# Session Handoff — 2026-06-08

## Current State

**GCP Docker VM: ACTIVE** — eBPF agent running, all 11 validate.sh tests passing.
**Health-AI GKE Cluster: DESTROYED** — torn down to save costs; redeploy when ready for eBPF testing.
**Health-AI DigitalOcean: PLANNED** — next permanent always-on deploy target. Plan: fix opensnoop on GKE first (1-2 sessions), then migrate infra to DO before GCP expiry.
GCP credits expire 2026-06-17 (~8 days). Resources on project `ebpfagent`.

---

## What Changed This Session (2026-06-08)

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
| `lsm-connect.bpf.c` | ✅ Correct | None (blocked_ips removed — was wrong scope) |
| `opensnoop.bpf.c` | ⚠️ Under investigation | tgid != tid filter suspected on GKE kernel 6.8 — diagnose first |

### What each C file does (and should only do)
- **C responsibility**: capture raw kernel events, minimal performance filtering (skip loopback, skip ENOENT, skip thread-level opens), emit to ring buffer
- **Go responsibility**: all detection policy, workload resolution, alerting, response actions

### opensnoop — GKE kernel 6.8 issue (unresolved)

**Symptom**: zero file events reach Go on GKE kernel 6.8. Process and network sensors work fine.

**What we know**:
- Tracepoints `sys_enter_openat` / `sys_exit_openat` exist on GKE nodes ✅
- Pod runs without crash — BPF programs loaded and attached ✅
- Zero file events in pod logs — not even from Java startup which opens hundreds of class files ❌
- V3/V7/V9 consistently fail across multiple deploys with different binary builds

**Suspected cause**: `tgid != tid` filter in `handle_enter` (opensnoop.bpf.c line 72) may always be true for container processes on GKE kernel 6.8, silencing opensnoop entirely. But this is unconfirmed — `cat` is single-threaded (tgid == tid) and should pass the filter.

**Next step — Go-only diagnostic (no C change, no VM rebuild)**:
Add one log line in `enrich()` for opensnoop events to count how many arrive in Go:
```go
case "opensnoop":
    log.Printf("DBG file event received: pid=%d filename=%s", ev.Pid, processor.CString(ev.Filename[:]))
    // ... rest of existing code
```
- If **zero** log lines → problem is in C/BPF layer → C change needed
- If **events arrive but no alerts** → filename is garbage or rule not matching → Go fix only

**If C change is needed**: remove `tgid != tid` filter AND plan Go-side noise handling in the same change. Do not change C without planning both sides. Requires rebuild on GCP VM.

### The one open C question — ENOENT in opensnoop

Current: ENOENT dropped (`bool valid = ret >= 0 || ret == -EACCES || ret == -EPERM`).
Gap: container probing `/etc/shadow` on Alpine (doesn't exist) returns ENOENT → invisible.
validate-gke.sh works around this by creating the file first.
Decision deferred until opensnoop issue resolved.

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
| V2 Shell spawn | ✅ PASS | Process sensor working |
| V3 Shadow read | ❌ FAIL | opensnoop emits zero events on GKE kernel 6.8 |
| V4 External connect | ✅ PASS | Network sensor working |
| V5 ai-service allowlist | ✅ PASS | |
| V6 No FP gateway traffic | ✅ PASS | |
| V7 SSH private key | ❌ FAIL | opensnoop emits zero events on GKE kernel 6.8 |
| V8 Network recon tool | ✅ PASS | Process sensor working |
| V9 /etc/passwd recon | ❌ FAIL | opensnoop emits zero events on GKE kernel 6.8 |
| V10 Reverse shell | ✅ PASS | Process + network sensors working |

**6 passed · 3 failed · 0 skipped**

Note: validate-gke.sh targets `auth-service`. Both Docker VM (validate.sh) and GKE use the same service — hard to verify resolver correctness for other services. Consider switching GKE target to `provider-service` in a future session.

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
