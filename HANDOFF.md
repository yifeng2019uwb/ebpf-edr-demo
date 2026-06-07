# Session Handoff — 2026-06-07

## Current State

**GCP Docker VM: ACTIVE** — eBPF agent running, all 11 validate.sh tests passing.
**Health-AI GKE Cluster: DOWN** — kept off to save costs; deploy on demand for eBPF testing.
<<<<<<< HEAD
**Health-AI DigitalOcean: PLANNED** — next deploy target (see health-ai docs/deploy-strategy.md).
=======
**Health-AI DigitalOcean: PLANNED** — next deploy target for permanent always-on environment.
>>>>>>> ff7b208f6ecd3257e0ed2744621ae91ec4468e81
GCP credits expire 2026-06-17 (~10 days). Resources on project `ebpfagent`.

---

<<<<<<< HEAD
## BPF C Files — Scope Review (2026-06-07)

**Rule: Do NOT change .bpf.c files unless truly necessary. All detection/policy logic belongs in Go.**

| File | Status | C changes needed |
|------|--------|-----------------|
| `execsnoop.bpf.c` | ✅ Correct | None |
| `lsm-connect.bpf.c` | ✅ Correct | None (blocked_ips removed — was wrong scope) |
| `opensnoop.bpf.c` | ✅ Correct | Maybe ENOENT only — decide after goroutine fix |

### What each C file does (and should only do)
- **C responsibility**: capture raw kernel events, minimal performance filtering (skip loopback, skip ENOENT, skip thread-level opens), emit to ring buffer
- **Go responsibility**: all detection policy, workload resolution, alerting, response actions

### The one open C question — ENOENT in opensnoop
Current: `bool valid = ret >= 0 || ret == -EACCES || ret == -EPERM` — ENOENT dropped.

Gap: if a container probes `/etc/shadow` on Alpine (where it doesn't exist), returns ENOENT → invisible to Go. Validate-gke.sh works around this by creating the file first.

Decision deferred until after goroutine fix. If V3/V7/V9 pass without it, the workaround is sufficient. If needed, it is a one-line C change (requires rebuild on GCP VM).

### openat() return code reference
| Return | Meaning | Currently | Security value |
|--------|---------|-----------|---------------|
| `>= 0` | File opened | ✅ emit | High |
| `-EACCES` | File exists, access denied | ✅ emit | High |
| `-EPERM` | Operation not permitted | ✅ emit | High |
| `-ENOENT` | File does not exist | ❌ drop | Medium — probe attempt |
| `-EROFS` | Write to read-only FS | ❌ drop | Low |
| `-ETXTBSY` | Write to executing binary | ❌ drop | Low — T1554 future rule |
| others | System/resource errors | ❌ drop | None |

---

## Go Fixes Needed (next session)

### Fix 1 — File reader goroutine restart (PRIORITY — unblocks V3/V7/V9)

**File:** `cmd/edr-monitor/main.go`

**Problem:** All three reader goroutines exit silently on any error (`if err != nil { return }`).
On GKE, Java startup hammers the ring buffer. A transient error kills the file reader goroutine
permanently — process and network goroutines survive unaffected.

**Fix:** Add restart loop:
```go
go func() {
    for {
        rec, err := loader.FileRd.Read()
        if err != nil {
            log.Printf("file reader error: %v — restarting", err)
            time.Sleep(time.Second)
            continue  // restart instead of exit
        }
        // ... existing logic
    }
}()
```
Same pattern for process and network readers for consistency.

**Verification:** Deploy to GKE, run `./validate-gke.sh`, expect V3/V7/V9 to pass.

### Fix 2 — StateUnknown false positives (after Fix 1)

**File:** `pkg/workload/k8s_resolver.go`

**Problem:** `containerIDFromK8sCgroup()` returns `""` for two different cases:
- Case A: no "kubepods" in cgroup → host process (safe)
- Case B: "kubepods" in cgroup but can't parse → legitimately suspicious

Both currently leave the namespace unresolved → StatePending → StateUnknown → 🚨 CRITICAL T1611.
Host daemons with private mount namespaces (not containers) trigger false escape alerts.

**Fix:** Distinguish the two cases with a sentinel:
```go
// In containerIDFromK8sCgroup:
if !strings.Contains(line, "kubepods") {
    return "HOST"  // sentinel — not a k8s pod
}

// In buildCache:
containerID := containerIDFromK8sCgroup(pid)
if containerID == "HOST" {
    m[nsID] = r.bareResult(StateHost)  // host process — mark safe
    continue
}
if containerID == "" {
    continue  // kubepods but unparseable — leave unresolved (suspicious)
}
```

**Result:** T1611 only fires for processes that genuinely look like k8s workloads but
can't be identified — not for host daemons with private namespaces.

---

## validate-gke.sh — Current Results
=======
## IMMEDIATE NEXT STEP — Fix file sensor (Go-only, no BPF C changes)

### Root cause identified

The file reader goroutine in `cmd/edr-monitor/main.go` exits silently on any error:

```go
go func() {
    for {
        rec, err := loader.FileRd.Read()
        if err != nil {
            return  // ← exits permanently, no restart, no log
        }
        // ...
    }
}()
```

On GKE, Java startup hammers the ring buffer with file opens. If this causes a
transient ring buffer error, the goroutine dies — and file events stop forever.
Process and network goroutines are unaffected (separate goroutines), which is
exactly the V3/V7/V9 failure pattern we see.

The same silent-exit pattern exists in all three reader goroutines (process, file, net).
Process/network goroutines survive because perf buffer and LSM hook are more stable.

### Fix (Go-only — no .bpf.c changes, no rebuild on GCP VM)

Add restart loop to the file reader goroutine in `cmd/edr-monitor/main.go`:

```go
go func() {
    for {
        rec, err := loader.FileRd.Read()
        if err != nil {
            log.Printf("file reader error: %v — restarting", err)
            time.Sleep(time.Second)
            continue  // restart, don't exit
        }
        // ...
    }
}()
```

After fix:
1. `make build` (can run on Mac — Go-only change)
2. `make docker-push-prebuilt`
3. Redeploy DaemonSet to GKE: `./kubernetes/deploy.sh app`
4. `./validate-gke.sh` — expect V3/V7/V9 to pass

### Diagnostic first (before fix) — confirm root cause

If GKE is up, run before applying the fix to confirm:
```bash
EDR_POD=$(kubectl get pod -n kube-system -l app=ebpf-edr -o jsonpath='{.items[0].metadata.name}')
# Check if ANY file events ever appeared (should see T1082 from Java startup if sensor works)
kubectl logs $EDR_POD -n kube-system | grep -c "T1082\|T1552\|T1003"
# If 0 → goroutine exited; if >0 → different issue
```

---

## Key Rule — Do NOT change .bpf.c files

Recent sessions incorrectly changed `lsm-connect.bpf.c` to add kernel IP blocking,
hit the BPF verifier complexity limit, then had to remove it — full cycle with two
binary rebuilds and GKE redeployments, ending back at the same place.

**All remaining fixes are Go-only:**
- File sensor goroutine restart → `cmd/edr-monitor/main.go`
- Any policy/rule changes → `pkg/detector/policy.go`, `pkg/detector/rules.go`
- Workload resolver fixes → `pkg/workload/`

Changing `.bpf.c` requires: rebuild on GCP VM (Linux) → commit generated files →
pull on Mac → `make docker-push-prebuilt` → redeploy. Avoid unless truly necessary.

### lsm-connect.bpf.c history (for reference)
- Was simple audit-only hook (no blocking)
- `67abbea` added `blocked_ips` LPMTrie (kernel IP blocking)
- Hit BPF verifier complexity limit on GKE
- `d6cacd0` removed `blocked_ips` entirely — back to simple audit-only hook
- Current state: simple audit hook, same as original. IP blocking disabled.

---

## validate-gke.sh — Current Results (2026-06-06)

Gateway IP changes on each GKE redeploy — check `kubectl get svc gateway -n health-ai`.
>>>>>>> ff7b208f6ecd3257e0ed2744621ae91ec4468e81

| Test | Result | Root cause |
|------|--------|------------|
| V2 Shell spawn | ✅ PASS | Process sensor working |
<<<<<<< HEAD
| V3 Shadow read | ❌ FAIL | File reader goroutine exits silently |
| V4 External connect | ✅ PASS | Network sensor working |
| V5 ai-service allowlist | ✅ PASS | |
| V6 No FP gateway traffic | ✅ PASS | |
| V7 SSH private key | ❌ FAIL | File reader goroutine exits silently |
| V8 Network recon tool | ✅ PASS | Process sensor working |
| V9 /etc/passwd recon | ❌ FAIL | File reader goroutine exits silently |
=======
| V3 Shadow read | ❌ FAIL | File reader goroutine exited silently |
| V4 External connect | ✅ PASS | Network sensor working |
| V5 ai-service allowlist | ✅ PASS | |
| V6 No FP gateway traffic | ✅ PASS | |
| V7 SSH private key | ❌ FAIL | File reader goroutine exited silently |
| V8 Network recon tool | ✅ PASS | Process sensor working |
| V9 /etc/passwd recon | ❌ FAIL | File reader goroutine exited silently |
>>>>>>> ff7b208f6ecd3257e0ed2744621ae91ec4468e81
| V10 Reverse shell | ✅ PASS | Process + network sensors working |

**6 passed · 3 failed · 0 skipped**

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

<<<<<<< HEAD
`block_ip` response disabled — `blocked_ips` LPMTrie removed from `lsm-connect.bpf.c`
(BPF verifier complexity limit). Alert T1041 still fires; enforcement is disabled.
`NewResponder(nil)` in `main.go`. Response policy and `blockIP()` function remain as dead
code — remove in future cleanup pass.
=======
`block_ip` response is disabled — `blocked_ips` LPMTrie removed from `lsm-connect.bpf.c`
(BPF verifier complexity limit on GKE). Alert still fires; only enforcement is disabled.

Re-enable path requires C changes (see rule above — avoid for now).
>>>>>>> ff7b208f6ecd3257e0ed2744621ae91ec4468e81

---

## Key Facts

### GCP Credits
- Expire: 2026-06-17 (~10 days)
<<<<<<< HEAD
- Docker VM `instance-20260318-023006` always on (~$43/mo billed to credits)
- Health-AI GKE: bring up only for eBPF testing

### eBPF Agent Binary
- Go-only changes: `make build` on Mac → `make docker-push-prebuilt` → redeploy DaemonSet
- BPF C changes: rebuild on GCP VM with `make rebuild` → commit generated files → pull on Mac
- **Avoid C changes** — all current fixes are Go-only

### Health-AI GKE (on-demand)
- Deploy: `cd kubernetes && ./deploy.sh all`
- Validate: `./validate-gke.sh` (from ebpf-edr-demo/)
- Destroy: `./deploy.sh destroy`
- DB: Supabase (external) — credentials in `health-ai/docker/.env`
=======
- Resources on `ebpfagent`: Docker VM `instance-20260318-023006` (~$43/mo)
- Health-AI GKE kept OFF — bring up only for eBPF testing
- After expiry: Cloud Logging free tier remains

### eBPF Agent Binary
- `make docker-push` — requires Linux; run on GCP VM
- `make docker-push-prebuilt` — uses committed binary; safe to run on Mac
- Go-only changes: `make build` on Mac → `make docker-push-prebuilt` → redeploy

### Health-AI GKE (on-demand)
- Cluster: `health-ai-cluster-us-west1`, namespace: `health-ai`, project: `ebpfagent`
- Pulumi: `health-ai/kubernetes/pulumi/` stack `gke-dev`
- Deploy: `./kubernetes/deploy.sh [all|build|infra|app|rls|status|destroy]`
- DB: Supabase (external, always on) — credentials in `health-ai/docker/.env`
>>>>>>> ff7b208f6ecd3257e0ed2744621ae91ec4468e81

### Alert Router (Mac)
- `make run-alert-router` — requires `gcloud auth application-default set-quota-project ebpfagent`

### Known False Positives
<<<<<<< HEAD
- `T1611_escape_to_host_ns` — fires on host daemons with private namespaces (Fix 2 will resolve)
- `T1611_escape_to_host_proc` on GKE — GKE monitoring sidecars read `/proc/1/`; response set to none
- `docker cp` during validate.sh → `state=unknown / comm=exe` alerts — test artifact
=======
- `T1611_escape_to_host_ns` from Podman health checks — excluded from kill response
- `T1611_escape_to_host_proc` on GKE — monitoring sidecars read `/proc/1/`; response set to none
- `docker cp` during validate.sh creates `state=unknown / comm=exe` alerts — test-setup artifact
>>>>>>> ff7b208f6ecd3257e0ed2744621ae91ec4468e81
- `ai-service` external Gemini calls — add to `externalAllowedServices` in `policy.go` if HIGH alerts appear
