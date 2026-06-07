# Session Handoff — 2026-06-07

## Current State

**GCP Docker VM: ACTIVE** — eBPF agent running, all 11 validate.sh tests passing.
**Health-AI GKE Cluster: DOWN** — kept off to save costs; deploy on demand for eBPF testing.
**Health-AI DigitalOcean: PLANNED** — next deploy target (see health-ai docs/deploy-strategy.md).
GCP credits expire 2026-06-17 (~10 days). Resources on project `ebpfagent`.

---

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

| Test | Result | Root cause |
|------|--------|------------|
| V2 Shell spawn | ✅ PASS | Process sensor working |
| V3 Shadow read | ❌ FAIL | File reader goroutine exits silently |
| V4 External connect | ✅ PASS | Network sensor working |
| V5 ai-service allowlist | ✅ PASS | |
| V6 No FP gateway traffic | ✅ PASS | |
| V7 SSH private key | ❌ FAIL | File reader goroutine exits silently |
| V8 Network recon tool | ✅ PASS | Process sensor working |
| V9 /etc/passwd recon | ❌ FAIL | File reader goroutine exits silently |
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

`block_ip` response disabled — `blocked_ips` LPMTrie removed from `lsm-connect.bpf.c`
(BPF verifier complexity limit). Alert T1041 still fires; enforcement is disabled.
`NewResponder(nil)` in `main.go`. Response policy and `blockIP()` function remain as dead
code — remove in future cleanup pass.

---

## Key Facts

### GCP Credits
- Expire: 2026-06-17 (~10 days)
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

### Alert Router (Mac)
- `make run-alert-router` — requires `gcloud auth application-default set-quota-project ebpfagent`

### Known False Positives
- `T1611_escape_to_host_ns` — fires on host daemons with private namespaces (Fix 2 will resolve)
- `T1611_escape_to_host_proc` on GKE — GKE monitoring sidecars read `/proc/1/`; response set to none
- `docker cp` during validate.sh → `state=unknown / comm=exe` alerts — test artifact
- `ai-service` external Gemini calls — add to `externalAllowedServices` in `policy.go` if HIGH alerts appear
