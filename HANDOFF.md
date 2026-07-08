# Project Handoff — Current Status

**Last Updated:** 2026-07-08 (K8s detection restored — full validation green)  
**Status:** ✅ Detection working on DO K8s — `./validate-do-k8s.sh` passes 11/11; ancestry/Phase-3 FP work also in
- Layer 1 fast-path filtering: ✅ DONE (ppid==0, pid in safeInfraPIDs)
- Layer 2 whitelisting: ✅ DONE (global_exceptions + exception macros; now skipped for verified containers)
- Process ancestry cache + bounded ancestry walk: ✅ DONE (replaces the old name-based blocklists — see `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md`)
- Phase 3 unresolved→LOW telemetry downgrade: ✅ DONE (no more CRITICAL T1611 for transient host processes)
- K8s workload resolution: ✅ FIXED (was fully broken — see 2026-07-08 section below)
- **Note:** the "Two-Stage Parent Process Verification" sections further down are SUPERSEDED by the ancestry-cache design; kept only for history.

---

## DONE: K8s detection was fully broken → restored, 11/11 validation green (2026-07-08)

A day-long hunt. K8s detection produced **only** `state=unknown` / LOW telemetry — no container
alerts at all. Root cause + a stack of resolver bugs beneath it, all now fixed.

**Root cause (the big one):** `cmd/edr-monitor/main.go` passed a `*pipeline.EnrichedEvent`
to `WorkloadResolver.Resolve()`, but every resolver type-switches only on
`*processor.ProcessEvent/FileEvent/NetEvent` → hits `default` → `StateUnknown` for **every**
event, on **both** runtimes (Docker was broken the same way, just untested). The `interface{}`
param meant the compiler never flagged it. A refactor had swapped `r.Resolve(ev)` →
`r.Resolve(enriched)`. Fix: pass the underlying `*processor` event (`enrich()` uses `ev`;
pending-retry uses new `underlyingEvent()` helper). **Note in memory:
`resolver-takes-processor-events`.** If detection ever goes fully dark (all state=unknown),
check the `.Resolve(...)` argument type FIRST.

**Resolver bugs found underneath (all in `pkg/workload/k8s_resolver.go`), each only reachable
once the type switch was fixed:**
1. **cgroupfs parser** — `containerIDFromK8sCgroup` only handled the systemd driver
   (`cri-containerd-<id>.scope`). DO nodes use **cgroupfs** (`/kubepods/burstable/pod<uid>/<raw-64-hex>`).
   Added a raw-64-hex fallback (`isHexID`).
2. **Dead-transient poisoning** — a dead process's empty cgroup was cached as `RuntimeHost`,
   and the K8s cache has no eviction → permanently poisoned the namespace. Now skips caching
   when `/proc/<pid>` is gone (mirrors Docker).
3. **No startup pre-population** — `buildInitialCache` only seeded self; Docker's `buildCache`
   scans `/proc`. Added a `/proc` scan that pre-resolves all container namespaces (logs
   `initial cache pre-populated N container namespaces`), so cold-start after a redeploy
   doesn't miss short-lived attacks.
4. **Agent self-FP** — the agent's own namespace was seeded via `bareResult` = `RuntimeK8s`,
   so its 5s `crictl` sync fired false T1613. Now seeded as `RuntimeHost`.
5. **Service-name mangling** — `normalizeServiceName("auth-service")` → `"service"` (splits on
   last `-`; a Docker-Compose helper). K8s now uses the container name directly.

**Detection policy:** `parent_context: infrastructure` global-exceptions no longer apply to
**verified-container** events (`yaml_detector.go`) — a shell/curl *inside* a container is the
signal (T1059/T1105/T1041), not host noise. This is what got V2/V4/V8/V10 to fire. Tradeoff:
container `curl/wget` now alerts; exec-style liveness probes would too (health-ai uses httpGet,
so no FP here — allowlist per-service if a future service uses exec-curl probes).

**Verified:** `./validate-do-k8s.sh` → **11/11**, real service/pod/namespace attribution,
kill-responses firing, no FPs on normal traffic.

**Docker `validate.sh` (rewritten to assert for real):**
- Alert-source fix: `LOG` is resolved absolutely (script-relative), overridable via
  `ALERT_LOG_PATH`. The docker agent loads `infra/.env` (godotenv), so its `ALERT_LOG_PATH`
  must be the docker path (`alerts/alert.log`), NOT the K8s `/alerts/alert.log` — that mismatch
  was why the file looked empty. K8s gets its path from the manifest, not `infra/.env`.
- `expect_alert` now asserts real alerts for **T1, T3, T4, T5, T8–T13** (was bare `pass`).
- **Removed tests (cover later, need work):**
  - **T2** (T1105 net-tool) — needs a *working* `nc`/`ncat`/`wget` in the container; the Python
    images have none and a host-copied `nc` won't run (missing libs). Re-add per-image with a
    static tool.
  - **T6** (allowlist negative) — needs a `no_alert` helper to actually verify "no alert fired";
    was a passive `pass`.
  - **T7** (T1611 host-reads-container-overlay) — detection is **commented out** in
    `checkFileRules`; wire that rule first, then re-add the test.
- Header numbering still says `/13` (10 tests now) — cosmetic, renumber if it bugs you.

**Post-validation FP tuning:**
- **T1082 `/etc/passwd` FP storm (FIXED).** T1082 fired on *any* container reading
  `/etc/passwd`/`/etc/group`, but those are world-readable and read constantly by libc NSS
  (`getpwuid`/`getgrgid`) → every normal service tripped it. Now gated on the READER: only fires
  when a recon/shell tool reads them (new `recon_file_readers` list in `default.yaml`; check in
  `yaml_detector.go` T1082 block). App NSS reads no longer alert; `cat /etc/passwd` still does.
  Caveat: a service whose entrypoint runs `getent`/`id`/`cat` at startup would still fire —
  allowlist that service if it happens.

**Cleanup / minor left:**
- Temp debug: removed mine (`DEBUG k8s async`); yours (`DEBUG k8s Resolve`) are commented out —
  delete when convenient.
- `default.yaml` `Health checks…` exception comment is now stale (no longer applies to containers).
- File-dedup double-fire: some file alerts fire twice ~80ms apart despite the 1s
  `fileDedupWindow` — cosmetic noise, low priority. Likely the dedup key differs subtly between
  the two events (thread vs group-leader pid, or trailing bytes in `Comm`/`Filename`).
- **Docker** is fixed by the same type-mismatch fix but should be re-validated end-to-end.

---

## DONE: Route LOW telemetry off the live dashboard (2026-07-07)

**Context:** Phase 3 emits `LOW EDR_telemetry_unresolved_namespace` for the residual
`state=unknown` processes the ancestry walk can't verify as infrastructure (e.g. udev
`bridge-network-interface`, open-iscsi `net-interface-handler`, `systemd-sysctl` during
network setup / deploy). These are *not* threats — they're a visibility gap. They no
longer fire CRITICAL, but at LOW they were still flooding the live dashboard.

**Decision & rationale:** Keep them at LOW, but off the human-facing live dashboard.
LOW ≈ Info; a dashboard full of it causes alert fatigue — humans skip LOW and miss the
CRITICAL/HIGH that matter. Telemetry persists to **file + Supabase**; an automated
**anomaly/behavior service** (see "Phase 2: Behavioral & Anomaly Detection" below)
consumes the Supabase stream. This LOW stream is that service's input.

**Implementation (simple, by level):** `RedisSink.Write` drops `alert.Low`
(`pkg/alertsink/redis_sink.go`). File + Supabase sinks are unchanged, so they still
receive everything. Chose the level check over a `FilterSink`/`Telemetry`-flag decorator
to keep it minimal; currently LOW == telemetry. If a real actionable LOW alert is added
later that *should* hit the dashboard, revisit (tag telemetry explicitly then).

---

## KNOWN ISSUE (deferred): `./deploy.sh app` never applies the eBPF DaemonSet — Pulumi hang (2026-07-07)

**Symptom:** the durable alert log (`ALERT_LOG_PATH=/alerts/alert.log` → node `/var/log/ebpf-edr/alert.log`)
never took effect through the pipeline — the DaemonSet spec never gained `ALERT_LOG_PATH`
across many rebuild/deploy cycles, so the agent kept writing to the ephemeral
`/app/alerts/alert.log` (relative default).

**Root cause:** health-ai `kubernetes/deploy.sh` → `_apply_daemonset()` prints
`Applying eBPF EDR DaemonSet from local repo...` then **hangs at two `pulumi stack output`
calls** (region/cluster) that run *before* `kubectl apply`. That's GKE/Pulumi-era code —
**we don't use Pulumi now** — and it stalls on the DO cluster, so `kubectl apply` +
`rollout restart` for the DaemonSet never run. Other services deploy fine (they don't go
through that function). The new *image* still lands via `rollout restart` +
`imagePullPolicy: Always`, which is why the binary was always current but the env never was.

**Workaround in place (working):**
`kubectl -n kube-system set env daemonset/ebpf-edr ALERT_LOG_PATH=/alerts/alert.log`
— persists in the DS spec, survives restarts, and is NOT clobbered by `./deploy.sh app`
(the apply hangs before touching the DaemonSet). Durable log confirmed writing
(`/alerts/alert.log` growing; `/app/alerts` gone).

**Proper fix (deferred):** in `_apply_daemonset`, drop the `pulumi stack output`
region/cluster lookups (Pulumi unused) — hardcode/env the `${REGION}`/`${CLUSTER_NAME}`
values for `envsubst`, or move `kubectl apply` ahead of them. Once the pipeline applies the
manifest, `ALERT_LOG_PATH` flows via the already-wired chain: `.env` → deploy.sh ConfigMap
key `alert-log-path` → manifest `configMapKeyRef` (optional). No agent code change needed —
the Go side (config.go env read + file_sink dir create) is correct.

**Related open item:** on K8s the Supabase sink is disabled (`DATABASE_URL` resolves over
IPv6; DO nodes have no IPv6 route), so LOW telemetry currently persists only to the node
file until the DB URL uses the IPv4/Supavisor endpoint.

---

## Known Issue: Docker Container Cache Never Evicts (2026-07-06)

**Status:** `listenDockerEvents()` is commented out in `DockerResolver.Start()` (`pkg/workload/docker_resolver.go`). Disabled today because its recovery/reconnect logic had unresolved issues and is hard to test reliably without a live Docker daemon to script event sequences against.

**Effect:** The only cache-cleanup code (removing `r.cache`/`r.containerToNs` entries on container stop/die/remove) lived inside `listenDockerEvents()`. With it disabled:
- `r.cache` and `r.containerToNs` only grow, via `asyncResolvePID` on new namespaces.
- Stopped/removed containers are never purged — slow unbounded growth plus stale entries if a namespace ID is ever reused.
- `lightweightRefresh()` (also only called from `listenDockerEvents()`) is currently unreachable.

**Why deferred:** Containers currently get discovered fine on-demand via `asyncResolvePID` (used at `Start()` for the initial `buildCache()` snapshot and per-event thereafter), so this doesn't block correctness of detection today — it's a slow memory/staleness leak, not a false positive/negative source. Revisit once the event-listener recovery path is redesigned and testable.

---

## Current Session: Two-Stage Parent Process Verification (2026-07-06)

**Objective:** Eliminate false positives from transient tools (grep, sleep, wget, curl, etc.) spawned during docker deploy/destroy without creating unmaintainable blocklists.

**Problem Analysis:**
- False positives flood during docker deploy (100+ CRITICAL alerts/sec)
- Root cause: transient processes exit before resolver completes, leaving state=unknown
- Example: deployment script spawns grep/sleep, they exit in milliseconds, resolver can't identify parent
- Previous approaches failed: adding each tool to blocklists is unmaintainable

**Solution Design: Two-Stage Parent Process Verification** ✅ DESIGNED

**Stage 1: Core Container Runtime Tools (Always Drop)**
- YAML list: `container_runtime_execs` 
- Tools: runc, containerd-shim, docker-proxy, dockerd, containerd, docker
- Rule: If state=unknown AND comm in container_runtime_execs → DROP (never alert)
- Rationale: These ARE infrastructure, can never be attacker-spawned

**Stage 2: Dynamic Lifecycle Utilities (Verify Parent)**
- YAML list: `docker_lifecycle_tools`
- Tools: grep, sleep, wget, curl, cut, tr, sed, etc., snap tools, docker-compose
- Rule: If state=unknown AND comm in docker_lifecycle_tools → READ parent command from /proc/ppid/comm → only DROP if parent is trusted (dockerd, containerd, snap, or another core tool)
- Rationale: Could be legitimate deployment OR malicious tool; parent command validates intent
- Secure default: If parent PID already exited (can't read /proc), return alert (secure fail)

**Key Advantages Over Blocklists:**
- ✅ No endless tool-name expansion
- ✅ Maintains security (attacker escapes won't have trusted parent)
- ✅ Works for transient parents (reads parent command at event time)
- ✅ Adapts to unknown Docker version changes

**Implementation Status:**
- ✅ YAML lists defined: container_runtime_execs, docker_lifecycle_tools
- ✅ Design documented and validated
- ⏳ Code implementation pending:
  - Modify yaml_detector.go: checkProcessRules() state=unknown section
  - Lines 377-398: Restructure to implement two-stage logic
  - Stage 1 check (runtimeExecs): Keep as-is (always drop)
  - Stage 2 check (dockerLifecycleTools): Read parent command, only drop if parent trusted

**Files to Modify:**
- `pkg/detector/yaml_detector.go` (lines 374-398) - implement two-stage logic
- `rules/default.yaml` - already has lists defined, no changes needed

**Next Steps (When Ready to Implement):**
1. Modify dockerLifecycleTools check to read parent command
2. Verify parent command is one of: dockerd, containerd, snap, or in coreRuntimeTools
3. Test on docker deploy to verify false positive reduction

---

## In Progress Work: Performance Bottleneck Root Cause Analysis & Fix (2026-07-03)

**Phase:** Root cause identified + partial fix implemented  
**Objective:** Resolve 146 events/sec bottleneck (target: 5000+/sec, 34× improvement needed)  
**Methodology:** Static review → identify root cause → implement fix → verify with logs

### Root Cause Analysis

**Problem Statement**
- eBPF producing 281 file events/sec, but only 13.9 resolved/sec
- 95% of events stuck as pending, then timing out → alerts never fired
- System appeared functional (logs shown) but completely blind to actual threats

**Root Cause #1: Docker Daemon Namespace (FIXED ✅)**
- **Issue:** When async resolver tried to read `/proc/[pid]/cgroup` for events from docker daemon, it found infrastructure processes (like containerd daemon PID 189541)
- **Problem:** These daemons have cgroups like `0::/system.slice/snap.docker.dockerd.service` (not containers), so containerID parsing failed, returning empty
- **Effect:** Entire docker namespace got stuck as `state=pending`, waiting for containerID that would never come
- **Fix Implemented:** 
  - Added `HostNamespaceService(mntNsID)` interface method to WorkloadResolver
  - DockerResolver now checks if mntNsID == dockerdNsID (docker daemon's namespace)
  - Returns service name directly ("docker-host") without async resolution
  - Coordinator adds Fast Path 3 check before delegating to async resolver
  - Files modified: `identity.go`, `docker_resolver.go`, `k8s_resolver.go`, `host_resolver.go`, `coordinator.go`
- **Verification:** Logs now show mixed `state=resolved` (docker-host) and `state=pending` (legitimate containers)

**Root Cause #2: Transient Process Race Condition (PARTIALLY FIXED ⚠️)**
- **Issue:** When new container starts after startup, events arrive with transient PIDs (process exits before async resolver can read `/proc/[pid]/cgroup`)
- **Current behavior:** asyncResolvePID → open `/proc/[pid]/cgroup` → ENOENT (process gone) → containerID empty → StateUnknown
- **Effect:** Container events still get stuck as pending or unknown
- **Current status:** Fix #1 prevents false infrastructure namespace issues, but real container resolution still fails for transient processes
- **Logs show:** Still seeing `containerID empty for ns 4026532403 pid 660 (procfs race)` errors
- **Next step:** Implement fallback when transient PID fails:
  1. Check if namespace already in buildCache (discovered at startup)
  2. Scan /proc for another process in same namespace (more stable cgroup read)
  3. Use Docker API if needed (last resort)

### Implementation Summary

**What was changed:**
1. `pkg/workload/identity.go` — Added `HostNamespaceService()` to interface
2. `pkg/workload/docker_resolver.go` — Implemented check for dockerdNsID
3. `pkg/workload/coordinator.go` — Added Fast Path 3 before async delegation
4. `pkg/workload/k8s_resolver.go` — Implemented (returns nil, no daemon namespace in K8s)
5. `pkg/workload/host_resolver.go` — Implemented (returns nil, handled by Coordinator)

**Build Status:** ✅ Compiles successfully

**Log Evidence:**
- Before: Only docker daemon was problematic (PID 189541 in system.slice)
- After: System correctly identifies `docker-host` processes as resolved
- Still broken: New containers starting after startup (transient process race)

### Implementation Complete: Docker Infrastructure Namespace Detection (2026-07-04)

**Problem Identified:**
- Only checking single `dockerdNsID` (snap docker daemon)
- Missing other infrastructure processes: containerd, runc, docker-proxy, containerd-shim, snapd
- Events from these namespaces were failing async resolution and poisoning cache with StateUnknown

**Solution Implemented:**
1. **Changed data structure:**
   - Removed: `dockerdNsID uint32` (single namespace)
   - Added: `infraNamespaces map[uint32]string` (mntNsID → process_name)

2. **New function: `findAllDockerInfrastructureNamespaces()`**
   - Scans /proc for 6 infrastructure process types: dockerd, containerd, runc, docker-proxy, containerd-shim, snapd
   - Returns map of all infrastructure namespace IDs
   - Called at startup and on Docker reconnect

3. **Updated methods:**
   - `Start()`: Populate infraNamespaces from new function
   - `HostNamespaceService()`: Check if namespace exists in infraNamespaces map (fast path)
   - `listenDockerEvents()`: Refresh infraNamespaces when Docker connects/disconnects
   - `lightweightRefresh()`: Simplified (no longer needs dockerdNsID check)
   - `asyncResolvePID()`: Removed dockerdNsID check (no longer needed)

4. **Files modified:**
   - `pkg/workload/docker_resolver.go` - complete refactor of daemon namespace handling

**Verification:**
- ✅ Code builds successfully (`go build ./pkg/workload`)
- ✅ All infrastructure processes now properly identified as docker-host
- ⏳ Next: Deploy and verify alerts resume firing

---

---

## Current State

### What's Working ✅

- **eBPF Agent**: Deployed to DO K8s, detecting all 12 MITRE techniques
  - Validation: 12/12 tests passing (`./validate-do-k8s.sh`)
  - Alerts: file + Redis + Supabase (end-to-end)
  - Config: Environment-aware (DO, K8s, Docker)

- **Alert Pipeline**: 
  - File sink: `alerts/alert.log` ✅
  - Redis pub/sub: real-time delivery ✅
  - Supabase PostgreSQL: persistent storage ✅ (via Supavisor IPv4 endpoint)

- **Detection Rules**: All migrated to YAML (`rules/default.yaml`)
  - 14 MITRE techniques implemented
  - Environment-specific whitelisting (cloud agents, K8s infra)
  - Response actions (kill_process, blockIP)
  - ✅ Validated: 12/12 test scenarios passing

- **Deployment Scripts**:
  - `scripts/deploy-ebpf-k8s.sh` — generic K8s deployment
  - `validate-do-k8s.sh` — 12-test functional validation
  - Works on any K8s cluster (tested on DO)

### Known Limitations (Current)

**✅ Fixed**
- Docker Snap Detection — working reliably
- DNS port 53 (systemd-resolve) — excluded from T1041

**⚠️ Critical Issue — Ephemeral Parent Process Race Condition (2026-07-05)**

**Problem:** Child processes (curl, sshd) alerting as state=unknown escape attempts
- Example alerts: `curl ppid=336791` (dead), `sshd ppid=5440` (SSH worker)
- Root cause: Parent process exits before resolver can read `/proc/[ppid]/cgroup`
- Effect: Resolver can't determine if parent was infrastructure → child left as state=unknown
- Result: CRITICAL T1611 false positives for legitimate health checks + SSH operations

**Detailed Analysis:**
1. **Curl health checks:** Ephemeral containerd-shim or orchestration process spawns curl, exits in milliseconds
2. **SSH workers:** Main sshd listener (PID 5440) forks worker for each connection; workers inherit cgroup context
3. **Race condition:** By time detector runs (async), parent is dead; can't read ppid's /proc to verify infrastructure status
4. **Current behavior:** asyncResolvePID → open `/proc/[ppid]/cgroup` → ENOENT → can't identify ppid → child stays unknown

**Temporary Fix (whitelist):** ✅ Implemented
- Added ephemeral_processes list (curl, redis-cli, wget, nc) to YAML
- If ephemeral process + parent in infrastructure whitelist → skip alert
- Limitation: Doesn't work if parent already dead; ppid's /proc doesn't exist
- Also added sshd to whitelisted_file_access_procs (SSH auth needs /etc/passwd)
- Also added early whitelist check in resolver (check comm before cgroup lookup)

**Proper Fix Candidates (need discussion):**
1. **Resolve ppid proactively (enricher)** — Capture parent identity when child event created (while ppid alive)
   - Requires: EnrichedEvent struct changes, parent resolution in enricher
   - Pro: Most reliable, handles all ephemeral cases
   - Con: More complex, requires passing resolver to enricher

2. **Capture parent context in kernel** — Include parent name/namespace in eBPF event
   - Pro: No race condition, most accurate
   - Con: Requires .bpf.c changes

3. **Skip unknown alerts for known ephemeral patterns** — curl/sshd + parent-not-in-proc = infrastructure
   - Pro: Simple, covers common cases
   - Con: Conservative, might miss some real threats

**⚠️ Accepted (Not Blocking Production)**
1. **T1611 False Positives** — Container initialization noise (state=unknown during startup)
   - Expected: ~80% of Docker alerts are initialization processes (dpkg, apt-get, pip, iSCSI)
   - Acceptable in controlled environments; suppression logic deferred until performance optimized

2. **T1105 Detection** — T1041 is sufficient proof (exfiltration threat confirmed)

3. **blockIP IPv4-only** — Covers majority of threats; IPv6 support deferred

---

## Architecture

```
eBPF Agent (deployed everywhere via DaemonSet)
  ├─ eBPF programs (kernel): execsnoop, opensnoop, lsm-connect
  ├─ Event enrichment: workload resolver (Docker/K8s)
  ├─ Detection: YAML rules + response actions
  └─ Alert sinks: file, Redis, Supabase

Alert Pipeline
  ├─ Redis pub/sub (real-time)
  ├─ Supabase PostgreSQL (persistent)
  └─ Alert Router web UI (viewing)

Configuration
  ├─ rules/default.yaml (detection rules)
  ├─ infra/.env (credentials)
  └─ k8s/ebpf-edr-ds.yaml (K8s manifest)
```

---

## Work in Queue

**IN PROGRESS: False Positive Reduction (Ephemeral Parent Race)** 🔄
- **Status:** Temporary whitelist fix implemented ✅ (needs testing)
  - Added ephemeral_processes list (curl, redis-cli, wget, nc)
  - Early whitelist check in resolver (before cgroup lookup)
  - sshd added to whitelisted_file_access_procs
- **Testing required:** Run on Docker VM to verify reduction in false curl/sshd alerts
- **Proper fix pending:** Need discussion on 3 approaches (parent resolution in enricher vs kernel capture vs conservative whitelist)

**IN PROGRESS: Performance Optimization (Partial Fix Done)** 🔄
- Phase 1 (Docker Daemon): ✅ COMPLETE — HostNamespaceService fast path prevents daemon processes from async resolution
- Phase 2 (Transient Process Fallback): ⏳ PENDING — Need to implement scan-proc or buildCache fallback for new containers
- Estimated impact: Current bottleneck 95%→partial fixed; Phase 2 should resolve remaining 5%

**Future Work** (Deferred until performance + false positives resolved)
- Structured logging with slog (for JSON-compatible aggregation)
- Generic PostgreSQL sink (remove Supabase-specific auth)
- Log rotation with lumberjack
- Type-safe DB queries with sqlc
- Defer-cleanup pattern for resource leaks
- Refactor module path to GitHub URL

---

## Code Status

### Architecture (Current)

**Resolver Architecture** ✅
- Docker/K8s: Async worker pool with semaphore (10 concurrent /proc reads)
- Namespace resolution: 1.5ms average (480× faster than sequential)
- Host runtime: New HostResolver added (classification logic pending)

**Event Pipeline** ✅
- Buffer: 65K event capacity (handles deployment spikes)
- Enrichment: Docker refresh triggered by lifecycle events (not periodic)
- Alert sinks: File, Redis, Supabase (all functional)

**Detection** ✅
- Rules: 14 MITRE techniques in `rules/default.yaml` (YAML-driven)
- Detector: `yaml_detector.go` (single source, policy.go legacy unused)
- Response: kill_process, blockIP actions implemented

### Files to Reference

- **SETUP.md** — Quick start + build commands
- **DEPLOYMENT.md** — Full deployment guide
- **rules/default.yaml** — All detection rules (self-documented)
- **MITRE-COVERAGE.md** — Supported techniques

---

## Deployment

### Current Setup
- **DigitalOcean K8s**: Primary (4-node cluster, health-ai services deployed)
- **Docker VM**: Local testing (for debugging eBPF changes)

### To Deploy
```bash
bash scripts/deploy-ebpf-k8s.sh
./validate-do-k8s.sh  # Should show 12/12 passing
```

### To Test eBPF Changes
```bash
make rebuild          # On Linux VM
make docker-push-ghcr
bash scripts/deploy-ebpf-k8s.sh
```

---

## Future Initiatives

### Phase 2: Behavioral & Anomaly Detection (Major Initiative)

**Goal:** Add intelligent threat detection using historical alert data from Supabase.

**Approach:**
- Analyze alert patterns over time (baseline normal behavior)
- Detect anomalies: unusual process chains, abnormal file access patterns, unexpected network connections
- Trigger alerts on behavioral deviations, not just rule matches
- Use historical data to reduce false positives

**Benefits:**
- Catch novel/unknown attacks not covered by YAML rules
- Distinguish real threats from legitimate but unusual activity
- Learn workload-specific normal behavior
- Reduce alert fatigue with context-aware scoring

**Status:** Pending — Design and implementation TBD. Supabase persistence infrastructure ready.

---

## Next Steps

**Session 4 (2026-07-05, After Rest):**
1. ⚠️ **ADD INFRASTRUCTURE WHITELISTS** to reduce false positive spam
   - Add: bash, snap-confine, snap-exec, docker-compose, xtables-nft-multi, getent
   - Reason: System producing 100+ CRITICAL T1611 alerts/sec from legitimate infrastructure
   - Impact: Makes debugging impossible; must quiet noise before Phase 2
2. **Rebuild** and verify alert spam is gone
3. **BEGIN PHASE 2: Transient Process Fallback** (now CRITICAL PATH)
   - Design fallback: buildCache → /proc scan → Docker API
   - Fix asyncResolvePID to handle dead processes properly
   - Test with real running containers

**After Phase 2 complete:**
1. Remove all temporary whitelists (replaced by proper resolver logic)
2. Verify performance baseline (resolve rate, latency)
3. Infrastructure improvements: structured logging, log rotation

---

---

## Current Crisis (Session 3 End, 2026-07-05)

**False Positive Explosion:** System producing 100+ CRITICAL alerts/sec from legitimate infrastructure processes.

**Root Cause:** Resolver early whitelist check doesn't match full paths:
- Whitelist: `bash`
- Process comm: `/snap/docker/3505/usr/sbin/bash` 
- Result: No match → state=unknown → CRITICAL alert

**Processes Affected:** bash, snap-confine, snap-exec, docker-compose, xtables-nft-multi, getent (all ppid=1371 = containerd daemon)

**Why This Matters:** Proves resolver is fundamentally broken for infrastructure identification. Phase 2 (proper namespace resolution) is now **BLOCKING** further progress.

**Action Plan (Session 4):**
1. Add temp whitelists (bash, snap tools, system utilities) to reduce noise
2. Proceed with Phase 2 implementation
3. Remove temp whitelists once resolver is fixed

**Next Session:** User rested, ready to implement Phase 2 (transient process fallback).

---

## Current Issue: SSH Session Initialization False Positives (Session 5, 2026-07-05)

**Problem:** Every new SSH console spawn triggers 50+ T1611_escape_to_host_ns CRITICAL alerts.

**Root Cause:** Resolver marks SSH login processes as `state=unknown` instead of `state=host` or resolving them properly.

**Alert Chain Example:**
```
sshd (PID 2117, infrastructure)
  → /bin/sh (PID 42054, state=unknown) → T1611 CRITICAL alert
    → /etc/update-motd.d/* scripts → T1611 CRITICAL alerts
      → /usr/bin/grep, /usr/bin/find, /usr/bin/awk → T1611 CRITICAL alerts
        → User bash session, reads /etc/passwd, /etc/group → T1082 MEDIUM alerts
```

**Why Whitelisting Doesn't Help:** The utilities (grep, find, awk, uname, etc.) are too numerous to whitelist individually. The real issue is that the parent chain trace is lost:
1. Process is dead by time detector runs (getParentComm fails)
2. Parent process's ppid not checked for infrastructure lineage
3. Process gets marked state=unknown instead of being identified as host/infrastructure

**Why It Matters:**
- Makes system unusable for security monitoring (100+ false alerts per SSH login)
- Proves resolver is broken for identifying SSH login processes
- Root cause: resolver should mark these as `state=host`, not `state=unknown`

**Solution Approaches:**
1. **Fix resolver** (proper fix): Identify SSH login namespace and mark as host/infrastructure
2. **Improve ancestor check** (quick fix): Check if any ancestor in process tree is in safeInfraPIDs
3. **Skip T1611 for /bin/sh children** (temporary): If parent is shell/script, likely initialization
4. **Disable T1611 until resolved** (nuclear option): Too many false positives block other detection

**Blockers:**
- Cannot easily fix without understanding how SSH processes should map to resolver namespaces
- Requires investigation into how sshd sessions differ from container namespaces

**Recommendation for Next Session:**
Start by understanding resolver behavior: Why do SSH login processes get state=unknown? Should they be state=host? Can we identify the SSH namespace at startup like we do for Docker?
