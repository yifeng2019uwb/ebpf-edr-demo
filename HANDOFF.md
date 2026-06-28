# Session Handoff

**Last Updated:** 2026-06-27 (Phase 1 Complete — tested on DigitalOcean K8s ✅)

---

## Current State

**Coverage:** 15 of ~15 single-event-detectable MITRE techniques implemented and validated
- Docker VM: 13/13 tests passing ✅
- GKE: 11/11 tests passing ✅
- See [MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md) for technique list

**Infrastructure:**
- eBPF agent: `ghcr.io/yifeng2019uwb/ebpf-edr:latest` (public)
- Health-AI services: ghcr.io/yifeng2019uwb (public images)
- Database: Supabase (external, always on)
- GCP credits expire 2026-06-17 (do not rely on GCP infrastructure after this date)

**Architecture:** 2-service design
1. **eBPF Agent** (deployed everywhere) — detects & enforces
2. **Central Control Service** (planned) — dashboard + behavioral analysis

---

## Upcoming Tasks

### Phase 1: MITRE Deep Review + Rules Refactoring (COMPLETE ✅)

**Goal:** Move rules from hardcoded Go to YAML format while learning MITRE attack patterns.

**Completed:**
1. ✅ Created `pkg/rules/loader.go` — Falco-style YAML loader with environment detection
   - ListDef, MacroDef, Detection, RulesDB structures
   - LoadRules(), CompileRules(), GetList(), GetMacro() functions
   - Consolidated DetectEnvironment() with context timeout (1.5s)
   - MergeWhitelists() for cloud agents + K8s infrastructure
   - LoadRulesForEnvironment() integration function

2. ✅ Created `rules/default.yaml` — all rules from policy.go (100% coverage)
   - 20+ lists (whitelists, credentials, MITRE indicators)
   - 20+ macros (conditions with clear state documentation)
   - 14 detections (MITRE techniques)
   - Network policy (allowed_ports, allowed_services)
   - Ignore namespaces (kube-system, gmp-system, gke-managed-cim)

3. ✅ Created `pkg/detector/yaml_detector.go` — Detection using loaded rules
   - YAMLDetector class using RulesDB instead of hardcoded policy.go
   - All detection methods (process, file, network) ported from rules.go
   - Reuses detection logic, only data source changed to YAML

4. ✅ Integrated loader into pipeline
   - Updated `cmd/edr-monitor/main.go` to load YAML rules
   - Calls LoadRulesForEnvironment() at startup
   - Creates YAMLDetector with loaded rules
   - Auto-detects environment, merges whitelists

5. ✅ Environment detection refactored
   - Consolidated into single DetectEnvironment() function
   - Context timeout prevents hanging (1.5s)
   - Tries DigitalOcean, GCP, defaults to local
   - Shared tryMetadata() helper (no code duplication)

6. ✅ K8s DaemonSet verified
   - k8s/ebpf-edr-ds.yaml already has hostNetwork: true, hostPID: true
   - All necessary volume mounts for eBPF and metadata access

**Ready for Testing:**
- Build: `make build`
- Deploy: k8s/ebpf-edr-ds.yaml (unchanged)
- Test on DigitalOcean K8s: environment detection, whitelist merging, MITRE rules

**Learning resources:**
- `/workspace/learning/ebpf-edr/LEARNING_PLAN.md` — study structure
- `/workspace/learning/ebpf-edr/MITRE-STUDY.md` — technique deep-dives (started with T1552)
- `/workspace/learning/ebpf-edr/DISCUSSION_SUMMARY.md` — context & reasoning

---

## Phase 1 Testing Results ✅

**Completed:** 2026-06-27 (DigitalOcean K8s)

**Verification:**
1. ✅ Build: `make build` — success
2. ✅ Environment detection: "rules: detected DigitalOcean environment" ✓
3. ✅ Whitelist merging: "rules: merged 2 cloud agents" ✓
4. ✅ Detection working: T1059_unix_shell_execution triggered correctly
5. ✅ YAML rules loaded: no parsing errors
6. ✅ yaml_detector integration: working identically to old rules.go

**Test Observations:**
- Shell spawn in container (T1059) — **correctly detected** ✓
- System process in unknown namespace (open-iscsi T1611) — **detected but false positive**
  - Question: Should open-iscsi be whitelisted? See Phase 2 notes.

**Next: Phase 2 (Central Hub + Real-Time Alerts)**

---

## Phase 2: Infrastructure Design

**Architecture:**
```
Central Hub (one location — any VM)
  ├─ Redis (Pub/Sub for real-time alerts)
  ├─ Monitoring Service (subscribes to Redis)
  └─ Supabase connection (persistent storage)

Agents (deployed everywhere)
  ├─ DigitalOcean K8s
  ├─ GCP VM
  ├─ AWS EC2
  └─ Azure VM
  
  All publish alerts to Central Hub (Redis + Supabase)
```

**Implementation order:**
1. **Build Central Hub first**
   - Deploy Redis (local VM or cloud)
   - Create Monitoring Service (subscribes to Redis, writes to Supabase)
   - Connect to Supabase
   
2. **Then deploy Agents**
   - Agents publish alerts to Central Hub
   - Two parallel writes: Redis (real-time) + Supabase (persistent)

**Infrastructure:** 
- Central Hub location: flexible (DO VM, local VM, anywhere)
- Network: agents reach Hub via DNS + VPC peering
- Cost: minimal (Redis small, Supabase free tier)

**Agent Resilience (Personal Project):**
- Try: Write to Redis + Supabase
- Fallback: Write to local alert.txt (if services unavailable)
- Agent continues running (doesn't crash)
- This allows testing without full infrastructure setup

---

### Phase 2: Behavioral Detection (Later)

**Goal:** Add stateful detection (baselines, anomaly, correlation) in Central Control Service.

**Dependencies:** Phase 1 complete + understanding false positives per rule

### Phase 3: Configurable Rules Framework (Last)

**Goal:** Let clients customize rules via YAML at deployment.

**Dependencies:** Phase 1 (rules in YAML) + Phase 2 (behavioral baseline understanding)

---

## Design Clarifications (This Session)

**Workload State Values:**
- `resolved` — container/pod found in resolver cache (normal path for Docker + K8s)
- `host` — host process (all detection rules skipped)
- `pending` — container/pod starting up (grace period, retried up to 60s)
- `unknown` — unresolved namespace (possible escape attempt)

**Environment-Specific Whitelists:**
- Base whitelists: `whitelisted_processes`, `whitelisted_unknown_ns_procs`
- Cloud agents merged at runtime: GCP getconf, DigitalOcean droplet-agent
- K8s infrastructure merged at runtime: GKE pause container, DigitalOcean specific processes
- Single YAML file works everywhere; merging happens based on detected environment

**Exception vs Condition Logic:**
- Use exceptions (`exception_macros: [is_whitelisted_proc]`) to suppress alerts
- Use conditions for positive checks (e.g., `workload.state == unknown`)
- Avoid negative logic in conditions; use exceptions instead

**No TODO/FIXME in Personal Projects:**
- Design can be extensible (support multiple clouds, AWS/Azure commented as ready)
- But don't promise future work with TODO comments
- Be honest about scope: "design ready, not yet validated" instead of "TODO"

---

## Backlog / Future Considerations

### Package Structure Cleanup (Future)

**Issue:** Some packages could be better organized
- `pkg/bpf/` contains eBPF loader + structs (FileEvent, ExecEvent, ConnEvent)
- These are tightly coupled to `pkg/detector` (not truly "public")
- Currently in `pkg/` but could move to `internal/bpf/`

**Decision deferred:** Keep `pkg/bpf/` as-is for Phase 1. Evaluate after rules refactoring is complete.

**If restructured later:**
```
internal/bpf/       ← eBPF loader + event structs (private to project)
  └─ loader.go
  └─ *_bpfel.go (generated)

pkg/detector/       ← Detection logic using internal BPF events
```

---

## Key Reference

### Deployment
- **Go-only changes:** `make build` → `make docker-push-ghcr-prebuilt` → redeploy
- **BPF C changes:** `make rebuild` on GCP VM → push → redeploy
- **Avoid C changes** — diagnose with Go first

### GKE (on-demand)
- Cluster: `health-ai-cluster-us-west1`, namespace: `health-ai`, project: `ebpfagent`
- Bring up: `cd kubernetes/pulumi && pulumi up`
- Deploy: `cd kubernetes && ./deploy.sh all`
- Destroy: `./deploy.sh destroy`

### Known Limitations
- T1105: skips in Docker if nc/wget not installed (verified working on GKE)
- block_ip disabled (BPF verifier limits)
- T1611 escape variants not easily testable locally
- `kernel/opensnoop.bpf.c` is dead code (safe to delete)

---

## Historical Reference

Full session logs and detailed technical decisions archived in `docs/archive/HANDOFF_0625.md`
