# Session Handoff

**Last Updated:** 2026-06-29 (Infrastructure Refactoring + K8s Multi-Cloud Deployment)**  
**Previous:** 2026-06-27 (Phase 1 Complete — YAML rules refactoring ✅)

---

## Session 2026-06-29: K8s Infrastructure Refactoring

### Completed This Session ✅

1. **DigitalOcean K8s Cluster Setup**
   - Deployed K8s cluster: `k8s-1-36-0-do-2-sfo3-1782763501543` (SFO3, 1.36.0)
   - Cost: $12/month per node + free control plane
   - kubectl configured and ready

2. **Health-AI Services → DO K8s**
   - All 4 services deployed and running (auth, provider, ai, gateway)
   - LoadBalancer assigned: `164.90.244.53:8080`
   - Supabase integration working
   - API endpoints responding correctly

3. **K8s Configuration Management (Secrets + ConfigMaps)**
   - Created Secret pattern for sensitive data (database-key, pubsub-key)
   - Created ConfigMap pattern for URLs (database-url, pubsub-addr)
   - DaemonSet references these via valueFrom
   - Works for any K8s cluster, any database/pub-sub

4. **Generic eBPF Deployment Template**
   - Created `scripts/deploy-ebpf-k8s.sh` — single canonical script for all services
   - Downloads DaemonSet from GitHub, substitutes cluster info, applies to K8s
   - No local repo dependency
   - Used by health-ai, order-processor, any service

5. **Deployment Documentation**
   - Created `DEPLOYMENT.md` (root) — comprehensive guide
   - Option 1: Add to Makefile (recommended, cleanest)
   - Option 2: Standalone script
   - Option 3: Integrate into deploy script
   - Option 4: Manual kubectl
   - Includes local Docker/VM deployment approach

6. **Project Reorganization**
   - Moved `k8s/deploy-template.sh` → `scripts/deploy-ebpf-k8s.sh`
   - Deleted redundant `k8s/deploy.sh`
   - Moved `DEPLOYMENT.md` from `k8s/` to root
   - `k8s/` now contains only: `ebpf-edr-ds.yaml` (DaemonSet)

7. **Health-AI Makefile Updates**
   - Added `make deploy-ebpf-k8s` — K8s deployment
   - Added `make deploy-ebpf-docker` — local VM deployment
   - Both read from `docker/.env` for configuration

8. **eBPF Agent Validation (Local Docker VM)**
   - Built and tested eBPF agent locally on DigitalOcean VM
   - Detected alerts: T1611_escape_to_host_ns (namespace detection)
   - Confirmed: eBPF programs loading, rules firing, alerts generating
   - Issue: False positives on legitimate system tools (/usr/bin/ps, /usr/sbin/apparmor_parser)
   - Conclusion: Detection mechanism working, rules need refinement

### Session 2026-06-30: Local Testing + Alert-Router Update

**Completed:**
1. ✅ **Unit Tests Fixed** — Rewrote for Sink-based Handler, passing on VM + macOS
2. ✅ **Alert-Router Updated** — Replaced GCP Pub/Sub with Redis, reads from infra/.env
3. ✅ **Supabase Sink Fixed** — Parses HTTPS URL to build correct PostgreSQL connection string
4. ✅ **Config Loader Fixed** — Now loads `infra/.env` directly (no need to copy to root)
5. ✅ **Redis Sink Fixed** — Uses `redis.ParseURL()` to handle full redis:// URLs
6. ✅ **eBPF Agent Local Testing** — Generates alerts to local file (alerts/alert.log)
7. ✅ **Redis Pub/Sub Working** — Alerts flowing real-time through Redis channel `edr-alerts`

**Verified Working End-to-End:**
- eBPF programs loading and detecting events ✅
- Alert generation working (both local file + Redis) ✅
- Redis sink publishing alerts ✅
- Real-time alert delivery via Redis ✅

**Code Changes (Ready to Commit):**
- `internal/config/config.go` — Load infra/.env directly
- `pkg/alertsink/redis_sink.go` — Use ParseURL for Redis URLs
- `pkg/alertsink/supabase_sink.go` — URL parsing (already committed)
- `cmd/alert-router/main.go` — Redis integration (already committed)
- `internal/alert/alert_test.go` — Sink-based tests (already committed)
- `Makefile` — Updated for deployments (already committed)

### Session 2026-06-30 (Continued): Supabase Connection Fixed ✅

**Issue Resolved:**
- **Problem:** Supabase direct endpoint (`db.*.supabase.co`) IPv6-only on free tier, DO VM lacks IPv6 connectivity
- **Solution:** Switched to Supavisor pooler endpoint (`aws-1-us-east-1.pooler.supabase.com`) which provides IPv4

**Key Discoveries:**
1. Supavisor endpoint format: `aws-{POOL_NUMBER}-{REGION}.pooler.supabase.com` (pool number "1" for this project)
2. Username format: `postgres.{PROJECT_ID}` (not just `postgres`)
3. DATABASE_REGION env var must include pool number: `1-us-east-1`
4. PASSWORD must be actual PostgreSQL password, not API key

**Fixed Code:**
- `pkg/alertsink/supabase_sink.go` — Supavisor pooler support with fallback paths
- `internal/config/config.go` — Simplified path resolution (repo root or bin/ directory)
- `.env` configuration — Added `DATABASE_REGION=1-us-east-1`

**Verified:**
- ✅ File sink working
- ✅ Redis sink working  
- ✅ Supabase sink working (via Supavisor IPv4 endpoint)
- ✅ All three sinks connected and receiving alerts

**Status:** Supabase connection issue RESOLVED ✅

**Next Priority:** Fix T1611 false positives (blocking detection testing)
- Capture alert log with T1611 events
- Identify which processes are false positives
- Add to whitelist or refine detection logic

### Architecture Now

```
ebpf-edr-demo/
├── DEPLOYMENT.md              ← All deployment docs (K8s + local)
├── scripts/
│   └── deploy-ebpf-k8s.sh     ← Canonical K8s script for all services
├── k8s/
│   └── ebpf-edr-ds.yaml       ← K8s DaemonSet (referenced by all)
├── infra/
│   ├── .env.example           ← Template
│   ├── .env                   ← User config (gitignored)
│   └── alerts_schema.sql      ← Supabase schema
├── pkg/alertsink/
│   ├── file_sink.go           ← Local file sink
│   ├── redis_sink.go          ← Redis pub/sub sink
│   └── supabase_sink.go       ← PostgreSQL sink (needs testing)
└── internal/config/
    └── config.go              ← Service-agnostic config loader

Services can use this pattern:
health-ai/Makefile:
  make deploy-ebpf-k8s   # Calls scripts/deploy-ebpf-k8s.sh from GitHub
  make deploy-ebpf-docker # Runs docker image locally
```

### For Next Session

1. **Unit Tests** ✅ DONE
   - Tests rewritten for Sink-based Handler
   - Passing on both VM and macOS

2. **Test Supabase Sink** (NEXT)
   - Add `go get github.com/lib/pq`
   - Build: `make build`
   - Deploy to K8s: `make deploy-ebpf-k8s`
   - Verify alerts reach Supabase database

3. **Refine T1611 Rule** (optional)
   - Adjust `T1611_escape_to_host_ns` detection
   - Add conditions for legitimate system processes
   - Re-test on Docker VM

4. **Deploy eBPF DaemonSet to DO K8s**
   - Once unit tests pass: `bash scripts/deploy-ebpf-k8s.sh`
   - Verify: agents running on all K8s nodes
   - Check: alerts flowing to Supabase + Redis

---

## Current State (as of 2026-06-27)

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
- **IPv6 blocking not supported** (Phase 2): blockIP only supports IPv4 (`.To4()` in response.go:79). IPv6 addresses are captured in alerts but cannot be blocked. Requires kernel-side lpmKey restructuring to support variable-length keys or dual IPv4/IPv6 key types.

---

## Historical Reference

Full session logs and detailed technical decisions archived in `docs/archive/HANDOFF_0625.md`
