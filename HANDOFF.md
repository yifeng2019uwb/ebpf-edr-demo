# Session Handoff

**Last Updated:** 2026-06-25

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

### Phase 1: MITRE Deep Review + Rules Refactoring (NEXT)

**Goal:** Move rules from hardcoded Go to YAML format while learning MITRE attack patterns.

**Why now:**
- Rules are currently buried in `pkg/detector/policy.go` (hard to review)
- YAML format enables per-service customization (Phase 3)
- Forces understanding of each MITRE technique while refactoring

**Plan:**
1. Create `pkg/rules/` package — YAML loader
2. Add `rules/default.yaml` — move all rules from policy.go
3. Refactor `pkg/detector/` to load rules from YAML
4. Test: ensure identical behavior (same alerts on same tests)
5. Document each rule in `/workspace/learning/ebpf-edr/MITRE-STUDY.md`

**Learning resources:**
- `/workspace/learning/ebpf-edr/LEARNING_PLAN.md` — study structure
- `/workspace/learning/ebpf-edr/MITRE-STUDY.md` — technique deep-dives (started with T1552)
- `/workspace/learning/ebpf-edr/DISCUSSION_SUMMARY.md` — context & reasoning

**YAML structure (example):**
```yaml
rules:
  whitelist:
    processes: [sshd, runc, dockerd, containerd, getconf]
  
  detections:
    T1552_private_keys:
      dir_prefixes: [/root/.ssh/, /home/.ssh/]
      suffixes: [.key, .pem, id_rsa, id_ed25519]
    
    T1036_masquerading:
      suspicious_paths: [/tmp/, /dev/shm/, /var/tmp/, /run/user/]
  
  network:
    allowed_ports: [6543]  # Supabase
    allowed_services: [inventory-service, inventory_service]
```

### Phase 2: Behavioral Detection (Later)

**Goal:** Add stateful detection (baselines, anomaly, correlation) in Central Control Service.

**Dependencies:** Phase 1 complete + understanding false positives per rule

### Phase 3: Configurable Rules Framework (Last)

**Goal:** Let clients customize rules via YAML at deployment.

**Dependencies:** Phase 1 (rules in YAML) + Phase 2 (behavioral baseline understanding)

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
