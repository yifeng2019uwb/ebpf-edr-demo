# Current Project Design & Structure

**Date:** 2026-06-27  
**Status:** Working (with graceful degradation when cloud services unavailable)

---

## 1. Project Structure

```
ebpf-edr-demo/
├── kernel/                    # eBPF C programs (sensors only)
│   ├── execsnoop.bpf.c       # Process execution events
│   ├── lsm-file.bpf.c        # File access events
│   ├── lsm-connect.bpf.c     # Network connection events
│   └── vmlinux.h             # Generated from running kernel
│
├── cmd/                       # Binary entry points
│   ├── edr-monitor/main.go   # Main agent (loads eBPF, detects threats, sends alerts)
│   └── alert-router/main.go  # Alert router (subscribes to Pub/Sub for monitoring)
│
├── pkg/                       # Public packages
│   ├── bpf/
│   │   ├── gen.go            # go:generate directives for bpf2go
│   │   ├── loader.go         # eBPF program loader/attacher
│   │   └── *_bpf*.go         # Generated BPF wrappers
│   │
│   ├── rules/
│   │   └── loader.go         # YAML rules loader + environment detection
│   │
│   ├── detector/
│   │   ├── yaml_detector.go  # Detection using YAML rules (NEW - current)
│   │   ├── rules.go          # Detection using hardcoded lists (OLD - legacy)
│   │   ├── policy.go         # Hardcoded policy lists (OLD - legacy)
│   │   ├── response.go       # Response actions (block IPs, etc.)
│   │   └── rule_names.go     # Rule constants
│   │
│   ├── workload/
│   │   ├── resolver.go       # Multi-environment resolver (Docker/K8s)
│   │   ├── docker_resolver.go
│   │   ├── k8s_resolver.go
│   │   └── common_resolver.go
│   │
│   └── pipeline/
│       └── event.go          # Event types (RawEvent, EnrichedEvent)
│
├── internal/                  # Private packages
│   ├── alert/
│   │   └── alert.go          # Alert handler (local file + optional Cloud Logging/Pub/Sub)
│   │
│   └── processor/
│       └── processor.go      # Event struct definitions (ProcessEvent, FileEvent, NetEvent)
│
├── rules/
│   └── default.yaml          # YAML rules (lists, macros, detections)
│
├── k8s/
│   └── ebpf-edr-ds.yaml      # Kubernetes DaemonSet configuration
│
├── infra/                     # Infrastructure as Code (Pulumi - GCP, now broken)
│   └── *.go                   # GCP resource definitions (unusable after credits expire)
│
└── Makefile                   # Build commands (generate, build, deploy)
```

---

## 2. Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         KERNEL LAYER                                │
│  execsnoop.bpf.c → [ProcessEvent]                                   │
│  lsm-file.bpf.c  → [FileEvent]                                      │
│  lsm-connect.bpf.c → [NetEvent]                                     │
│  (via Ring Buffer)                                                   │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ RawEvent (binary data)
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    USER SPACE - edr-monitor                         │
│                                                                       │
│  rawCh (kernel events)                                              │
│    ↓                                                                 │
│  Enricher                                                            │
│    │ • Parse binary event                                           │
│    │ • Resolve workload (Docker/K8s)                                │
│    │ • Handle pending namespace (retry up to 60s)                   │
│    ↓                                                                 │
│  enrichedCh (EnrichedEvent with workload info)                      │
│    ↓                                                                 │
│  YAMLDetector (or RuleDetector - legacy)                            │
│    │ • Load rules from YAML (or hardcoded policy)                   │
│    │ • Match against detection rules                                │
│    │ • Return Alert if rule triggered                               │
│    ↓                                                                 │
│  Responder (optional)                                               │
│    │ • Decide response action (block IP, kill process, etc.)        │
│    ↓                                                                 │
│  alertCh (Alert)                                                    │
│    ↓                                                                 │
│  Handler                                                            │
│    │ • Write to alerts/alert.log (always)                           │
│    │ • Write to Cloud Logging (if GCP available)                    │
│    │ • Publish to Pub/Sub (if GCP available)                        │
│    ↓                                                                 │
│  stdout (always visible in logs)                                    │
└─────────────────────────────────────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
   alerts/alert.log            Cloud Logging (GCP)
   (local file)                 + Pub/Sub topic
```

---

## 3. Component Details

### 3.1 eBPF Sensors (Kernel)

**Files:** `kernel/*.bpf.c`

**Purpose:** Capture kernel events without blocking syscalls

| Program | Hook | Event Type | Purpose |
|---------|------|-----------|---------|
| execsnoop | sys_enter_execve | ProcessEvent | Detect process execution |
| lsm-file | lsm/file_open | FileEvent | Detect file access |
| lsm-connect | lsm/socket_connect | NetEvent | Audit outbound connections |

**Key property:** BPF programs do NOT contain detection logic — they're sensors only. All policy decisions are in Go.

---

### 3.2 Detection System (Go)

**Two parallel implementations exist:**

#### Current (Active): YAML-Based
- **Files:** `pkg/rules/loader.go`, `pkg/detector/yaml_detector.go`, `rules/default.yaml`
- **How it works:**
  1. Load YAML rules at startup: `rules.LoadRulesForEnvironment("rules/default.yaml")`
  2. Detect environment (DigitalOcean, GCP, local) via metadata server queries
  3. Merge environment-specific whitelists (cloud agents, K8s infrastructure)
  4. At detection time, rules are looked up dynamically from YAML

- **Lists in YAML:** 20+ reusable collections (whitelisted_processes, shell_binaries, credential_dirs, etc.)
- **Macros in YAML:** Named conditions (currently defined but not yet used in conditions)
- **Detections in YAML:** 14 MITRE rules with condition-based matching

#### Legacy (Inactive): Hardcoded Go
- **Files:** `pkg/detector/rules.go`, `pkg/detector/policy.go`
- **How it works:** Detection logic hardcoded with lists compiled into binary
- **Status:** Still exists but not used (replaced by yaml_detector)

**Current choice:** `yaml_detector.go` is instantiated in main.go

---

### 3.3 Workload Resolution

**Files:** `pkg/workload/resolver.go`, `docker_resolver.go`, `k8s_resolver.go`

**Purpose:** Identify which container/pod an event came from

**Multi-environment support:**
- Docker resolver: Reads `/proc/*/cgroup` for docker paths, calls `docker ps`
- K8s resolver: Reads `/proc/*/cgroup` for kubepods paths, calls `crictl ps`
- Automatic fallback: If K8s fails, falls back to Docker

**Workload State:**
```go
type ResolveResult struct {
    State    WorkloadState  // resolved, host, pending, unknown
    Identity WorkloadIdentity
    Meta     WorkloadMeta
}
```

**States:**
- `resolved` — container/pod found in resolver cache (normal)
- `host` — host process (trust it, skip detection)
- `pending` — container starting, retry for 60s
- `unknown` — namespace unresolved, possible escape attempt

---

### 3.4 Alert Handler

**File:** `internal/alert/alert.go`

**Alert Path:**
1. Create alert (Alert struct with rule, severity, process info, workload info)
2. Format as `alertPayload` JSON struct
3. **Always:** Write to `alerts/alert.log` + print to stdout
4. **If GCP available:** Send to Cloud Logging + Pub/Sub
5. **If GCP not available:** Continue with just local file (graceful degradation)

**Current behavior:** Works without GCP (local file + stdout)

---

### 3.5 Alert Router

**File:** `cmd/alert-router/main.go`

**Purpose:** Consume alerts from Pub/Sub and display in monitoring dashboard

**Current status:** 
- Designed for GCP Pub/Sub
- Requires `GOOGLE_CLOUD_PROJECT` env var + service account credentials
- Unusable since GCP free tier expired
- No local alternative (cannot read from alerts/alert.log)

---

### 3.6 Rules System (YAML)

**File:** `rules/default.yaml`

**Structure:**
```yaml
rules:
  lists:
    - name: shell_binaries
      items: [bash, sh, zsh, ...]
    # 20+ more lists
  
  macros:
    - name: is_container
      condition: workload.state == resolved
    # 20+ more macros
  
  detections:
    T1059_unix_shell_execution:
      condition: spawned_shell and in_container
    # 14 total MITRE rules
  
  network:
    allowed_ports: [80, 443, ...]
    allowed_services: [api-gateway, ...]
  
  ignore_namespaces: [kube-system, gmp-system, ...]
```

**Environment-specific whitelists (merged at runtime):**
- GCP: getconf (cloud agent), GKE pause container
- DigitalOcean: droplet-agent (cloud agent), DO-specific infrastructure
- Local: no extra agents

---

## 4. Detection Rules

**14 MITRE techniques implemented (all single-event detectable):**

1. **T1059** — Unix shell execution (critical)
2. **T1105** — Ingress tool transfer (high)
3. **T1552.004** — Private keys accessed (critical)
4. **T1552.001** — Credentials in files (high)
5. **T1003.008** — OS credential dumping (high)
6. **T1082** — System information discovery (medium)
7. **T1036** — Masquerading (high)
8. **T1053.003** — Scheduled task/cron (high)
9. **T1070.003** — Clear command history (medium)
10. **T1611** (3 variants) — Container escape (critical/high)
11. **T1613** — Container discovery (high)
12. **T1041** — Exfiltration over C2 (high)

**Coverage:** Works on any VM + K8s (Docker, GKE, DOKS)

---

## 5. Build & Deployment

**Build system:**
```bash
make generate      # Compile eBPF .c → .o (requires Linux + clang)
make build        # Cross-compile to linux/amd64 binary
make rebuild      # Both steps (for eBPF changes)
```

**Deployment:**
- **Docker VM:** Run binary directly: `sudo ./ebpf-edr --runtime=docker`
- **K8s:** Deploy DaemonSet: `kubectl apply -f k8s/ebpf-edr-ds.yaml`

**Image:** `ghcr.io/yifeng2019uwb/ebpf-edr:latest` (public)

---

## 6. Current Working State

### What Works
- ✅ eBPF event capture (all 3 hooks)
- ✅ YAML rules loading + parsing
- ✅ Environment detection (DigitalOcean, GCP, local)
- ✅ Whitelist merging (cloud agents + K8s infrastructure)
- ✅ Multi-environment support (Docker + K8s)
- ✅ Alert generation + local logging
- ✅ Alert output to stdout + alerts/alert.log
- ✅ Tested on: Docker VM, GCP GKE, DigitalOcean K8s

### What's Broken
- ❌ Cloud Logging (GCP free tier expired)
- ❌ Pub/Sub (GCP free tier expired)
- ❌ Alert Router (depends on Pub/Sub)
- ❌ Infrastructure as Code (Pulumi GCP — no credentials)

### What's Partial
- ⚠️ Monitoring from remote machine (currently via stdout/file only, alert-router would be needed for real-time dashboard)

---

## 7. Environment-Specific Notes

### DigitalOcean K8s
- Metadata server: `169.254.169.254/metadata/v1/`
- DaemonSet needs: `hostNetwork: true`, `hostPID: true`
- Auto-detected, whitelists droplet-agent automatically

### GCP GKE
- Metadata server: `metadata.google.internal/computeMetadata/v1/`
- DaemonSet needs: same as above
- Auto-detected, whitelists GKE pause container automatically

### Local Docker
- No cloud metadata server
- Fallback to local detection
- Whitelists only base processes

---

## 8. Known Limitations

1. **False positives:** System processes (open-iscsi, fwupd) trigger T1611 escape detection
   - Currently logged as alerts
   - Could be filtered by behavioral baselines (Phase 2)

2. **No stateful detection:** All rules are single-event (no correlation across events)

3. **No behavioral learning:** Cannot distinguish between normal and anomalous patterns

4. **No centralized alerting:** Alerts stay local or in GCP (which is down)

5. **Alert router unavailable:** No way to consume alerts from Pub/Sub currently

---

## 9. Key Files Modified Recently

- `pkg/rules/loader.go` — Created (YAML rules loading)
- `pkg/detector/yaml_detector.go` — Created (new detector)
- `rules/default.yaml` — Created (rules moved from Go to YAML)
- `cmd/edr-monitor/main.go` — Modified (load YAML, use yaml_detector)
- `pkg/bpf/gen.go` — Modified (fixed vmlinux.h include path)
- `Makefile` — Modified (auto-generate vmlinux.h at build time)

---

## 10. Current Configuration

**Agent startup:** `cmd/edr-monitor/main.go`
```go
rulesDB, err := rules.LoadRulesForEnvironment("rules/default.yaml")
det := detector.NewYAMLDetector(rulesDB)
// Uses environment detection + whitelist merging automatically
```

**Environment detection order:**
1. Try DigitalOcean metadata (1.5s timeout)
2. Try GCP metadata (1.5s timeout)
3. Default to local

**Alert handler:** `internal/alert/alert.go`
```go
if project := os.Getenv("GOOGLE_CLOUD_PROJECT"); project != "" {
    // Try Cloud Logging + Pub/Sub (optional)
} else {
    log.Printf("Cloud Logging disabled — GOOGLE_CLOUD_PROJECT not set")
}
// Always writes to alerts/alert.log
```
