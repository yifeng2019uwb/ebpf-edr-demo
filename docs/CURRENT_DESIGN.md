# Architecture

**Scope:** the moving parts and how an event flows through them. **Architecture only** — details
(rules, policy, parent verification, deployment, performance) live in the linked per-part docs and
change more often than this overview.

---

## Project structure

```
ebpf-edr-demo/
├── kernel/                     # eBPF C sensors — telemetry only, no detection logic
│   ├── execsnoop.bpf.c         # process exec        → exec_event
│   ├── lsm-file.bpf.c          # file open (LSM)     → file_event
│   ├── lsm-connect.bpf.c       # socket connect (LSM)→ net_event
│   └── event.h                 # shared C structs (mirrored 1:1 in internal/processor)
├── cmd/
│   ├── edr-monitor/            # the agent: load eBPF → enrich → detect → respond → alert
│   └── alert-router/           # web UI that consumes the Redis alert stream
├── pkg/
│   ├── bpf/                    # generated eBPF loaders (bpf2go)
│   ├── pipeline/               # RawEvent / EnrichedEvent types, Source/Detector interfaces
│   ├── workload/               # resolver: mnt_ns → identity (Docker / K8s / host)
│   ├── detector/               # yaml_detector + response policy + ancestry cache
│   ├── rules/                  # YAML rules loader + environment detection
│   └── alertsink/              # file / redis / supabase sinks
├── internal/
│   ├── config/                 # env/config (ALERT_LOG_PATH, etc.)
│   ├── processor/              # ProcessEvent / FileEvent / NetEvent structs + parsing
│   └── alert/                  # Alert type + Level / Action
├── rules/                      # process/file/network.yaml (detections + response),
│                               #   common.yaml (shared lists, Layer 1/2 config, namespaces)
├── k8s/ebpf-edr-ds.yaml        # DaemonSet manifest
└── Makefile
```

---

## Data flow

```
kernel sensor  ──►  rawCh  ──►  enrich
 (execsnoop /                     │ parse binary event (internal/processor)
  lsm-file /                      │ resolve workload: mnt_ns → {runtime, service, state}
  lsm-connect)                    │ pending namespaces retry within a bounded window
                                  ▼
                             enrichedCh  ──►  YAMLDetector.Detect
                                                 │ Layer 1/2 filters + structured rule match
                                                 │ rules from rules/*.yaml (lists in common.yaml)
                                                 ▼
                                            Alert?  ──►  Responder (rule's response: — kill_process / block_ip)
                                                 │
                                                 ▼
                                              sinks
                             ┌──────────────────┼─────────────────────┐
                             ▼                  ▼                     ▼
                        FileSink            SupabaseSink           RedisSink
                     (+ stdout, always)   (persist all)        (drops LOW) ──► alert-router UI
```

Key properties:
- **Sensors are dumb.** `.bpf.c` programs only capture events; all policy is in Go.
- **Identity, then policy.** The resolver attaches `runtime` ∈ {docker, k8s, host, unknown} and
  `state` ∈ {resolved, pending, unknown} before any rule runs. Detection keys off that identity.
- **LOW telemetry stays off the live dashboard.** `RedisSink` drops LOW so unresolved-namespace
  telemetry (Phase 3) doesn't cause alert fatigue; file + Supabase still receive everything.

---

## Components → where the detail lives

| Component | What it does | Detail doc |
|-----------|--------------|-----------|
| eBPF sensors | capture exec / file-open / connect events | `kernel/*.bpf.c` |
| Workload resolver | `mnt_ns → identity` via one runtime-agnostic engine (`pkg/workload/resolver_engine.go`), host fast-path, ancestry cache for parent verification | [DESIGN-PROCESS-ANCESTRY-CACHE.md](DESIGN-PROCESS-ANCESTRY-CACHE.md) |
| Detection rules & policy | layers, per-rule attack→detection, exceptions, gating | [DETECTION-RULES-AND-POLICY.md](DETECTION-RULES-AND-POLICY.md), [MITRE-COVERAGE.md](MITRE-COVERAGE.md) |
| Response | `kill_process` / `block_ip` via `response:` on YAML detections | `rules/*.yaml`, `pkg/detector/response.go` |
| Alert sinks | file (+stdout), Supabase (persist), Redis (live, drops LOW) | `pkg/alertsink/` |
| Performance / throughput | instrumentation, targets, pending load test | [PERFORMANCE.md](PERFORMANCE.md) |
| Deployment | DaemonSet, image, environments | [DEPLOYMENT.md](DEPLOYMENT.md) |

---

## Environment awareness

The agent auto-detects its environment at startup (cloud metadata probes) and merges
environment-specific infrastructure whitelists from the rules. It runs the same everywhere —
Docker VM and Kubernetes (validated on DO managed K8s) — with no per-environment code paths in the
detection logic. Environment only affects which infrastructure processes are trusted.
