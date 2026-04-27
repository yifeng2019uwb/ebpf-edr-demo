# eBPF EDR — GKE Expansion Design

> Status: **Phase 5 validation complete (2026-04-27) — all 5 GKE functional tests pass. Next: Phase 6 Cloud Pub/Sub alert aggregation.**
> Discussion dates: 2026-04-22 → 2026-04-27

---

## 1. Goal

Extend the eBPF EDR agent beyond the existing Docker VM to monitor GKE workloads, using a pipeline architecture that supports additional environments in the future without core changes.

**Two design goals driving the architecture:**
1. **Multi-environment** — swap resolver (Docker / GKE / EKS / future) without touching detection logic
2. **New eBPF probes easy to add** — each BPF probe is independent; adding one requires no changes to the pipeline, detection, or alert layers

---

## 2. Current Situation

### Deployed environments

```
VM1 (GCP VM, Debian 12, kernel 6.1.0-44)
  ├── cloud-native-order-processor (Docker Compose, 8 containers)
  └── eBPF agent — host process (sudo ./edr-monitor)
        resolver: DockerResolver (docker ps + cgroup)
        probes:   execsnoop, opensnoop, lsm-connect

VM2 (GKE Standard, Ubuntu 24.04, kernel 6.8.0-1042-gke, us-west1-a)
  ├── cloud-native-order-processor (K8s, 7 workloads, HPA enabled)
  └── eBPF agent — NOT YET DEPLOYED (this plan)
        gateway: http://136.109.215.94:8080
        all integration tests passing ✓
```

**Multi-region plan (next after eBPF GKE deployment):** Refactor Pulumi to reusable pattern.
- Extract `region` and `zone` as `cfg.Require("region")` / `cfg.Require("zone")` (currently hardcoded in `config.go`)
- Create reusable `deployCluster(ctx, region, zone, sa)` function encapsulating cluster + node pool creation
- Each new region = new Pulumi stack only (`pulumi stack init us-east1`) — no code changes
- DaemonSet manifest injects `REGION=<region>` env var per cluster → `WorkloadIdentity.Region` in eBPF agent

### eBPF agent current state

- 3 probes: execsnoop (process), opensnoop (file), lsm-connect (network)
- 6 detection rules covering RCE, credential theft, network exfiltration, container escape
- Resolver: Docker-only, tightly coupled to `main.go` — no interface abstraction
- BPF programs: use `BPF_CORE_READ` correctly, but build toolchain not yet emitting BTF-annotated objects

### Key findings (2026-04-23)

| # | Question | Answer |
|---|----------|--------|
| R1 | GKE kernel version | **6.8.0-1042-gke** (Ubuntu 24.04.3 LTS) |
| R2 | BTF on GKE Ubuntu? | **Yes** — `/sys/kernel/btf/vmlinux` present by default |

GKE kernel 6.8 vs VM kernel 6.1 — compiled BPF objects will NOT load across versions without CO-RE.

### Decisions

- **CO-RE** is the build path — BTF available on both nodes, code already uses `BPF_CORE_READ`. Toolchain needs to emit BTF-annotated objects.
- **BPF programs unchanged** — all 3 probes capture `mnt_ns_id + pid`, sufficient for resolution on both Docker and K8s. No kernel-side changes needed.
- **AlertHandler is pluggable** — no decision made on Cloud Logging vs file vs stdout. Output target is an interface; each environment picks its own handler.

### Possible future environments

| Environment | New resolver? | New rules? | New eBPF? |
|-------------|--------------|------------|-----------|
| GKE multi-region (us-east1) | No — K8sResolver reused, tag `Region` | No | No |
| EKS (AWS) | EKSResolver — minor crictl variant | No | No |
| Bare metal / plain VM | HostResolver — pid → process name only | Possibly | No |
| healthcare-ai on GKE | No — same K8sResolver, different namespace | Possibly | No |
| New threat surface | No | Yes | Yes — new probe |

---

## 3. Pipeline Architecture

### WorkloadIdentity

The central data type. `Service` is the primary field used by detection rules.

```go
type WorkloadIdentity struct {
    Runtime   string  // "docker" | "k8s"
    Container string  // raw container name from runtime
    Pod       string  // pod name (k8s) or same as Container (docker)
    Namespace string  // k8s namespace; empty for Docker
    Service   string  // MOST IMPORTANT — used in all detection rules
                      // Docker: e.g. "inventory_service"
                      // K8s:    e.g. "inventory-service"
                      // Sentinels: "host", "unknown-ns", "pending-ns"
    Node      string  // host node name — needed for cross-node correlation (Section 5)
    Region    string  // GCP region — needed for cross-region correlation (Section 5)
}
```

Resolution path: `mnt_ns_id + pid → WorkloadIdentity`
(`pid` needed as fallback for `/proc/<pid>/cgroup` on cache miss)

`Node` and `Region` are populated at agent startup, not by the resolver:
- `Node` = `os.Hostname()`
- `Region` = `REGION` env var injected by DaemonSet manifest; fallback: GCP metadata endpoint `http://metadata.google.internal/computeMetadata/v1/instance/zone`

#### Known issue: `Service` field is fragile across runtimes

Docker gives `inventory_service`, K8s gives `inventory-service`, a future env may give `inventory`. Without normalization, detection rules must handle all variants — duplication grows with each new environment.

**Proposed approach (to decide at implementation):** resolver normalizes `_` → `-` as a minimum, giving `inventory-service` consistently across Docker and K8s. Whether to further strip to `inventory` (losing some context) is deferred. Even the minimal normalization significantly reduces rule duplication.

**Open question:** who owns normalization — the resolver, or a canonical name registry? TBD.

### EnrichedEvent — typed union, no interface{}

`interface{}` requires type assertions everywhere, hurts testing, and hides compiler errors. Typed optional fields — nil means absent.

```go
type EventType string

const (
    ProcessEventType EventType = "process"
    FileEventType    EventType = "file"
    NetEventType     EventType = "network"
)

type EnrichedEvent struct {
    Type      EventType
    Process   *ProcessEvent   // non-nil when Type == ProcessEventType
    File      *FileEvent      // non-nil when Type == FileEventType
    Net       *NetEvent       // non-nil when Type == NetEventType
    Workload  WorkloadIdentity
    Timestamp time.Time  // userspace time at event receipt — see known issue below
}
```

#### Known issue: kernel time ≠ userspace time

`Timestamp time.Time` is set when the event is read in userspace — not when it occurred in the kernel. Under load, events queue in the ring buffer before being read, introducing drift between actual event time and recorded time. For correlation across nodes, this drift matters.

**Future improvement:** carry the kernel timestamp (`ktime_get_ns()` from the BPF program) as a raw `uint64` nanoseconds field alongside `Timestamp`. Convert to wall clock using a boot-time offset calculated at agent startup. This gives accurate event ordering even under burst load.

**Not blocking current work** — note the field limitation when implementing cross-node correlation (Section 5).

### Core interfaces

```go
// Each BPF probe is an independent event source
type EventSource interface {
    Name()   string
    Start()  error
    Events() <-chan RawEvent
    Close()
}

// Any runtime implements this — Docker, K8s, EKS, future
type WorkloadResolver interface {
    Resolve(mntNsID uint32, pid uint32) WorkloadIdentity  // always non-blocking
    Start() error
}

// Detection rules — operate on enriched events only, runtime-agnostic
type Detector interface {
    Detect(event EnrichedEvent) []Alert
}

// Any output target — file, stdout, Cloud Logging, webhook
type AlertHandler interface {
    Send(alert Alert)
    // Future: Flush() error  — for batched handlers
    // Future: Close() error  — graceful shutdown with drain
}
```

### Buffered pipeline

eBPF generates bursts. Without buffering, slow enrichment or detection blocks the kernel ring buffer reader and events are dropped.

```
execsnoop ──┐
opensnoop ──┼──▶ rawCh(large) ──▶ Enricher ──▶ enrichedCh(med) ──▶ Detector ──▶ alertCh(small) ──▶ Handler
lsm-connect ┘
```

- `rawCh` — largest, absorbs kernel burst directly behind ring buffer
- `enrichedCh` — medium, absorbs enrichment jitter
- `alertCh` — small, alerts are rare

### Resolver design constraints

- `Resolve()` **must never block** — reads from in-memory cache only
- Cache miss → return best-effort result immediately, trigger async background refresh
- K8s resolver should use **containerd watch API** (not poll every 30s) — HPA pods appear faster than a 30s poll window

#### Known issue: crictl dependency

MVP uses `crictl ps --output json` to build the container map. This works but has drawbacks:
- Slower than direct API — spawns a subprocess each refresh
- External dependency — crictl must be on PATH inside the DaemonSet container
- Less real-time — even with watch API, crictl is a CLI wrapper around the containerd gRPC API

**Design path:** MVP uses crictl. Future `K8sResolver` should be rewritten against the **containerd client API directly** (Go package `github.com/containerd/containerd`) — real-time events, no subprocess overhead, no external binary dependency. The `WorkloadResolver` interface is unchanged; only the implementation swaps.

#### Known issue: AlertHandler is underused

`Send(alert)` is sufficient for MVP but not production-grade. Missing concerns:

- **Batching** — sending one alert at a time to Cloud Logging or a webhook is inefficient under burst; a batching handler groups alerts over a time window before flushing
- **Retry** — transient network failures silently drop alerts without retry logic
- **Backpressure** — if `alertCh` fills (handler is slow), the detector blocks; pipeline slows; ring buffer drops events

**MVP backpressure strategy (implement now, simple):**
```go
select {
case alertCh <- alert:
default:
    droppedAlerts.Add(1)  // atomic counter — visible in logs/metrics
}
```
Drop the alert if `alertCh` is full, increment a counter. Log the counter periodically. This prevents pipeline stalls without complex retry logic. Counter makes the drop visible rather than silent.

**Not implemented now (full):** batching, retry, `Flush() error`, `Close() error` — revisit when adding a persistent handler (Cloud Logging, Pub/Sub).

#### Known issue: `unknown-ns` → CRITICAL is dangerous in K8s

In K8s, pods start fast and the resolver cache always lags slightly. Short-lived pods (init containers, Jobs) may never be resolved at all. Immediately emitting CRITICAL on any `unknown-ns` event produces false positives under normal HPA scaling — this is the difference between a demo system and production-grade thinking.

**Proposed design (to implement in Phase 2):**

```
Event arrives with unseen mnt_ns_id:
  → Resolve() returns Service: "pending-ns"
  → enricher places event in pending buffer with timestamp + retry_count=0
  → resolver triggers immediate async refresh

Every retry interval (~3s), re-resolve all pending events:
  → if resolved: process normally, no alert
  → if still unknown AND retry_count < N (or elapsed < T seconds): retry_count++, keep pending
  → if still unknown AND retry_count >= N (or elapsed >= T): emit CRITICAL unknown_namespace_process

Cap: max 3 retries over max 10 seconds → then escalate.
```

Why cap matters:
- Resolver can fail temporarily (crictl subprocess error, containerd restart)
- Containerd watch events may lag or be missed
- Without a cap, events stay in pending forever → memory leak + silent missed alerts

**Decisions made at implementation (Phase 2):**
- Buffer size: unbounded per namespace ID, capped by retry count (3) and age (10s) per entry — acceptable for MVP; monitor `pending_ns` counter in metrics
- If buffer is full (`enrichedCh` full at resolution time): drop with `dropped` counter increment — consistent with rest of pipeline
- Severity during grace period: suppress entirely — emitting LOW breadcrumbs during normal pod startup adds noise without signal value

---

## 4. Implementation Plan

### Phase 1 — Pipeline refactor + WorkloadIdentity + DockerResolver ✅ DONE

**Goal:** introduce the pipeline and `WorkloadIdentity` without changing any existing behaviour. Docker VM monitoring must work identically after this phase.

New packages:
- `pkg/workload/identity.go` — `WorkloadIdentity` struct
- `pkg/workload/resolver.go` — `WorkloadResolver` interface + `NewResolver(runtime)` factory
- `pkg/workload/docker_resolver.go` — existing Docker logic (`docker ps` + cgroupv2 parser + cache) refactored into `WorkloadResolver`
- `pkg/pipeline/event.go` — core types and interfaces:

```go
// RawEvent is the unparsed bytes read from a BPF ring/perf buffer,
// tagged with which probe produced it.
type RawEvent struct {
    Source string  // "execsnoop" | "opensnoop" | "lsm-connect"
    Data   []byte  // raw sample from ring buffer — parsed by Enricher
}
```

Along with `EnrichedEvent`, `EventSource`, `Detector`, `AlertHandler`, `EventForwarder` interfaces.

Updated:
- `cmd/edr-monitor/main.go` — rewired as buffered pipeline; `--runtime=docker|k8s|auto` flag (default: `auto`)
- `pkg/detector/rules.go` — rule functions accept `WorkloadIdentity`, use `id.Service` (replaces container name string)

Remove:
- `pkg/container/container.go` — replaced by `pkg/workload/`

**Verify:** `make test` passes; existing Docker VM alert output unchanged. **Validated on Docker VM ✓**

---

### Phase 2 — K8sResolver ✅ DONE

**Goal:** resolve `mnt_ns_id + pid → WorkloadIdentity` on GKE using containerd/crictl.

New file: `pkg/workload/k8s_resolver.go`

Implemented:
1. **cgroup parser** — handles all 3 QoS classes: `kubepods/pod<uid>/`, `kubepods/burstable/pod<uid>/`, `kubepods/besteffort/pod<uid>/`. Container ID = last path segment.
2. **crictl lookup** — `crictl ps --output json` builds `container-id → WorkloadIdentity` map using K8s labels (`io.kubernetes.container.name`, `io.kubernetes.pod.name`, `io.kubernetes.pod.namespace`). Refresh every 5s (shorter than Docker's 30s to handle HPA pod churn).
3. **Watch API** — deferred; MVP uses crictl polling at 5s. Future: containerd client API for real-time events. `WorkloadResolver` interface unchanged — only implementation swaps.
4. **Self-filter** — reads `/proc/self/ns/mnt` at startup, maps agent's own `mnt_ns_id` → `Service: "host"` (silently skipped by detector).
5. **Pause filter** — `comm == "pause"` dropped in enricher before `enrichedCh`.
6. **Pending-ns buffer** — in `main.go`: miss → `"pending-ns"` → retry every 3s, max 3 retries / 10s → CRITICAL. Resolves false-positive CRITICAL during HPA scale-up.

**Verify:**
- Unit tests (cgroup parser, self-filter, pending retry path) — **pending, add before Phase 4**
- Integration tests on GKE node (VALIDATION-GKE.md 5.1, 5.2, 5.4) — **blocked on Phase 4 DaemonSet**

---

### Phase 3 — Dockerfile + CO-RE build ✅ DONE

Containerized the agent; BPF objects compile with BTF and load on GKE kernel 6.8.
Image: `us-west1-docker.pkg.dev/ebpfagent/ebpf-edr/ebpf-edr:latest`
Deploy: `make docker-push` cross-compiles on macOS (GOOS=linux GOARCH=amd64) and pushes to AR.

---

### Phase 4 — DaemonSet manifest + deploy ✅ DONE

DaemonSet runs in `kube-system` on all GKE nodes. Key manifest: `k8s/ebpf-edr-ds.yaml`.

Required mounts beyond proc/sys:
- `/sys/kernel/debug` (debugfs) + `/sys/kernel/tracing` (tracefs) — needed for tracepoints to attach
- `/run/containerd/containerd.sock` — crictl subprocess talks to containerd
- `${REGION}` substituted via `envsubst` per cluster in `deploy.sh daemonset`

**Bug fixed:** `containerIDFromK8sCgroup` — GKE Ubuntu nodes use cgroup v2 systemd format (`cri-containerd-<id>.scope`). Original code only matched cgroup v1 (`/kubepods/`). Fixed to match `kubepods` and strip prefix/suffix.

**Verified:** workload resolver populates `service=`, `pod=`, `namespace=` correctly on GKE.

---

### Phase 5 — Validation ✅ DONE (2026-04-27)

**Goal:** confirm detection rules fire correctly against GKE workloads, no false positives from normal traffic.

Automated with `./validate-gke.sh`. Run from `ebpf-edr-demo/` directory.

### Results (2026-04-27) — 5 passed, 0 failed

| Test | Scenario | Result |
|------|----------|--------|
| V2 | CRITICAL `shell_spawn_container` — `kubectl exec bash` into user-service | ✅ PASS |
| V3 | HIGH `sensitive_file_access` — `cat /etc/shadow` from container | ✅ PASS |
| V4 | HIGH `unauthorized_external_connect` — python3 connect to 8.8.8.8:80 | ✅ PASS |
| V5 | No HIGH from inventory-service external connects (allowlist working) | ✅ PASS |
| V6 | No CRITICAL from normal gateway HTTP traffic | ✅ PASS |

### Issues found and fixed during validation

| Issue | Fix |
|-------|-----|
| GKE ClusterIPs (`34.118.x.x`) flagged as unauthorized external connects | Auto-detect service CIDR from GCP metadata server at startup |
| kube-system / gmp-system constant alert noise | `systemNamespaces` map — suppress these namespaces entirely |
| `validate-gke.sh` timed out before alerts arrived | Use `--since-time=<RFC3339>` anchored before trigger instead of rolling `--since=Ns` window |
| Script exited after first PASS | `((PASS++))` returns 0 (falsy) with `set -e`; fixed with `|| true` |

---

### Out of scope for this plan

- Alert aggregation strategy (Cloud Logging, file, stdout) — `AlertHandler` is pluggable, decide per environment
- Detection rules for K8s-specific threats (privileged container escape, hostPath abuse) — future phase
- Multi-node cluster support — current cluster is single-node; K8sResolver scoped to local node
- VM1 Cloud Logging shipping — deferred

---

## 5. Future: System-Level Correlation

### The gap in node-local detection

The current pipeline is purely node-local — each agent processes events independently and has no visibility into what other nodes or pods are doing. This is sufficient for single-event threats (shell spawn, credential read) but cannot detect distributed or multi-step patterns.

```
Current (node-local):
  Node 1: agent → pipeline → local alerts
  Node 2: agent → pipeline → local alerts
          ↑ no connection between them

Needed:
  Node 1: agent → pipeline → local alerts
                           → event stream ──┐
  Node 2: agent → pipeline → local alerts   ├──▶ Correlation Engine → system alerts
                           → event stream ──┘
```

### What becomes detectable

| Pattern | Per-node signal | Cross-node signal |
|---------|----------------|-------------------|
| Distributed exfiltration | LOW — 1 external connect each | HIGH — 5 pods → same IP within 60s |
| Lateral movement | MEDIUM — shell spawn | CRITICAL — shell → net → shell chain across services |
| Recon sweep | LOW — 1 file read | HIGH — same sensitive file across 8 pods within 10s |
| Repeated low-signal | nothing (below threshold) | HIGH — pattern visible only in aggregate |

### Minimal architecture (not built in this plan)

Node agents emit enriched events to a **central stream** alongside local alerting. The correlation engine is a separate stateful process.

```go
// New interface — node agent forwards events to central stream (non-blocking)
type EventForwarder interface {
    Forward(event EnrichedEvent)
}
```

Node pipeline becomes:

```
rawCh → Enricher → enrichedCh ──▶ Detector → alertCh → LocalHandler
                             └──▶ EventForwarder → [central stream]
```

The branch is off `enrichedCh` — ALL enriched events are forwarded, not just those that triggered local alerts. The correlation engine needs the full event stream to detect patterns that don't cross the local alert threshold.

The correlation engine subscribes to the stream and applies time-windowed rules. It emits system-level alerts that no single node could generate.

### What `WorkloadIdentity` needs for correlation

`Node` and `Region` fields are already included in the canonical `WorkloadIdentity` struct (Section 3). No struct changes needed — they just need to be populated at agent startup:

- `Node` = `os.Hostname()` at startup
- `Region` = `REGION` env var injected in DaemonSet per cluster; fallback: GCP metadata endpoint `http://metadata.google.internal/computeMetadata/v1/instance/zone`. New region = new Pulumi stack with different `REGION` value — see multi-region plan in Section 2.

### Stream transport on GCP

Cloud Pub/Sub is natural — both GKE pods and the Docker VM publish to the same topic, correlation engine subscribes. No additional infrastructure needed if already on GCP.

---

## Q&A — Design Decisions

**Q: Why `interface{}` is removed from `EnrichedEvent`?**
`interface{}` requires type assertions everywhere in detection rules, removes compiler safety, and makes tests harder to write. The typed union pattern (`*ProcessEvent`, `*FileEvent`, `*NetEvent` as optional fields) is idiomatic Go — nil means absent, compiler enforces correctness.

**Q: Why must `Resolve()` be non-blocking?**
The enricher runs inline on the hot path between the kernel ring buffer and detection. Any blocking call in `Resolve()` backs up the pipeline and can cause `rawCh` to fill, which in turn causes the eBPF ring buffer to drop events. Cache reads are always O(1); I/O (crictl, /proc scan) happens only in background goroutines.

**Q: Why `Service` instead of `Container` as the primary field for rules?**
Container names include runtime-specific prefixes and instance suffixes (e.g. `order-processor-inventory_service-1` on Docker, `inventory-service-68ccd68889-vbpvq` on K8s) that change between deploys. `Service` is the stable logical name the resolver extracts — rules written against it work across runtimes and restarts without changes.

**Q: What is the `Service` normalization strategy?**
Decision is open — see Section 3 "Known issue: Service field is fragile." Minimum proposal: normalize `_` → `-` in the resolver, giving `inventory-service` consistently across Docker and K8s. Whether to further strip suffixes (e.g. `inventory-service` → `inventory`) is deferred. The open question is whether the resolver owns normalization or a separate canonical name registry does. Decision must be made at Phase 1 implementation before writing any detection rules against `Service`.

**Q: Why K8s watch API instead of polling for resolver cache?**
HPA scale-up creates pods in seconds. Polling `crictl ps` every 30s means a new pod's `mnt_ns_id` is unknown for up to 30s, firing CRITICAL `unknown-ns` false positives during normal autoscaling. Containerd's watch API delivers pod lifecycle events in real-time, closing this window. The 30s poll is sufficient for Docker (containers start/stop slowly) but not for K8s.

**Q: Why Cloud Logging is not decided?**
GKE automatically captures pod stdout — no config needed. For Docker VM, shipping `alert.log` requires installing the ops-agent. Since `AlertHandler` is now a pluggable interface, there is no need to decide on an aggregation strategy upfront. Each environment chooses its own handler. Cloud Logging remains an option but is not required.

**Q: Why `Pod` field duplicates `Container` on Docker?**
Docker has no pod concept. Rather than leaving `Pod` empty and creating an asymmetric struct, `Pod = Container` on Docker keeps the shape consistent — callers always have a non-empty `Pod` field for logging, regardless of runtime.

---

## References

- GKE node details: `gke-order-processor--auth-service-poo-c67e95af-pkgr`, kernel 6.8.0-1042-gke, Ubuntu 24.04.3 LTS
- GKE order-processor gateway: `http://136.109.215.94:8080`
- GKE manifests + deploy scripts: `cloud-native-order-processor/gcp_gke/`
- GKE deployment notes: `cloud-native-order-processor/gcp_gke/NOTES.md`
- eBPF agent repo: `~/workspace/ebpf-edr-demo`
- Existing validation suite: `ebpf-edr-demo/VALIDATION.md`
- Technical implementation notes (cgroup parsing, BPF patterns, rule design): `ebpf-edr-demo/NOTES.md`
