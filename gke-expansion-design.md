# eBPF EDR — GKE Expansion Design

> Status: **GKE order-processor deployment complete (2026-04-24) — eBPF GKE expansion ready to start.**
> Discussion date: 2026-04-22

---

## Goal

Extend the eBPF EDR agent to monitor a second workload environment: the
cloud-native-order-processor deployed on GKE, alongside the existing Docker VM.
This creates a hybrid monitoring setup that demonstrates both container runtime
strategies with the same eBPF kernel probes.

---

## Architecture Decision: Hybrid (VM1 Docker + VM2 GKE)

```
VM1 (existing GCP VM, Debian 12, kernel 6.1.0-44)
  ├── cloud-native-order-processor (Docker Compose, 8 containers)
  └── eBPF agent — host process (sudo ./edr-monitor)
        resolver: DockerResolver (docker ps + cgroup)
        output:   alert.log + Cloud Logging

VM2 (GKE Standard, Ubuntu node pool)
  ├── cloud-native-order-processor (K8s Deployments, multiple replicas)
  └── eBPF agent — privileged DaemonSet pod
        resolver: K8sResolver (crictl + cgroup)
        output:   stdout → Cloud Logging (automatic in GKE)
```

Both alert streams visible in Cloud Logging with workload tags.

---

## Why Order-Processor (not healthcare-ai)

- K8s manifests already exist in the project (`kubernetes/prod/`)
- Integration tests are stable and cover all 8 services
- Detection rules already tuned for order-processor services
- Integration tests can run from local laptop against GKE gateway (NodePort/LoadBalancer),
  simulating external traffic — validates `unauthorized_external_connect` rules realistically
- healthcare-ai is still in active development; adding GKE complexity on top is premature

---

## GKE Setup

- **Distribution**: GKE Standard (not Autopilot — Autopilot blocks privileged pods, which eBPF requires)
- **Node pool OS**: Ubuntu (not Container-Optimized OS — Ubuntu is more eBPF-friendly and has BTF)
- **Cluster size**: single node for demo (order-processor fits on one node)
- **Kernel check**: `kubectl describe node <node-name> | grep "Kernel Version"` after first deploy

---

## Key eBPF Architecture Change: ContainerResolver Interface

The kernel probes (execsnoop, opensnoop, lsm-connect) are **unchanged**.
Only the userspace container resolution layer changes.

### Current (Docker only)

```
mnt_ns_id → /proc/<pid>/cgroup → docker container ID → docker ps → container name
```

### Required (pluggable)

```
ContainerResolver interface {
    Resolve(mntNsID uint32, pid uint32) (ContainerInfo, error)
    Refresh()
}

DockerResolver  → docker ps + cgroup parsing       (VM1)
K8sResolver     → crictl ps + cgroup parsing       (VM2)
```

`ContainerInfo` adds pod-level fields for K8s:
```go
type ContainerInfo struct {
    Name      string  // container name (Docker) or container name within pod (K8s)
    PodName   string  // empty on Docker
    Namespace string  // empty on Docker
    Runtime   string  // "docker" | "k8s"
}
```

Agent selects resolver at startup via config flag (e.g., `--runtime=docker|k8s`).

### K8sResolver approach

- `crictl ps --output json` to build container ID → pod name map at startup
- `/proc/<pid>/cgroup` format on K8s: `kubepods/pod<uid>/<container-id>`
- Refresh on cache miss (same pattern as current DockerResolver rescan)
- Handles dynamic pod lifecycle: new replicas spin up, cache miss triggers rescan

---

## eBPF Agent on GKE: DaemonSet

Running as a privileged DaemonSet pod is how production tools (Falco, Tetragon) operate.

Required pod security context:
```yaml
securityContext:
  privileged: true
hostPID: true
hostNetwork: true
volumes:
  - name: proc
    hostPath:
      path: /proc
  - name: sys
    hostPath:
      path: /sys
```

The agent binary sees all host processes via `hostPID: true`, same as running directly on the VM.

---

## Alert Aggregation: Cloud Logging

- VM2 (GKE): pod stdout is captured by Cloud Logging automatically — no config needed
- VM1 (Docker): install `google-cloud-ops-agent` on the VM, ship `alert.log` to Cloud Logging
- Both streams queryable in Cloud Logging with a workload label filter
- No new aggregation service needed

---

## Scope Breakdown

### eBPF project changes

| Item | Description | Status |
|------|-------------|--------|
| Refactor `pkg/container` | Extract `ContainerResolver` interface | Not started |
| `DockerResolver` | Existing logic moved into interface | Not started |
| `pkg/k8s` / `K8sResolver` | crictl-based resolver for K8s pods | Not started |
| DaemonSet manifest | Privileged DaemonSet with host mounts | Not started |
| Dockerfile | Containerize eBPF agent binary | Not started |
| Dynamic rescan | Validate cache refresh against HPA scale events | Not started |
| Cloud Logging (VM1) | ops-agent config to ship alert.log | Not started |

### Order-processor (GKE deployment)

**Complete** — all services running, all integration tests passing (auth ✓, inventory ✓, order ✓, user ✓).
Gateway: `http://136.109.215.94:8080`. See `cloud-native-order-processor/gcp_gke/` for manifests and deploy scripts.

---

## CO-RE Gap (from design doc Section 8)

The current BPF programs are compiled against the Debian 12 / kernel 6.1 vmlinux headers.
GKE Ubuntu nodes may run a different kernel version.

**Two paths forward:**
1. **Recompile on the node**: Dockerfile builds BPF objects during container build using
   the GKE node's kernel headers. Works but requires matching kernel headers in the image.
2. **CO-RE properly**: Use BTF relocation. Requires `/sys/kernel/btf/vmlinux` on the GKE node
   (present on Ubuntu 22.04 by default) and building with CO-RE-aware toolchain flags.

The code already uses `BPF_CORE_READ` — it is written correctly for CO-RE.
The gap is the build/toolchain setup, not the BPF program logic.

---

## Research Findings (2026-04-23)

GKE node: `gke-order-processor--auth-service-poo-c67e95af-pkgr`

| # | Question | Answer |
|---|----------|--------|
| R1 | GKE Ubuntu kernel version | **6.8.0-1042-gke** (Ubuntu 24.04.3 LTS) |
| R2 | BTF present on GKE Ubuntu? | **Yes** — Ubuntu 24.04 ships BTF by default at `/sys/kernel/btf/vmlinux` |

**Key finding**: GKE kernel is **6.8**, existing VM is **6.1** — different major.minor versions.
Compiled BPF objects from the existing VM will NOT load on GKE without CO-RE.

---

## Decisions Made

- **CO-RE is the path forward** — BTF is available on GKE Ubuntu 24.04, code already uses `BPF_CORE_READ`. Build toolchain needs to emit BTF-annotated objects.
- Recompile-in-Dockerfile approach deferred — CO-RE is cleaner and portable.
- **HPA is deployed** (not manual kubectl scale) — CPU-based HPA for all 5 services; cluster autoscaler min 1 / max 3 nodes. Integration tests drive real CPU load to trigger scale events for eBPF to observe.
- VM1 ops-agent deferred to a later phase.
