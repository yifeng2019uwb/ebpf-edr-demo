# pkg/workload — Container & Pod Resolver

Maps kernel namespace IDs to container/pod identities (which service is this workload?).

## What It Does

Given a mount namespace ID from eBPF event, determine:
- Is it a host process? Container? Pod?
- Which service/pod is it running in?
- Which Kubernetes namespace?
- Full workload metadata (pod name, node, region, cluster)

## Files

- **types.go** — Shared types
  - `WorkloadResolver` interface
  - `ResolveResult` with identity + metadata
  - `State` enum: StateHost, StateResolved, StatePending, StateUnknown

- **k8s_resolver.go** — K8s pod resolution
  - Uses `crictl` to map namespace ID → pod
  - Reads pod metadata from Kubernetes API
  
- **docker_resolver.go** — Docker container resolution
  - Uses `docker ps` to find containers
  - Detects snap docker vs system docker
  - Caches container ID → service name mapping

## Resolver States

| State | Meaning | Whitelisted |
|-------|---------|------------|
| `StateHost` | Host process | ✅ Ignored (trusted) |
| `StateResolved` | Known pod/container | ❌ Monitored |
| `StatePending` | Container starting (grace period) | ❌ Buffered, retried |
| `StateUnknown` | Unresolved after timeout | ❌ May be escape attempt |

## Usage

```go
// Create resolver (K8s or Docker)
resolver := workload.NewResolver(workload.RuntimeK8s)
resolver.Start()

// Resolve namespace ID to workload
result := resolver.Resolve(mntNsID, pid)

// Check resolution state
if result.State == workload.StateResolved {
    svc := result.Identity.Service  // Use service for detection rules
}
```

See: `cmd/edr-monitor/main.go` for full pipeline.

## How It Works

**K8s Resolver (5s refresh):**
- Uses `crictl` to inspect containers directly from runtime
- Maps cgroup paths → pod/container metadata
- Handles cgroup v1 and v2 formats

**Docker Resolver (10s refresh):**
- Runs `docker ps` for running containers
- Reads cgroup to find container IDs
- Detects snap docker vs system docker

**Namespace Resolution:**
- Parses `/proc/[pid]/ns/mnt` symlink to extract namespace ID
- Maps namespace → service identity for detection

---

**Last Updated:** 2026-07-01
