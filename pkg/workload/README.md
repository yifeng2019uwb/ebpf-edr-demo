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
// Create resolver
resolver := workload.NewResolver("k8s")  // or "docker"
resolver.Start()

// Resolve namespace to workload
result := resolver.Resolve(mntNsID, pid)

// Use in detection
if result.State == workload.StateResolved {
    svc := result.Identity.Service
    // Apply rules for this service
}
```

See: `cmd/edr-monitor/main.go` for full pipeline.

## Architecture

**Resolver Cache:**
- Maps namespace ID → workload identity
- Refreshes every 30 seconds
- K8s: reads from kubepods cgroup paths
- Docker: runs `docker ps`, checks cgroup

**Snap Docker Detection:**
- Special handling for snap-packaged docker
- `findDockerDaemonNamespace()` finds snap docker namespace
- Prevents false positives from docker infrastructure

---

**Last Updated:** 2026-06-30
