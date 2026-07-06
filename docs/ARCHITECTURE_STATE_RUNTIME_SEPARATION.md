# Architecture Issue: State vs Runtime Separation

**Date:** 2026-07-03  
**Status:** 🔄 Pending Review & Implementation  
**Severity:** Medium (Design clarity, affects resolver logic)

---

## Problem Statement

Currently, `ResolveState` mixes two orthogonal concepts:

### Current (Conflated) Model
```go
type ResolveState string

const (
    StateResolved  ResolveState = "resolved"  // Container found in cache
    StateHost      ResolveState = "host"      // ← CONFUSION: Is this a state or runtime?
    StatePending   ResolveState = "pending"   // Container not yet in cache
    StateUnknown   ResolveState = "unknown"   // Unresolved after retries
)
```

**The Problem:**
- `StateHost` conflates "we found it" (state) with "it's on the host OS" (runtime)
- Forces bareResult() to return confusing values:
  ```go
  return ResolveResult{
      State: StateHost,      // Implies special resolution status
      Identity: WorkloadIdentity{
          Runtime: RuntimeDocker,  // But actually running on host!
          Service: "host",
      },
  }
  ```
- When checking alerts, `state=host` doesn't clearly mean "this is on the host OS" — it's ambiguous

---

## Root Cause

Two independent dimensions being conflated into one enum:

| Dimension | Values | Meaning |
|---|---|---|
| **State (Resolution Status)** | Resolved, Pending, Unknown | Did we figure out what this process is? |
| **Runtime (Execution Environment)** | Docker, K8s, Host, Unknown | What technology is it running in? |

Current design only has one enum (`ResolveState`), so it tries to encode both.

---

## Proposed Solution

**Separate into two orthogonal enums:**

### 1. ResolveState — Resolution Status Only
```go
type ResolveState string

const (
    StateResolved ResolveState = "resolved"  // Found in resolver cache
    StatePending  ResolveState = "pending"   // Still resolving (retry queue)
    StateUnknown  ResolveState = "unknown"   // Unresolved after grace period
)

// StateHost is REMOVED — encode this in Runtime instead
```

### 2. Runtime — Execution Environment (Already Exists)
```go
type Runtime string

const (
    RuntimeHost    Runtime = "host"      // NEW: Process on host OS
    RuntimeDocker  Runtime = "docker"    // Existing: Docker container
    RuntimeK8s     Runtime = "k8s"       // Existing: Kubernetes pod
    RuntimeUnknown Runtime = "unknown"   // Existing: Unknown execution env
)
```

---

## Impact on Code

### Before (Confusing)
```go
// Host process
return ResolveResult{
    State: StateHost,
    Identity: WorkloadIdentity{
        Runtime: RuntimeDocker,  // ← Wrong! It's not in Docker
        Service: "host",
    },
}

// Container in Docker
return ResolveResult{
    State: StateResolved,
    Identity: WorkloadIdentity{
        Runtime: RuntimeDocker,
        Service: "redis",
    },
}

// Unresolved
return ResolveResult{
    State: StateUnknown,
    Identity: WorkloadIdentity{
        Runtime: RuntimeUnknown,
        Service: "",
    },
}
```

### After (Clear Separation)
```go
// Host process
return ResolveResult{
    State: StateResolved,  // We resolved it
    Identity: WorkloadIdentity{
        Runtime: RuntimeHost,  // It's on the host OS
        Service: "host",
    },
}

// Container in Docker
return ResolveResult{
    State: StateResolved,  // We resolved it
    Identity: WorkloadIdentity{
        Runtime: RuntimeDocker,  // It's in Docker
        Service: "redis",
    },
}

// Unresolved
return ResolveResult{
    State: StateUnknown,   // We couldn't resolve it
    Identity: WorkloadIdentity{
        Runtime: RuntimeUnknown,  // Unknown what it's running in
        Service: "",
    },
}
```

---

## Implementation Tasks

### Phase 1: Type Changes
- [ ] Remove `StateHost` from ResolveState enum
- [ ] Add `RuntimeHost` to Runtime enum
- [ ] Update ResolveResult.State type (only 3 states now)

### Phase 2: Resolver Updates
- [ ] Docker resolver: Cache `hostMntNsID = getMntNsID(1)` at startup
- [ ] Docker resolver: Check `if mntNsID == hostMntNsID` → return `StateResolved + RuntimeHost`
- [ ] K8s resolver: Same pattern (cache host namespace, detect at runtime)
- [ ] Remove `bareResult(state)` — replace with `hostResult()` and `containerResult()`

### Phase 3: Alert Logic Updates
- [ ] Update detection rules that check `state == "host"`
- [ ] Rules should check `runtime == "host"` instead
- [ ] Rules that check `state == "unknown"` remain unchanged (still means "unresolved")

### Phase 4: Pipeline & Output Updates
- [ ] Update EnrichedEvent serialization (alerts, Redis, Supabase)
- [ ] Verify alert output shows correct runtime + state combination
- [ ] Update HANDOFF.md examples

---

## Examples: Before vs After

### Scenario 1: Host daemon (systemd-resolved)
```
Before: state=host, runtime=docker
After:  state=resolved, runtime=host  ← Clear: resolved to host OS
```

### Scenario 2: Container process (redis in Docker)
```
Before: state=resolved, runtime=docker
After:  state=resolved, runtime=docker  ← No change (already clear)
```

### Scenario 3: Unresolved (new container starting)
```
Before: state=pending, runtime=unknown
After:  state=pending, runtime=unknown  ← No change
```

### Scenario 4: Container escape (process in unknown namespace)
```
Before: state=unknown, runtime=unknown
After:  state=unknown, runtime=unknown  ← No change (correct interpretation)
```

---

## Alert Rule Impact

### Current Rules (Need Update)
```yaml
# Example: Skip host processes
if alert.state == "host":
    skip_alert()

# Example: Alert on unresolved
if alert.state == "unknown":
    alert_critical("container_escape")
```

### After Separation
```yaml
# Clearer: Skip processes running on host OS
if alert.runtime == "host":
    skip_alert()

# Still alert on unresolved
if alert.state == "unknown":
    alert_critical("container_escape")
```

---

## Verification Checklist

- [ ] All alert outputs show correct `state` + `runtime` combination
- [ ] Host processes (systemd, droplet-agent) show `state=resolved, runtime=host`
- [ ] Container processes show `state=resolved, runtime=docker/k8s`
- [ ] Unresolved processes show `state=unknown, runtime=unknown`
- [ ] Pending containers show `state=pending, runtime=unknown` (during startup)
- [ ] No confusing `state=host` values in any alerts

---

## Notes

- This is a **clarification** not a behavior change — same detection logic applies
- Benefits:
  1. **Clarity**: State ≠ Runtime, they mean different things
  2. **Correctness**: Host processes correctly show `RuntimeHost` instead of false `RuntimeDocker`
  3. **Extensibility**: Easy to add new runtimes (podman, containerd) without confusion
  4. **Alerts**: Cleaner filtering logic in detection rules

---

## Host Runtime: Not a Monolithic State

**Key Insight:** Host is a complex runtime with many processes requiring differentiated policies.

### Host Runtime Contains Multiple Services

```
RuntimeHost can be:
├── System daemons (systemd, sshd, droplet-agent) → Expected
├── Docker daemon (dockerd) → Service detection needed
├── Package managers (apt, dpkg, pip) → Installation context
├── Init processes (/bin/sh, /usr/bin/init) → Bootstrapping
└── User processes (curl, grep, sleep) → Application-dependent
```

### Differentiated Rules by Service/Runtime Combination

```yaml
# Current: Too broad
if alert.state == "host":
    skip_alert()

# Better: Service-aware policies
if alert.runtime == "host":
    if alert.service == "docker-daemon":
        apply_docker_policies()      # Docker-specific rules
    elif alert.service == "systemd":
        apply_system_daemon_policies()  # System daemon rules
    elif alert.service == "init":
        apply_init_policies()        # Bootstrapping rules
    else:
        apply_general_host_policies()  # Generic host process rules
```

### Policy Examples

| Service | T1082 (System Info) | T1059 (Shell) | T1041 (Exfil) |
|---|---|---|---|
| systemd | ✅ Allow | ✅ Allow | ❌ Block |
| droplet-agent | ✅ Allow | ✅ Allow | ❌ Block |
| docker-daemon | ✅ Allow | ⚠️ Monitor | ❌ Block |
| init scripts | ✅ Allow (startup) | ✅ Allow (startup) | ❌ Block |
| user services | ⚠️ Monitor | ⚠️ Monitor | ❌ Block |

### Implementation Strategy

1. **Resolver Enhancement:**
   - Detect host namespace: `mntNsID == hostMntNsID`
   - Return `runtime=host` + service name (daemon/init/user)
   - Example: `runtime=host, service=docker-daemon`

2. **Service Detection for Host Processes:**
   ```go
   func identifyHostService(comm string, ppid uint32) string {
       switch {
       case comm == "systemd":
           return "systemd"
       case comm == "sshd":
           return "sshd"
       case comm == "dockerd":
           return "docker-daemon"
       case ppid == 1:  // Direct child of init
           return "init-service"
       default:
           return "user-process"
       }
   }
   ```

3. **Rule Filtering:**
   ```yaml
   # In rules/default.yaml
   t1082_system_info_discovery:
       exclude_runtimes:
           - runtime: host
             services: [systemd, sshd, droplet-agent, init-service]
       
       t1059_shell_execution:
           exclude_runtimes:
               - runtime: host
                 services: [systemd, init-service]
                 reason: "Expected during system initialization"
   ```

---

## Discussion Points

1. Should we cache host namespace in both resolvers or centrally?
2. Should `bareResult()` be split into `hostResult()` and `containerResult()`?
3. Any existing code that depends on `StateHost` needing special handling?
4. **NEW:** How do we identify host services? (process name, parent PID, command line?)
5. **NEW:** Should host services have a service registry (systemd=system, dockerd=docker)?
6. **NEW:** Different policies per host service, or one unified "host" policy?

---

**Status**: Awaiting review and approval before implementation.
