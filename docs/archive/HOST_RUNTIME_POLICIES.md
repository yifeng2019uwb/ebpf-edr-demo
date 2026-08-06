# Host Runtime Detection & Differentiated Policies

**Date:** 2026-07-03  
**Status:** 🔄 Design Phase  
**Scope:** System services, daemons, and user processes running on host OS

---

## Overview

Host OS processes are not monolithic — they include:
- **System daemons** (systemd, sshd, docker daemon)
- **Package managers** (apt, dpkg, pip) — expected during installation
- **Init/startup scripts** — temporary processes during boot
- **User services** — application processes running on host

Each category has different behavioral expectations and should trigger different alert levels.

---

## Host Service Classification

### Tier 1: System Daemons (Core Services)
These are permanent system services that should exist on any production host.

```go
var SystemDaemons = map[string]bool{
    "systemd":           true,  // Init system
    "sshd":              true,  // Secure shell
    "droplet-agent":     true,  // Cloud provider agent (DigitalOcean)
    "docker":            true,  // Container daemon
    "kubelet":           true,  // K8s node agent
    "containerd":        true,  // Container runtime
    "systemd-resolved":  true,  // DNS resolver
    "systemd-journal":   true,  // Logging daemon
}
```

**Policy:** 
- T1082 (System Info): ✅ Allow — reading /etc/passwd is expected
- T1059 (Shell Execution): ✅ Allow — system daemons spawn shells
- T1041 (Exfiltration): ❌ Alert CRITICAL — unexpected outbound

---

### Tier 2: Init/Startup Processes (Ephemeral)
These processes run during system boot or container startup. They're transient.

```go
var InitProcesses = map[string]bool{
    "/bin/sh":           true,
    "/bin/bash":         true,
    "/usr/bin/init":     true,
    "/sbin/init":        true,
    "systemd-tmpfiles":  true,  // Temporary file cleanup
    "apt":               true,  // Package manager (Debian/Ubuntu)
    "dpkg":              true,  // Package tool
    "pip":               true,  // Python package manager
}
```

**Detection:** Check parent PID == 1 (direct child of init)

**Policy:**
- T1082 (System Info): ✅ Allow (startup initialization)
- T1059 (Shell Execution): ✅ Allow (during installation)
- T1041 (Exfiltration): ❌ Alert CRITICAL
- **Constraint:** Only during boot window (first 5 minutes after system start)

---

### Tier 3: Cloud/Infrastructure Agents
Provider-specific agents that manage the instance.

```go
var CloudAgents = map[string]bool{
    "droplet-agent":     true,      // DigitalOcean
    "ec2-user-data":     true,      // AWS EC2
    "cloud-init":        true,      // Multi-cloud
    "azure-agent":       true,      // Azure
    "gce-startup":       true,      // Google Compute
}
```

**Policy:** Same as system daemons (expected infrastructure maintenance)

---

## Workload Resolution: Host Process Identification

**Purpose:** When the workload resolver encounters a process with no valid container ID (cgroup parse fails or infrastructure process), identify if it's a host system process. This prevents false "unknown namespace" alerts and deadlocks for legitimate infrastructure processes.

**When Used:** `pkg/workload/docker_resolver.go` - `asyncResolvePID()` method, when `containerID == ""` (procfs race or system process)

---

### Host Process Whitelist (for Resolver)

Extracted from Tier 1-3 classifications + environment-specific infrastructure.

**Reference:** See [DETECTION-POLICY.md](DETECTION-POLICY.md) for environment-specific whitelists per Docker/K8s.

**Tier 1 - System Daemons:**
- `systemd*` (systemd, systemd-logind, systemd-sysctl, systemd-resolved, systemd-journal)
- `sshd` — Secure shell
- `docker*` (dockerd, docker-proxy) — Container daemon
- `kubelet` — K8s node agent
- `containerd*` (containerd, containerd-shim) — Container runtime
- `runc` — Container runtime (Docker/K8s)
- `init` — System init

**Tier 3 - Cloud/Infrastructure Agents:**
- `droplet-agent` — DigitalOcean
- `ec2-*` — AWS EC2
- `cloud-init` — Multi-cloud
- `azure-*` — Azure
- `gce-*` — Google Compute

**K8s Infrastructure (from DETECTION-POLICY.md):**
- `iptables*`, `iptables-legacy`, `iptables-restore` — kube-proxy network rules
- `ip6tables` — IPv6 networking
- `conntrack` — Connection tracking
- `ip` — iproute2 route/address management
- `kube-proxy` — Kubernetes network proxy
- `pause` — K8s pod sandbox
- `bridge*` — Network bridge management

**Pattern Matching:**
- `systemd*` matches: systemd, systemd-logind, systemd-sysctl, etc.
- `docker*` matches: dockerd, docker-proxy, etc.
- `containerd*` matches: containerd, containerd-shim
- `iptables*` matches: iptables, iptables-legacy, iptables-restore
- `ec2-*`, `azure-*`, `gce-*` for cloud-specific tools

---

### Resolver Algorithm

**In `asyncResolvePID(pid)` when `containerID == ""`:**

1. Read process name from `/proc/[pid]/comm`
2. Match against hostProcessWhitelist (with pattern support)
3. **If match:** 
   - Cache as `host-process`
   - Return immediately (no deadlock, no unknown namespace alert)
4. **If no match:**
   - Cache as `StateUnknown` 
   - Potential container escape or unrecognized process

**Example:**
```
PID 660 → /proc/660/comm = "systemd-logind"
Match against "systemd*" ✓
→ Cache as host-process, return
Result: workload.runtime=host, workload.service=systemd-logind
```

**Prevents:**
- ❌ Deadlock from nested lock acquisition
- ❌ False "unknown namespace" alerts for infrastructure processes
- ❌ Events stuck pending forever
- ✅ Correct classification of system services

---

### Tier 4: User Processes (Unprivileged)
Applications running as non-root on the host.

```go
// uid > 1000 typically indicates user process
// Can be legitimate user applications, but less trusted
```

**Policy:**
- T1082 (System Info): ⚠️ Monitor (might indicate reconnaissance)
- T1059 (Shell Execution): ⚠️ Monitor (might indicate shell injection)
- T1041 (Exfiltration): ❌ Alert HIGH (suspicious for user process)

---

## Detection Strategy

### 1. Identify Process Category

```go
func classifyHostProcess(proc ProcessEvent, ppid uint32) HostServiceClass {
    comm := processor.CString(proc.Comm[:])
    
    // Check Tier 1: System daemons
    if SystemDaemons[comm] {
        return ClassSystemDaemon
    }
    
    // Check Tier 3: Cloud agents
    if CloudAgents[comm] {
        return ClassCloudAgent
    }
    
    // Check Tier 2: Init processes (parent is init)
    if ppid == 1 && InitProcesses[comm] {
        return ClassInitProcess
    }
    
    // Check UID: root vs unprivileged
    if proc.Uid == 0 {
        return ClassRootProcess
    }
    
    return ClassUserProcess
}
```

### 2. Get Service Name from Category

```go
func getHostServiceName(class HostServiceClass, comm string) string {
    switch class {
    case ClassSystemDaemon:
        return "daemon-" + comm
    case ClassCloudAgent:
        return "cloud-agent"
    case ClassInitProcess:
        return "init-process"
    case ClassRootProcess:
        return "root-process"
    default:
        return "user-process"
    }
}
```

### 3. Use in Resolver

```go
// In Resolve() when detecting host namespace
if mntNsID == hostMntNsID {
    serviceClass := classifyHostProcess(ev.Process, ev.Process.Ppid)
    serviceName := getHostServiceName(serviceClass, comm)
    
    return ResolveResult{
        State: StateResolved,
        Identity: WorkloadIdentity{
            Runtime: RuntimeHost,
            Service: serviceName,  // e.g., "daemon-systemd" or "cloud-agent"
            Env: r.env,
        },
    }
}
```

---

## Policy Application in Rules

### Current (Too Broad)
```yaml
t1082_system_info_discovery:
    exclude_runtimes: [host]  # Skip ALL host processes
```

### After (Differentiated)
```yaml
t1082_system_info_discovery:
    exclude_runtime_services:
        - runtime: host
          services: 
            - daemon-*           # Skip all system daemons
            - cloud-agent        # Skip cloud agents
            - init-process       # Skip init/startup
          
        - runtime: host
          services: [user-process]
          severity: medium       # Downgrade user processes to medium
          reason: "User processes reading system files are less critical"

t1059_shell_execution:
    exclude_runtime_services:
        - runtime: host
          services: 
            - daemon-*           # System daemons can spawn shells
            - init-process       # Init/startup expected to run installers
          
        - runtime: host
          services: [user-process]
          severity: high         # User processes spawning shells = suspicious
```

---

## Alert Examples

### Before (All confused)
```
ALERT state=host rule=T1082_system_info_discovery pid=649 comm=droplet-agent
ALERT state=host rule=T1082_system_info_discovery pid=235287 comm=sshd
ALERT state=host rule=T1611_escape_to_host_ns pid=235339 comm=/usr/bin/dirname
→ Can't tell which are false positives and which are real threats
```

### After (Clearly categorized)
```
ALERT runtime=host service=cloud-agent rule=T1082_system_info_discovery pid=649
→ Skip: Expected infrastructure maintenance

ALERT runtime=host service=daemon-sshd rule=T1082_system_info_discovery pid=235287
→ Skip: Expected system daemon behavior

ALERT runtime=host service=user-process rule=T1082_system_info_discovery pid=236172 comm=curl
→ Downgrade severity or skip: Legitimate user tool

ALERT runtime=container service=redis state=unknown rule=T1082_system_info_discovery pid=236108
→ ALERT: Container doing suspicious activity in unknown namespace
```

---

## Implementation Phases

### Phase 1: Resolver Enhancement
- [ ] Add host namespace caching
- [ ] Implement process classification logic
- [ ] Return service name for host processes
- [ ] Update resolver return types

### Phase 2: Rules Update
- [ ] Migrate rules from `exclude_runtimes: [host]` to service-based exclusions
- [ ] Add severity overrides per service class
- [ ] Test against existing VM activity

### Phase 3: Monitoring
- [ ] Log which host services are being excluded
- [ ] Monitor for unexpected host process behavior
- [ ] Refine classifications based on false positives

---

## Open Questions

1. **Service naming convention:**
   - Use `daemon-<name>`, `cloud-agent`, `init-process`?
   - Or simpler: just the command name?

2. **Time-based policies for init:**
   - Should init processes only be whitelisted in first 5min of boot?
   - Or always whitelisted (assumes container startup)?

3. **UID-based policies:**
   - Should non-root host processes be treated differently?
   - Different policies for `uid > 1000` vs `uid == 0`?

4. **Dynamic service registry:**
   - Should administrators be able to add/remove services from tiers?
   - Config file with allowed host services?

5. **Docker daemon special handling:**
   - Docker daemon (`runtime=host, service=docker-daemon`) spawns containers
   - Should have different rules than other daemons
   - Example: connecting to Docker socket is expected; external network less so

---

**Status:** Design phase. Ready for review and refinement.
