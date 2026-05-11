# Validation Guide — eBPF EDR on GKE

Attack simulation test procedure for the GKE DaemonSet deployment.
Run from a laptop with `kubectl` configured for the order-processor cluster.

---

## Test Strategy

Tests run against a live `user-service` pod in the `order-processor` namespace.
The EDR agent runs as a DaemonSet (`kube-system/ebpf-edr`) and watches all pods on the node.

Two goals verified together:

1. **Attack detection** — each threat rule fires at the correct severity with full workload identity
2. **No false positives** — normal gateway traffic does not produce CRITICAL or HIGH alerts

Automated with `validate-gke.sh` — each test polls EDR logs and reports PASS/FAIL.

---

## Prerequisites

- GKE cluster running: `kubectl get nodes`
- EDR DaemonSet deployed: `kubectl get pods -n kube-system -l app=ebpf-edr`
- `user-service` pod running: `kubectl get pods -n order-processor -l component=user-service`
- Run from laptop: `./validate-gke.sh`

---

## Test Cases

### V2 — Shell Spawn in Container

**Threat**: Attacker achieved RCE inside a pod and spawned an interactive shell.

**Trigger**:
```bash
kubectl exec <user-service-pod> -n order-processor -- bash -c "exit 0"
```

**Expected alert**:
```
level=CRITICAL rule=shell_spawn_container service=user-service namespace=order-processor
```

**Why it fires**: `bash` matches `shellBinaries` suffix list. Any shell spawn inside a
container is treated as RCE evidence regardless of the command run inside it.

---

### V3 — Sensitive File: `/etc/shadow`

**Threat**: Attacker reads the password hash file to crack credentials offline.

**Trigger**:
```bash
kubectl exec <user-service-pod> -n order-processor -- cat /etc/shadow
```

**Expected alert**:
```
level=HIGH rule=sensitive_file_access service=user-service namespace=order-processor
msg=Container accessed sensitive file: /etc/shadow
```

**Note**: `cat` gets `EACCES` (permission denied) but opensnoop still fires — the two-probe
design emits on access-denied opens, not just successful ones. The *attempt* to read shadow is
the signal, not the success.

---

### V4 — Unauthorized External Network Connection

**Threat**: Compromised pod reaches out to an external IP (C2, exfiltration).

**Trigger**:
```bash
kubectl exec <user-service-pod> -n order-processor -- \
  python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('8.8.8.8',80)); s.close()"
```

**Expected alert**:
```
level=HIGH rule=unauthorized_external_connect service=user-service namespace=order-processor
msg=Container made unauthorized external connection to 8.8.8.8:80
```

**Why it fires**: `user-service` is not in `externalAllowedServices`. Any external (non-RFC-1918)
connection from an unauthorized container triggers HIGH.

---

### V5 — Inventory Allowlist (No Alert)

**Threat model**: Verify the allowlist works — `inventory-service` is the only container
permitted to call external APIs. This test confirms no HIGH alert fires.

**Trigger**: Observe passively — inventory syncs automatically, or hit the gateway endpoint.

**Expected**: No `HIGH unauthorized_external_connect` for `inventory-service`.
`inventory-service` is in `externalAllowedServices` — external connections are silently allowed.

---

### V6 — No CRITICAL False Positives from Normal Traffic

**Trigger**:
```bash
curl -sf "http://<gateway-ip>:8080/health"
```

**Expected**: No CRITICAL alerts for `gateway`, `user-service`, `auth-service`, or
`order-service` in the `order-processor` namespace from a normal health check.

---

### V7 — SSH Private Key Read

**Threat**: Attacker reads an SSH private key from inside a pod to move laterally.

**Trigger**:
```bash
kubectl exec <user-service-pod> -n order-processor -- bash -c \
  "mkdir -p /root/.ssh && echo 'test-key' > /root/.ssh/id_rsa && cat /root/.ssh/id_rsa"
```

**Expected alert**:
```
level=CRITICAL rule=sensitive_file_access service=user-service namespace=order-processor
msg=Container accessed SSH credential file: /root/.ssh/id_rsa
```

**Note**: The `bash -c` also triggers `shell_spawn_container` CRITICAL — that is expected.
The SSH key access fires as a separate CRITICAL event for the `/root/.ssh/` path prefix.

---

### V8 — Network Recon Tool in Container

**Threat**: Attacker inside a pod runs `nc` or `wget` to probe external hosts or exfiltrate data.

**Trigger** (`nc` preferred, falls back to `wget`):
```bash
kubectl exec <user-service-pod> -n order-processor -- nc -w 2 1.1.1.1 80
# or
kubectl exec <user-service-pod> -n order-processor -- wget --timeout=2 -q http://1.1.1.1
```

**Expected alert**:
```
level=HIGH rule=network_tool_container service=user-service namespace=order-processor
```

**Note**: Detection fires on binary execution, not the network connection.
`validate-gke.sh` attempts `nc` first, falls back to `wget`. Skipped if neither is available.

---

### V9 — System File Recon: `/etc/passwd`

**Threat**: Attacker reads the user account list to identify targets for privilege escalation
or lateral movement.

**Trigger**:
```bash
kubectl exec <user-service-pod> -n order-processor -- cat /etc/passwd
```

**Expected alert**:
```
level=MEDIUM rule=sensitive_file_access service=user-service namespace=order-processor
msg=Container accessed system file: /etc/passwd
```

**Why MEDIUM not HIGH**: `/etc/passwd` is world-readable and not a direct credential.
Reading it from application code is suspicious but lower risk than `/etc/shadow` or private keys.

---

### V10 — Reverse Shell Simulation

**Threat**: Attacker establishes a reverse shell — combines external C2 connection with
spawning a shell process, the classic RCE-to-persistence attack chain.

**Trigger**:
```bash
kubectl exec <user-service-pod> -n order-processor -- bash -c "
  python3 -c \"
import socket, subprocess
s = socket.socket()
s.settimeout(2)
try: s.connect(('8.8.8.8', 4444))
except: pass
subprocess.call(['/bin/sh'])
\""
```

**Expected alerts** (both must fire):
```
level=CRITICAL rule=shell_spawn_container service=user-service namespace=order-processor
level=HIGH rule=unauthorized_external_connect service=user-service namespace=order-processor
msg=Container made unauthorized external connection to 8.8.8.8:4444
```

**Why two alerts**: `subprocess.call(['/bin/sh'])` triggers `shell_spawn_container` CRITICAL;
the `s.connect(('8.8.8.8', 4444))` attempt triggers `unauthorized_external_connect` HIGH.
Both together signal a reverse shell pattern.

---

## Results Checklist

**Attack detection:**

- [x] V2 — CRITICAL `shell_spawn_container` (`kubectl exec bash`)
- [x] V3 — HIGH `sensitive_file_access` (`/etc/shadow`)
- [x] V4 — HIGH `unauthorized_external_connect` (8.8.8.8:80)
- [x] V5 — No alert (inventory-service allowlisted — correct)
- [x] V6 — No CRITICAL from normal gateway traffic
- [x] V7 — CRITICAL `sensitive_file_access` (SSH key `/root/.ssh/id_rsa`)
- [x] V8 — HIGH `network_tool_container` (`nc` / `wget`)
- [x] V9 — MEDIUM `sensitive_file_access` (`/etc/passwd`)
- [x] V10 — CRITICAL `shell_spawn_container` + HIGH `unauthorized_external_connect` (reverse shell)

**Workload identity verified on all alerts:**

- [x] `service` field populated (`user-service`)
- [x] `pod` field populated (pod name)
- [x] `namespace` field populated (`order-processor`)
- [x] `cluster` field populated (`order-processor-cluster-us-west1`)
- [x] `region` field populated (`us-west1`)
- [x] `runtime` = `k8s`
