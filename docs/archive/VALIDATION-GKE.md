# Validation Guide — eBPF EDR on GKE

Attack simulation test procedure for the GKE DaemonSet deployment.
Run from a laptop with `kubectl` configured for the health-ai cluster.

---

## Test Strategy

Tests are distributed across all 4 health-ai services to confirm the eBPF resolver
maps mount-namespace IDs to service identities for every pod, not just one.

| Service | Tests |
|---------|-------|
| auth-service | V3 (shadow), V8 (net-tool), V10 (reverse-shell) |
| provider-service | V2 (shell-spawn), V7 (ssh-key), V11 (credentials-env) |
| gateway | V4 (ext-connect), V9 (passwd), V12 (container-mgmt) |
| ai-service | V5 (allowlist passive check) |

Two goals verified together:

1. **Attack detection** — each threat rule fires at the correct severity with full workload identity
2. **No false positives** — normal gateway traffic does not produce CRITICAL or HIGH alerts

Automated with `validate-gke.sh` — each test polls Cloud Logging and reports PASS/FAIL.

---

## Prerequisites

- GKE cluster running: `kubectl get nodes`
- EDR DaemonSet deployed: `kubectl get pods -n kube-system -l app=ebpf-edr`
- health-ai pods running: `kubectl get pods -n health-ai`
- Run from laptop: `./validate-gke.sh`

---

## Test Cases

### V2 — Shell Spawn in Container (provider-service)

**Threat**: Attacker achieved RCE inside a pod and spawned an interactive shell.

**Trigger**:
```bash
kubectl exec <provider-service-pod> -n health-ai -- sh -c "exit 0"
```

**Expected alert**:
```
level=CRITICAL rule=T1059_unix_shell_execution service=provider-service namespace=health-ai
```

**Why it fires**: `sh` matches `shellBinaries` suffix list. Any shell spawn inside a
container is treated as RCE evidence regardless of the command run inside it.

---

### V3 — Sensitive File: `/etc/shadow` (auth-service)

**Threat**: Attacker reads the password hash file to crack credentials offline.

**Trigger**:
```bash
kubectl exec <auth-service-pod> -n health-ai -- sh -c \
  "echo 'root:!:19000:0:99999:7:::' > /etc/shadow && cat /etc/shadow"
```

**Expected alert**:
```
level=HIGH rule=T1003_008_os_credential_dumping service=auth-service namespace=health-ai
filename=/etc/shadow
```

**Note**: The file is created first because Alpine JRE images don't ship `/etc/shadow`.
`lsm/file_open` fires on the successful open — unlike the old opensnoop design, ENOENT
events are naturally absent (LSM hook fires only after the kernel validates the open).

---

### V4 — Unauthorized External Network Connection (gateway)

**Threat**: Compromised pod reaches out to an external IP (C2, exfiltration).

**Trigger**:
```bash
kubectl exec <gateway-pod> -n health-ai -- wget --timeout=3 -q http://8.8.8.8/ -O /dev/null
```

**Expected alert**:
```
level=HIGH rule=T1041_exfiltration_over_c2 service=gateway namespace=health-ai
dst_ip=8.8.8.8
```

**Why it fires**: `gateway` is not in `externalAllowedServices`. Any external (non-RFC-1918)
connection from an unauthorized container triggers HIGH.

---

### V5 — ai-service Allowlist (No Alert)

**Threat model**: Verify the allowlist works — `ai-service` calls Gemini (external AI API).
This test confirms no HIGH `T1041_exfiltration_over_c2` fires for `ai-service` traffic.

**Trigger**: Observe passively for 20s — ai-service sends periodic Gemini requests.

**Expected**: No `HIGH T1041_exfiltration_over_c2` for `ai-service`.
`ai-service` is in `externalAllowedServices` — external connections are silently allowed.

---

### V6 — No CRITICAL False Positives from Normal Traffic

**Trigger**:
```bash
curl -sf "http://<gateway-ip>:8080/actuator/health"
```

**Expected**: No CRITICAL alerts for `gateway`, `auth-service`, `provider-service`, or
`ai-service` in the `health-ai` namespace from a normal health check.

---

### V7 — SSH Private Key Read (provider-service)

**Threat**: Attacker reads an SSH private key from inside a pod to move laterally.

**Trigger**:
```bash
kubectl exec <provider-service-pod> -n health-ai -- sh -c \
  "mkdir -p /root/.ssh && echo 'test-key' > /root/.ssh/id_rsa && cat /root/.ssh/id_rsa"
```

**Expected alert**:
```
level=CRITICAL rule=T1552_004_private_keys service=provider-service namespace=health-ai
filename=/root/.ssh/id_rsa
```

**Note**: The `/root/.ssh/` directory prefix triggers CRITICAL (SSH dir prefix rule).
The `sh -c` also triggers `T1059_unix_shell_execution` CRITICAL — that is expected.

---

### V8 — Network Recon Tool in Container (auth-service)

**Threat**: Attacker inside a pod runs `wget` to probe external hosts or stage tools.

**Trigger**:
```bash
kubectl exec <auth-service-pod> -n health-ai -- wget --timeout=2 -q http://1.1.1.1 -O /dev/null
```

**Expected alert**:
```
level=HIGH rule=T1105_ingress_tool_transfer service=auth-service namespace=health-ai
```

**Note**: Detection fires on binary execution (`/usr/bin/wget` matches `networkBinaries`),
not on the network connection. `validate-gke.sh` attempts `wget` first, falls back to `nc`.

---

### V9 — System File Recon: `/etc/passwd` (gateway)

**Threat**: Attacker reads the user account list to identify targets for privilege escalation.

**Trigger**:
```bash
kubectl exec <gateway-pod> -n health-ai -- cat /etc/passwd
```

**Expected alert**:
```
level=MEDIUM rule=T1082_system_info_discovery service=gateway namespace=health-ai
filename=/etc/passwd
```

**Why MEDIUM not HIGH**: `/etc/passwd` is world-readable and not a direct credential.
Reading it from application code is suspicious but lower risk than `/etc/shadow` or private keys.

---

### V10 — Reverse Shell Simulation (auth-service)

**Threat**: Attacker establishes a reverse shell — combines external C2 connection with
spawning a shell process, the classic RCE-to-persistence attack chain.

**Trigger**:
```bash
kubectl exec <auth-service-pod> -n health-ai -- sh -c \
  "wget --timeout=2 -q http://8.8.8.8:4444 -O /dev/null || true; sh -c 'exit 0'"
```

**Expected alerts** (both must fire):
```
level=CRITICAL rule=T1059_unix_shell_execution service=auth-service namespace=health-ai
level=HIGH rule=T1041_exfiltration_over_c2 service=auth-service namespace=health-ai dst_ip=8.8.8.8
```

**Why two alerts**: the inner `sh -c 'exit 0'` triggers `T1059_unix_shell_execution` CRITICAL;
the `wget http://8.8.8.8:4444` attempt triggers `T1041_exfiltration_over_c2` HIGH.
Both together signal a reverse shell pattern.

### V11 — Credentials in Files (provider-service)

**MITRE**: T1552.001 — Unsecured Credentials: Credentials in Files

**Threat**: Attacker finds a `.env` file inside a pod containing database passwords or API keys.

**Trigger**:
```bash
kubectl cp /tmp/app.env <provider-service-pod>:/tmp/app.env -n health-ai
kubectl exec <provider-service-pod> -n health-ai -- cat /tmp/app.env
```

**Expected alert**:
```
level=HIGH rule=T1552_001_credentials_in_files service=provider-service namespace=health-ai
filename=/tmp/app.env
```

**Why it fires**: `/tmp/app.env` matches `.env` suffix in `t1552CredentialFileSuffixes`. `kubectl cp` uses tar (open for write happens before `V11_SINCE`); `cat` triggers the alert captured by the test.

---

### V12 — Container Management Tool Execution (gateway)

**MITRE**: T1613 — Container and Resource Discovery

**Threat**: Attacker inside a pod runs a container management tool (`kubectl`, `docker`, `crictl`) to enumerate the surrounding cluster and discover lateral movement targets.

**Trigger**:
```bash
kubectl exec <gateway-pod> -n health-ai -- sh -c \
  "cp /bin/cat /usr/local/bin/kubectl"
# wait 3s for cp to complete
kubectl exec <gateway-pod> -n health-ai -- /usr/local/bin/kubectl /etc/hostname
```

**Expected alert**:
```
level=HIGH rule=T1613_container_resource_discovery service=gateway namespace=health-ai
comm=/usr/local/bin/kubectl
```

**Note**: The setup step (`sh -c "cp ..."`) fires `T1059_unix_shell_execution` CRITICAL — expected side effect. The cp fork-child completes before SIGKILL arrives (cp is extremely fast). The second exec fires T1613 on the binary name match `/kubectl`. The binary itself fails to do anything useful (it's actually `cat`) but the execve fires the alert.

---

## Results Checklist

**Attack detection:**

- [x] V2 — CRITICAL `T1059_unix_shell_execution` (provider-service)
- [x] V3 — HIGH `T1003_008_os_credential_dumping` `/etc/shadow` (auth-service)
- [x] V4 — HIGH `T1041_exfiltration_over_c2` 8.8.8.8 (gateway)
- [x] V5 — No alert (ai-service allowlisted — correct)
- [x] V6 — No CRITICAL from normal gateway traffic
- [x] V7 — CRITICAL `T1552_004_private_keys` `/root/.ssh/id_rsa` (provider-service)
- [x] V8 — HIGH `T1105_ingress_tool_transfer` wget (auth-service)
- [x] V9 — MEDIUM `T1082_system_info_discovery` `/etc/passwd` (gateway)
- [x] V10 — CRITICAL `T1059_unix_shell_execution` + HIGH `T1041_exfiltration_over_c2` (auth-service)
- [x] V11 — HIGH `T1552_001_credentials_in_files` `/tmp/app.env` (provider-service)
- [x] V12 — HIGH `T1613_container_resource_discovery` `/usr/local/bin/kubectl` (gateway)

**Workload identity verified on all alerts:**

- [x] `service` field populated (e.g. `auth-service`, `provider-service`, `gateway`)
- [x] `namespace` field populated (`health-ai`)
- [x] `runtime` = `k8s`
- [x] All 4 services confirmed: resolver maps mnt_ns_id correctly for every pod

All 11 GKE tests validated on health-ai cluster. V2–V10 as of 2026-06-10; V11–V12 as of 2026-06-09.
