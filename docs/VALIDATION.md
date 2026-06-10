# Validation Guide — eBPF EDR Detection Rules

Manual test procedure to verify each detection rule fires correctly against real container behavior.
Run on the GCP Docker VM while the EDR agent is running.

Automated: `sudo ./validate.sh` runs all 13 tests with concurrent integration traffic.

---

## Test Strategy

Attack tests run while the full order-processor integration test suite runs concurrently in the
background. This validates two things at once:

1. **Attack detection** — each threat rule fires at the correct severity with the correct response action
2. **No false positives** — normal API traffic does not produce CRITICAL or HIGH alerts

---

## Prerequisites

```bash
# EDR agent running
sudo ./ebpf-edr --runtime=docker

# All order-processor containers running
docker ps

# Three terminals
tail -f alerts/alert.log          # Terminal 1: watch alerts live
tail -f /tmp/integ_tests.log      # Terminal 2: watch integration tests
sudo ./validate.sh                # Terminal 3: run all 13 tests
```

---

## Test Cases

### T1 — Shell Spawn in Container

**MITRE**: T1059.004 · T1609 — Command & Scripting: Unix Shell / Container Administration Command

**Threat**: Attacker achieved RCE inside a container and spawned an interactive shell.

**Command**:
```bash
docker exec order-processor-user_service bash -c "id"
```

**Expected**:
```
level=CRITICAL rule=T1059_unix_shell_execution service=user_service comm=/usr/bin/bash
```

---

### T2 — Network Staging Tool in Container

**MITRE**: T1105 · T1095 — Ingress Tool Transfer / Non-Application Layer Protocol

**Threat**: Attacker runs `nc` or `wget` to stage tools or exfiltrate data.

**Command**:
```bash
docker exec order-processor-auth_service nc -w 2 1.1.1.1 80
```

**Expected**:
```
level=HIGH rule=T1105_ingress_tool_transfer service=auth_service comm=nc
```

**Note**: validate.sh copies `nc` from host if not present in container. If neither nc/wget is in the container nor `nc` on the host, the test is silently skipped. Rule correctness confirmed by GKE V8 (wget in auth-service image).

---

### T3 — OS Credential Dumping

**MITRE**: T1003.008 — OS Credential Dumping: /etc/shadow

**Threat**: Attacker reads password hashes to crack credentials offline.

**Command**:
```bash
docker exec order-processor-order_service cat /etc/shadow
```

**Expected**:
```
level=HIGH rule=T1003_008_os_credential_dumping service=order_service filename=/etc/shadow action=kill_process
```

---

### T4 — Private Key Access

**MITRE**: T1552.004 — Unsecured Credentials: Private Keys

**Threat**: Attacker reads an SSH private key from inside a container.

**Command**:
```bash
docker cp /tmp/test_id_rsa order-processor-user_service:/tmp/id_rsa
docker exec order-processor-user_service cat /tmp/id_rsa
```

**Expected**:
```
level=HIGH rule=T1552_004_private_keys service=user_service filename=/tmp/id_rsa action=kill_process
```

---

### T5 — Unauthorized External Connect + Block Verification

**MITRE**: T1041 · T1048 — Exfiltration Over C2 / Alternative Protocol

**Threat**: Compromised container connects to attacker C2 or exfiltrates data.

**Test includes 3-step verification:**

```
Step 1: connect to 8.8.8.8 → T1041 alert fires + IP added to blocked_ips BPF map
Step 2: connect to 8.8.8.8 again → EPERM (blocked at kernel before TCP handshake)
Step 3: connect to private IP → no EPERM (private IPs never blocked)
```

**Expected (Step 1)**:
```
level=HIGH rule=T1041_exfiltration_over_c2 service=auth_service dst=8.8.8.8:80 action=block_ip
```

**Expected (Step 2)**: `[Errno 1] Operation not permitted` — no alert (blocked at kernel, no event emitted)

**Expected (Step 3)**: connection refused or timeout — NOT EPERM

---

### T6 — Authorized External Connection (No Alert)

**Threat model**: Verify the allowlist works — `inventory_service` is permitted to call CoinGecko.

**Expected**: No alert. HIGH alert would indicate the allowlist is broken.

---

### T7 — Host Reads Container Filesystem

**MITRE**: T1611 — Escape to Host

**Threat**: Attacker on the host reads secrets directly from container overlay — bypassing container isolation.

**Command**:
```bash
MERGED=$(docker inspect order-processor-order_service --format '{{.GraphDriver.Data.MergedDir}}')
cat "${MERGED}/etc/hostname"
```

**Expected**:
```
level=CRITICAL rule=T1611_escape_to_host_fs service=host filename=/var/lib/docker/overlay2/.../merged/etc/hostname action=kill_process
```

---

### T8 — System Information Discovery

**MITRE**: T1082 — System Information Discovery

**Threat**: Attacker enumerates user accounts for privilege escalation targets.

**Command**:
```bash
docker exec order-processor-insights_service cat /etc/passwd
```

**Expected**:
```
level=MEDIUM rule=T1082_system_info_discovery service=insights_service filename=/etc/passwd
```

**Note**: MEDIUM because `/etc/passwd` is world-readable. `bash` is whitelisted (reads at startup); `cat` is not.

---

### T9 — Binary Masquerading

**MITRE**: T1036 — Masquerading

**Threat**: Attacker drops a malicious binary named after a legitimate process and runs it from `/tmp`.

**Command**:
```bash
docker exec order-processor-order_service cp /bin/cat /tmp/sshd
docker exec order-processor-order_service /tmp/sshd /etc/hostname
```

**Expected**:
```
level=HIGH rule=T1036_masquerading service=order_service comm=/tmp/sshd
```

**Note**: Two separate `docker exec` calls — avoids `/bin/sh` wrapper which would trigger T1059.
Masquerading check runs before the process whitelist (`/tmp/sshd` fires even though `sshd` is whitelisted).

---

### T10 — Cron Modification

**MITRE**: T1053.003 — Scheduled Task/Job: Cron

**Threat**: Attacker modifies cron to establish persistence inside a container.

**Command**:
```bash
echo "* * * * * root /tmp/evil" > /tmp/test_crontab
docker cp /tmp/test_crontab order-processor-user_service:/etc/crontab
docker exec order-processor-user_service cat /etc/crontab
```

**Expected**:
```
level=HIGH rule=T1053_003_scheduled_task_cron service=user_service filename=/etc/crontab
```

---

### T11 — Clear Command History

**MITRE**: T1070.003 — Indicator Removal: Clear Command History

**Threat**: Attacker covers tracks by accessing or clearing shell history.

**Command**:
```bash
echo "rm -rf /important" > /tmp/bash_hist
docker cp /tmp/bash_hist order-processor-insights_service:/tmp/.bash_history
docker exec order-processor-insights_service cat /tmp/.bash_history
```

**Expected**:
```
level=MEDIUM rule=T1070_003_clear_command_history service=insights_service filename=/tmp/.bash_history
```

### T12 — Credentials in Files

**MITRE**: T1552.001 — Unsecured Credentials: Credentials in Files

**Threat**: Attacker finds an unencrypted `.env` file inside a container containing database passwords or API keys.

**Command**:
```bash
echo "DB_PASSWORD=super_secret_password" > /tmp/app.env
docker cp /tmp/app.env order-processor-user_service:/tmp/app.env
docker exec order-processor-user_service cat /tmp/app.env
```

**Expected**:
```
level=HIGH rule=T1552_001_credentials_in_files service=user_service filename=/tmp/app.env
```

**Why it fires**: `/tmp/app.env` matches the `.env` suffix in `t1552CredentialFileSuffixes`. Docker cp places the file; docker exec cat opens it — `lsm/file_open` fires on the successful open.

---

### T13 — Container Resource Discovery

**MITRE**: T1613 — Container and Resource Discovery

**Threat**: Attacker inside a container runs a container management tool (`docker`, `kubectl`, `crictl`) to enumerate the surrounding container environment and discover lateral movement targets.

**Command**:
```bash
docker cp $(which docker) order-processor-auth_service:/usr/local/bin/docker
docker exec order-processor-auth_service /usr/local/bin/docker ps
```

**Expected**:
```
level=HIGH rule=T1613_container_resource_discovery service=auth_service comm=/usr/local/bin/docker
```

**Note**: The `docker ps` command fails at runtime (no socket mounted in container) but the execve fires the process event before any I/O. `/usr/local/bin/docker` matches the `/docker` suffix in `t1613ContainerMgmtTools`.

---

## Results Checklist

**Attack detection:**

- [x] T1  — CRITICAL `T1059_unix_shell_execution`
- [x] T2  — HIGH `T1105_ingress_tool_transfer` (requires nc/wget in container — see T2 note)
- [x] T3  — HIGH `T1003_008_os_credential_dumping` + kill_process
- [x] T4  — HIGH `T1552_004_private_keys` + kill_process
- [x] T5  — HIGH `T1041_exfiltration_over_c2` + block_ip (EPERM on retry verified)
- [x] T6  — No alert (inventory_service allowlisted — correct)
- [x] T7  — CRITICAL `T1611_escape_to_host_fs` + kill_process
- [x] T8  — MEDIUM `T1082_system_info_discovery`
- [x] T9  — HIGH `T1036_masquerading`
- [x] T10 — HIGH `T1053_003_scheduled_task_cron`
- [x] T11 — MEDIUM `T1070_003_clear_command_history`
- [x] T12 — HIGH `T1552_001_credentials_in_files` `.env` file (user_service)
- [x] T13 — HIGH `T1613_container_resource_discovery` docker in container (auth_service)

**False positive check — confirmed clean:**

- [x] No CRITICAL alerts from normal API traffic
- [x] No HIGH alerts from normal API traffic
- [x] Integration tests pass (services remain healthy under EDR observation)

---

## Out of Scope

| Scenario | Why excluded |
|----------|-------------|
| SSH login detection | Host-level auth — outside container threat model |
| Container escape via kernel exploit | Requires real CVE — impractical to simulate safely |
| Scripting interpreter (python -c) | High FP risk — Python service processes are legitimate |
| Network service scanning (burst) | Requires stateful detection — sliding window counter |
