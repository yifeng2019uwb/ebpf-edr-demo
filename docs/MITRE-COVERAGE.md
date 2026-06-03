# MITRE ATT&CK Coverage — eBPF EDR Demo

Scope: runtime-detectable container/K8s techniques only.

Full ATT&CK has 200+ techniques. Of those, ~35 apply to containerized GKE workloads.
Of those 35, only ~15 are detectable via eBPF at runtime via single-event detection —
the rest require image scanning, CI/CD pipeline hooks, WAF, or stateful behavioral analysis.

**Current coverage: 15 of ~15 single-event-detectable techniques**

All single-event-detectable techniques are now covered.
Remaining gaps require stateful/behavioral detection (see Phase 2 section).

---

## Detection Rules → MITRE Mapping

Status: ✅ implemented + validated by validate.sh  🔲 planned — not yet implemented

| Rule | Severity | MITRE ID | Technique | Status |
|------|----------|----------|-----------|--------|
| `T1059_unix_shell_execution` | CRITICAL | T1059.004 | Command & Scripting: Unix Shell | ✅ |
| `T1059_unix_shell_execution` | CRITICAL | T1609 | Container Administration Command | ✅ |
| `T1611_escape_to_host_ns` | CRITICAL | T1611 | Escape to Host — unknown mount namespace | ✅ |
| `T1611_escape_to_host_fs` | CRITICAL | T1611 | Escape to Host — host reads container overlay2 | ✅ |
| `T1611_escape_to_host_proc` | HIGH | T1611 | Escape to Host — container reads /proc/1/ | ✅ |
| `T1105_ingress_tool_transfer` (nc/ncat) | HIGH | T1095 | Non-App Layer Protocol — binary in container¹ | ✅ |
| `T1105_ingress_tool_transfer` (wget) | HIGH | T1105 | Ingress Tool Transfer — binary in container¹ | ✅ |
| `T1552_004_private_keys` /root/.ssh/ /home/.ssh/ | CRITICAL | T1552.004 | Unsecured Credentials: Private Keys — SSH dirs | ✅ |
| `T1552_004_private_keys` .key/id_rsa/.pem | HIGH | T1552.004 | Unsecured Credentials: Private Keys — key files | ✅ |
| `T1552_001_credentials_in_files` | HIGH | T1552.001 | Unsecured Credentials: Credentials in Files | ✅ |
| `T1003_008_os_credential_dumping` | HIGH | T1003.008 | OS Credential Dumping: /etc/shadow | ✅ |
| `T1082_system_info_discovery` | MEDIUM | T1082 | System Information Discovery | ✅ |
| `T1036_masquerading` | HIGH | T1036 | Masquerading — binary running from /tmp, /dev/shm | ✅ |
| `T1053_003_scheduled_task_cron` | HIGH | T1053.003 | Scheduled Task/Job: Cron | ✅ |
| `T1070_003_clear_command_history` | MEDIUM | T1070.003 | Indicator Removal: Clear Command History | ✅ |
| `T1613_container_resource_discovery` | HIGH | T1613 | Container and Resource Discovery | ✅ |
| `T1041_exfiltration_over_c2` | HIGH | T1041 | Exfiltration Over C2 Channel | ✅ |
| `T1041_exfiltration_over_c2` | HIGH | T1048 | Exfiltration Over Alt Protocol | ✅ |
| `T1059_scripting_interpreter` | HIGH | T1059 | Command & Scripting Interpreter | 🔲 needs parent-process context |
| `T1046_network_service_scanning` | HIGH | T1046 | Network Service Scanning | 🔲 needs stateful burst detection |

¹ Detection fires on binary presence in container (unexpected tool = signal). Not intent-based.

---

## ATT&CK Coverage by Tactic

### ✅ Covered

| Tactic | Technique | Rule |
|--------|-----------|------|
| Execution | T1059.004 Unix Shell | `T1059_unix_shell_execution` |
| Execution | T1609 Container Admin Command | `T1059_unix_shell_execution` |
| Privilege Escalation | T1611 Escape to Host (namespace) | `T1611_escape_to_host_ns` |
| Privilege Escalation | T1611 Escape to Host (overlay2) | `T1611_escape_to_host_fs` |
| Privilege Escalation | T1611 Escape to Host (/proc/1/) | `T1611_escape_to_host_proc` |
| Defense Evasion | T1036 Masquerading | `T1036_masquerading` |
| Defense Evasion | T1070.003 Clear Command History | `T1070_003_clear_command_history` |
| Credential Access | T1003.008 OS Credential Dumping | `T1003_008_os_credential_dumping` |
| Credential Access | T1552.004 Private Keys (dirs) | `T1552_004_private_keys` |
| Credential Access | T1552.004 Private Keys (files) | `T1552_004_private_keys` |
| Credential Access | T1552.001 Credentials in Files | `T1552_001_credentials_in_files` |
| Discovery | T1082 System Info Discovery | `T1082_system_info_discovery` |
| Discovery | T1613 Container Resource Discovery | `T1613_container_resource_discovery` |
| Persistence | T1053.003 Scheduled Task: Cron | `T1053_003_scheduled_task_cron` |
| Command & Control | T1095 Non-App Layer Protocol | `T1105_ingress_tool_transfer` |
| Command & Control | T1105 Ingress Tool Transfer | `T1105_ingress_tool_transfer` |
| Exfiltration | T1041 Exfil Over C2 Channel | `T1041_exfiltration_over_c2` |
| Exfiltration | T1048 Exfil Over Alt Protocol | `T1041_exfiltration_over_c2` |

### 🔲 Phase 2 — Require Stateful Detection

| Tactic | Technique | Rule | Blocker |
|--------|-----------|------|---------|
| Execution | T1059 Scripting Interpreter | `T1059_scripting_interpreter` | Needs parent-process context — high FP risk on Python services |
| Discovery | T1046 Network Service Scan | `T1046_network_service_scanning` | Needs sliding window burst counter across events |

### ❌ Out of Scope

| Tactic | Technique | Why Not Covered |
|--------|-----------|----------------|
| Initial Access | T1190 Exploit Public-Facing App | Needs WAF or RASP — not detectable via eBPF syscall events |
| Execution | T1610 Deploy Container | Needs container lifecycle events (not in current eBPF hooks) |
| Persistence | T1525 Implant Internal Image | Needs image scanning at build time — not runtime |
| Lateral Movement | T1570 Lateral Tool Transfer | Needs file write events + cross-pod correlation |
| Collection | T1005 Data from Local System | Needs per-service sensitive path policy |
| Impact | T1496 Resource Hijacking | Needs CPU usage anomaly detection |
| Impact | T1485 Data Destruction | Needs unlink/rmdir monitoring |

---

## Response Actions

| Action | Rules | When |
|--------|-------|------|
| `kill_process` | T1059, T1611_fs, T1611_proc, T1552_004, T1552_001, T1003_008, T1105 | CRITICAL/HIGH — kill immediately |
| `none` (alert only) | T1611_ns, T1041, T1036, T1613, T1053, T1070, T1082 | Phase 2 block_ip for T1041; T1611_ns excluded due to Podman FP |

---

## Atomic Red Team Tests

Run via `sudo ./validate.sh` on the GCP Docker VM (covers all 11 tests below).
For GKE: use `kubectl exec` equivalents.

### T1059.004 / T1609 — Unix Shell (`T1059_unix_shell_execution`)

```bash
docker exec order-processor-auth_service bash -c "id"
# Expected: CRITICAL T1059_unix_shell_execution action=kill_process
```

### T1105 / T1095 — Ingress Tool Transfer (`T1105_ingress_tool_transfer`)

```bash
docker exec order-processor-auth_service nc -w 2 1.1.1.1 80
# Expected: HIGH T1105_ingress_tool_transfer
```

### T1003.008 — OS Credential Dumping (`T1003_008_os_credential_dumping`)

```bash
docker exec order-processor-auth_service cat /etc/shadow
# Expected: HIGH T1003_008_os_credential_dumping action=kill_process
```

### T1552.004 — Private Keys (`T1552_004_private_keys`)

```bash
docker cp /tmp/id_rsa order-processor-auth_service:/tmp/id_rsa
docker exec order-processor-auth_service cat /tmp/id_rsa
# Expected: HIGH T1552_004_private_keys action=kill_process
```

### T1041 / T1048 — Exfiltration Over C2 (`T1041_exfiltration_over_c2`)

```bash
docker exec order-processor-auth_service python3 -c \
  "import socket; s=socket.socket(); s.settimeout(2); s.connect(('8.8.8.8',80)); s.close()"
# Expected: HIGH T1041_exfiltration_over_c2
```

### T1611 — Escape to Host / overlay2 (`T1611_escape_to_host_fs`)

```bash
MERGED=$(docker inspect order-processor-auth_service --format '{{.GraphDriver.Data.MergedDir}}')
cat "${MERGED}/etc/hostname"
# Expected: CRITICAL T1611_escape_to_host_fs action=kill_process
```

### T1082 — System Info Discovery (`T1082_system_info_discovery`)

```bash
docker exec order-processor-auth_service cat /etc/passwd
# Expected: MEDIUM T1082_system_info_discovery
```

### T1036 — Masquerading (`T1036_masquerading`)

```bash
docker exec order-processor-auth_service cp /bin/cat /tmp/sshd
docker exec order-processor-auth_service /tmp/sshd /etc/hostname
# Expected: HIGH T1036_masquerading comm=/tmp/sshd
```

### T1053.003 — Cron (`T1053_003_scheduled_task_cron`)

```bash
echo "* * * * * root /tmp/evil" > /tmp/test_crontab
docker cp /tmp/test_crontab order-processor-auth_service:/etc/crontab
docker exec order-processor-auth_service cat /etc/crontab
# Expected: HIGH T1053_003_scheduled_task_cron
```

### T1070.003 — Clear Command History (`T1070_003_clear_command_history`)

```bash
echo "rm -rf /important" > /tmp/hist
docker cp /tmp/hist order-processor-auth_service:/tmp/.bash_history
docker exec order-processor-auth_service cat /tmp/.bash_history
# Expected: MEDIUM T1070_003_clear_command_history
```

---

## Validation Script

```bash
sudo ./validate.sh   # runs all 11 tests on Docker VM
```

All 11 tests validated on GCP Docker VM (`instance-20260318-023006`) as of 2026-06-03.
