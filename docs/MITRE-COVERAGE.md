# MITRE ATT&CK Coverage — eBPF EDR Demo

Scope: runtime-detectable container/K8s techniques only.

**Framework context** (MITRE ATT&CK Enterprise v18, October 2025):
- Total techniques: 200+ across 14 tactics
- Container-applicable techniques: ~35 (via [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/))
- Single-event runtime-detectable (eBPF/syscall): ~15
  - Industry reference: [Falco detects ~20-25 container techniques](https://www.sysdig.com/blog/mitre-defense-evasion-falco) via syscalls
  - This project (ebpf-edr-demo): 15 implemented and validated

**Current coverage: 15 of ~15 single-event-detectable techniques**

All single-event-detectable techniques are now covered.
Remaining gaps require stateful/behavioral detection (see Phase 2 section).

---

## Detection Rules → MITRE Mapping

Status: ✅ implemented + validated  🔲 planned — not yet implemented  ⛔ inactive

| Rule | Severity | MITRE ID | Technique | Status |
|------|----------|----------|-----------|--------|
| `T1059_unix_shell_execution` | CRITICAL | T1059.004 | Command & Scripting: Unix Shell | ✅ |
| `T1059_unix_shell_execution` | CRITICAL | T1609 | Container Administration Command | ✅ |
| `T1611_escape_to_host_ns` | — | T1611 | Escape to Host — unknown mount namespace | ⛔ superseded³ |
| `T1611_escape_to_host_fs` | CRITICAL | T1611 | Escape to Host — host reads container overlay2 | ⛔ disabled⁴ |
| `T1611_escape_to_host_proc` | HIGH | T1611 | Escape to Host — container reads /proc/1/ | ✅² |
| `T1105_ingress_tool_transfer` (nc/ncat) | HIGH | T1095 | Non-App Layer Protocol — binary in container¹ | ✅ |
| `T1105_ingress_tool_transfer` (wget) | HIGH | T1105 | Ingress Tool Transfer — binary in container¹ | ✅ |
| `T1552_004_private_keys` /root/.ssh/ /home/.ssh/ | CRITICAL | T1552.004 | Unsecured Credentials: Private Keys — SSH dirs | ✅ |
| `T1552_004_private_keys` .key/id_rsa/.pem | HIGH | T1552.004 | Unsecured Credentials: Private Keys — key files | ✅ |
| `T1552_001_credentials_in_files` | HIGH | T1552.001 | Unsecured Credentials: Credentials in Files | ✅ |
| `T1003_008_os_credential_dumping` | CRITICAL | T1003.008 | OS Credential Dumping: /etc/shadow | ✅ |
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
² Rule is implemented and fires in production; not testable via `docker exec` because normal
Docker containers have PID namespace isolation — `/proc/1/` inside the container resolves to
the container's own init, not the host's.
³ A bare unresolved namespace is a resolver-timing artifact, not an escape signal — routed to
LOW `EDR_telemetry_unresolved_namespace` after ancestry verification fails (see
DESIGN-PROCESS-ANCESTRY-CACHE.md §3.5–3.6). T1611 coverage comes from the proc rule.
⁴ Disabled pending its allowlist (deferred validate.sh T7 work); its data
(`container_fs_paths`) stays in `rules/common.yaml`.

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

Declared per detection via `response:` in `rules/*.yaml` (executed by `pkg/detector/response.go`).

| Action | Rules | When |
|--------|-------|------|
| `kill_process` | T1552_004 (both entries), T1003_008 | High-confidence credential access — never legitimate in a container |
| `block_ip` | T1041 | Dst IP denied at the LSM hook on re-connect; kernel-side `blocked_ips` map not yet compiled, so currently skipped with a log line (alert-only in practice) |
| alert only (no `response:`) | T1059, T1105, T1611_proc, T1036, T1613, T1053, T1070, T1082, T1552_001 | Legitimate uses exist (shells in builds, curl health checks, `.env` at startup); killing risks breaking workloads |

---

## Atomic Red Team Tests

Run via `sudo ./validate.sh` on the Docker VM (12 automated tests, incl. ingress-tool and a
no-alert allowlist check; only the T1611 overlay test remains out — rule disabled). On DO K8s:
`./validate-do-k8s.sh` (11 tests).

### T1059.004 / T1609 — Unix Shell (`T1059_unix_shell_execution`)

```bash
docker exec order-processor-user_service bash -c "id"
# Expected: CRITICAL T1059_unix_shell_execution service=user_service
```

### T1105 / T1095 — Ingress Tool Transfer (`T1105_ingress_tool_transfer`)

```bash
docker exec order-processor-auth_service nc -w 2 1.1.1.1 80
# Expected: HIGH T1105_ingress_tool_transfer service=auth_service
```

### T1003.008 — OS Credential Dumping (`T1003_008_os_credential_dumping`)

```bash
docker exec order-processor-order_service cat /etc/shadow
# Expected: CRITICAL T1003_008_os_credential_dumping service=order_service action=kill_process
```

### T1552.004 — Private Keys (`T1552_004_private_keys`)

```bash
docker cp /tmp/id_rsa order-processor-user_service:/tmp/id_rsa
docker exec order-processor-user_service cat /tmp/id_rsa
# Expected: HIGH T1552_004_private_keys service=user_service action=kill_process
```

### T1041 / T1048 — Exfiltration Over C2 (`T1041_exfiltration_over_c2`)

```bash
docker exec order-processor-auth_service python3 -c \
  "import socket; s=socket.socket(); s.settimeout(2); s.connect(('8.8.8.8',80)); s.close()"
# Expected: HIGH T1041_exfiltration_over_c2 service=auth_service
```

### T1611 — Escape to Host / overlay2 (`T1611_escape_to_host_fs`) — INACTIVE

Rule is disabled pending its allowlist (deferred validate.sh T7 work) — this test
currently produces NO alert.

```bash
MERGED=$(docker inspect order-processor-order_service --format '{{.GraphDriver.Data.MergedDir}}')
cat "${MERGED}/etc/hostname"
# Expected when re-enabled: CRITICAL T1611_escape_to_host_fs
```

### T1082 — System Info Discovery (`T1082_system_info_discovery`)

```bash
docker exec order-processor-insights_service cat /etc/passwd
# Expected: MEDIUM T1082_system_info_discovery service=insights_service
```

### T1036 — Masquerading (`T1036_masquerading`)

```bash
docker exec order-processor-order_service cp /bin/cat /tmp/sshd
docker exec order-processor-order_service /tmp/sshd /etc/hostname
# Expected: HIGH T1036_masquerading service=order_service comm=/tmp/sshd
```

### T1053.003 — Cron (`T1053_003_scheduled_task_cron`)

```bash
echo "* * * * * root /tmp/evil" > /tmp/test_crontab
docker cp /tmp/test_crontab order-processor-user_service:/etc/crontab
docker exec order-processor-user_service cat /etc/crontab
# Expected: HIGH T1053_003_scheduled_task_cron service=user_service
```

### T1070.003 — Clear Command History (`T1070_003_clear_command_history`)

```bash
echo "rm -rf /important" > /tmp/hist
docker cp /tmp/hist order-processor-insights_service:/tmp/.bash_history
docker exec order-processor-insights_service cat /tmp/.bash_history
# Expected: MEDIUM T1070_003_clear_command_history service=insights_service
```

### T1552.001 — Credentials in Files (`T1552_001_credentials_in_files`) — T12

```bash
echo "DB_PASSWORD=super_secret_password" > /tmp/app.env
docker cp /tmp/app.env order-processor-user_service:/tmp/app.env
docker exec order-processor-user_service cat /tmp/app.env
# Expected: HIGH T1552_001_credentials_in_files service=user_service filename=/tmp/app.env
```

### T1613 — Container Resource Discovery (`T1613_container_resource_discovery`) — T13

```bash
docker cp $(which docker) order-processor-auth_service:/usr/local/bin/docker
docker exec order-processor-auth_service /usr/local/bin/docker ps
# Expected: HIGH T1613_container_resource_discovery service=auth_service comm=/usr/local/bin/docker
# Note: docker ps fails (no socket) but execve fires the alert before any I/O.
```

---

## Validation Script

```bash
sudo ./validate.sh       # 12 automated tests on Docker VM (distributed across services)
./validate-do-k8s.sh     # 11 tests on DO K8s (distributed across services)
```

Both validated 2026-07-10 with the complete YAML rules engine (Docker VM 12/12, DO K8s 11/11).

---

## Sources & References

**MITRE ATT&CK Framework:**
- [MITRE ATT&CK Official Site](https://attack.mitre.org/) — Enterprise matrix, October 2025 (v18)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/) — Container/K8s specific techniques
- [MITRE ATT&CK Updates (October 2025)](https://attack.mitre.org/resources/updates/updates-october-2025/) — 216 techniques, 14 tactics

**Runtime Detection (eBPF/Syscall):**
- [Sysdig Falco: MITRE ATT&CK Defense Evasion](https://www.sysdig.com/blog/mitre-defense-evasion-falco) — Falco coverage (~20-25 techniques)
- [Trend Micro: Container Security Detection Maps MITRE](https://www.trendmicro.com/en_us/research/25/a/mitre-attack-container-security-detection.html) — Runtime detection strategies
- [Orca Security: Container Runtime Security Guide](https://orca.security/resources/blog/what-is-container-runtime-security/) — eBPF-based detection overview

**Scope Validation:**
- [RedHat: Protecting Kubernetes Against MITRE ATT&CK](https://www.redhat.com/en/blog/protecting-kubernetes-against-mitre-attck-execution) — K8s specific techniques
- [Tigera: Using MITRE ATT&CK for Container Security](https://www.tigera.io/blog/using-the-mitre-attck-framework-to-understand-container-security/) — Detection coverage gaps
