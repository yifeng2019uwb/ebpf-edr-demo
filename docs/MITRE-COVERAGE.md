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

## Validation

How each technique is exercised (attack commands, expected alerts, the Docker + DO K8s test
matrices) lives in [VALIDATION.md](VALIDATION.md) — the automated scripts `validate.sh` (Docker) and
`validate-do-k8s.sh` (K8s) are the source of truth.

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
