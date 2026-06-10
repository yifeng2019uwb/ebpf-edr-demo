# ebpf-edr-demo

eBPF-based runtime security monitor for containerized workloads. Detects and responds to threats at the kernel level — no agent inside containers, no application changes required.

Monitors two target workloads:
- **order-processor** — cloud-native microservices on GCP Docker VM
- **health-ai** — healthcare AI microservices on GKE

![eBPF EDR Live Alert Dashboard — GKE multi-service alerts](snapshots/Screenshot%202026-06-09%20at%207.59.46%20PM.png)

---

## How It Works

Three eBPF programs attach to kernel hooks and stream events via ring buffer to a Go userspace pipeline:

```
KERNEL
──────────────────────────────────────────────────────────────────────
execsnoop            lsm-file              lsm-connect
sys_enter_execve     lsm/file_open         lsm/socket_connect
     │                     │                     │
     └─────────────────────┴─────────────────────┘
                           │  ring buffer
USERSPACE (Go)
──────────────────────────────────────────────────────────────────────
Enricher
  mnt_ns_id → WorkloadIdentity (service / pod / namespace / cluster)
                           │
Detector
  apply MITRE-mapped detection rules → Alert
                           │
Responder                                        ← response actions
  kill_process (SIGKILL)                         ← process + file rules
  block_ip (LPMTrie → LSM -EPERM)               ← network rules
                           │
AlertHandler
  ├── stdout + local file      (always-on)
  ├── Google Cloud Logging     (structured JSON, centralized, 365-day retention)
  └── Pub/Sub edr-alerts       (real-time stream, <1s latency)
       └── Alert Router → WebSocket → browser dashboard
```

`lsm/file_open` fires for every file open regardless of syscall variant (open, openat, openat2, io_uring), catching busybox, glibc, musl, and all container runtimes uniformly.

---

## Environments

| Environment   | Host OS      | Kernel | Runtime  | Workload              |
|---------------|--------------|--------|----------|-----------------------|
| Docker VM     | Debian 12    | 6.1    | Docker   | order-processor (8 containers) |
| GKE DaemonSet | Ubuntu 24.04 | 6.8    | K8s      | health-ai (4 services) |

---

## Detection Rules

All rules follow MITRE ATT&CK naming. Rules marked with a response action are actively enforced.

### Process Events (execsnoop)

| Rule | MITRE | Severity | Response | Trigger |
|------|-------|----------|----------|---------|
| `T1059_unix_shell_execution` | T1059.004 · T1609 | CRITICAL | kill_process | Shell spawned inside container |
| `T1105_ingress_tool_transfer` | T1105 · T1095 | HIGH | kill_process | `nc`, `wget` executed in container |
| `T1611_escape_to_host_ns` | T1611 | CRITICAL | — | Process in unrecognized mount namespace |
| `T1036_masquerading` | T1036 | HIGH | — | Binary running from `/tmp`, `/dev/shm` |
| `T1613_container_resource_discovery` | T1613 | HIGH | — | `kubectl`, `docker` run inside container |

### File Events (lsm-file)

| Rule | MITRE | Severity | Response | Trigger |
|------|-------|----------|----------|---------|
| `T1611_escape_to_host_fs` | T1611 | CRITICAL | kill_process | Host reads container overlay filesystem |
| `T1611_escape_to_host_proc` | T1611 | HIGH | — | Container reads `/proc/1/` |
| `T1552_004_private_keys` | T1552.004 | CRITICAL/HIGH | kill_process | SSH key dirs or `.key`/`id_rsa` files |
| `T1552_001_credentials_in_files` | T1552.001 | HIGH | kill_process | `.env`, `/run/secrets/` |
| `T1003_008_os_credential_dumping` | T1003.008 | HIGH | kill_process | `/etc/shadow` |
| `T1082_system_info_discovery` | T1082 | MEDIUM | — | `/etc/passwd`, `/etc/group` |
| `T1053_003_scheduled_task_cron` | T1053.003 | HIGH | — | Container touches cron config |
| `T1070_003_clear_command_history` | T1070.003 | MEDIUM | — | Container touches shell history |

### Network Events (lsm-connect)

| Rule | MITRE | Severity | Response | Trigger |
|------|-------|----------|----------|---------|
| `T1041_exfiltration_over_c2` | T1041 · T1048 | HIGH | block_ip | Unauthorized external connection |

---

## Validation

### Docker VM — 11/11 pass

All 11 attack tests distributed across `auth_service`, `user_service`, `order_service`, `insights_service`.

| Test | Rule | Severity |
|------|------|----------|
| Shell spawn | `T1059_unix_shell_execution` | CRITICAL |
| Network tool | `T1105_ingress_tool_transfer` | HIGH |
| Read `/etc/shadow` | `T1003_008_os_credential_dumping` | HIGH |
| Read SSH private key | `T1552_004_private_keys` | HIGH |
| Unauthorized external connect | `T1041_exfiltration_over_c2` | HIGH |
| Authorized connect (allowlisted) | — | no alert |
| Host reads container filesystem | `T1611_escape_to_host_fs` | CRITICAL |
| Read `/etc/passwd` | `T1082_system_info_discovery` | MEDIUM |
| Binary masquerading from `/tmp` | `T1036_masquerading` | HIGH |
| Container touches cron config | `T1053_003_scheduled_task_cron` | HIGH |
| Container touches shell history | `T1070_003_clear_command_history` | MEDIUM |

### GKE — 11/11 pass

Tests distributed across all 4 health-ai services — confirms eBPF resolver maps mount-namespace IDs correctly for every pod.

| Test | Service | Rule | Severity |
|------|---------|------|----------|
| Shell spawn | provider-service | `T1059_unix_shell_execution` | CRITICAL |
| Read `/etc/shadow` | auth-service | `T1003_008_os_credential_dumping` | HIGH |
| Unauthorized external connect | gateway | `T1041_exfiltration_over_c2` | HIGH |
| Allowlist check | ai-service | — | no alert |
| No FP from normal traffic | all services | — | no alert |
| Read SSH private key | provider-service | `T1552_004_private_keys` | CRITICAL |
| Network tool | auth-service | `T1105_ingress_tool_transfer` | HIGH |
| Read `/etc/passwd` | gateway | `T1082_system_info_discovery` | MEDIUM |
| Reverse shell | auth-service | `T1059` + `T1041` | CRITICAL + HIGH |
| `.env` credentials file | provider-service | `T1552_001_credentials_in_files` | HIGH |
| Container mgmt tool | gateway | `T1613_container_resource_discovery` | HIGH |

![Docker VM validation](snapshots/monitor-dashboardWithResponse.png)

---

## How to Run

**Docker VM:**
```bash
sudo env GOOGLE_CLOUD_PROJECT=ebpfagent ./ebpf-edr --runtime=docker
sudo ./validate.sh        # 11 attack tests across 4 services
```

**GKE:**
```bash
cd kubernetes/pulumi && pulumi up
cd kubernetes && ./deploy.sh all
./validate-gke.sh         # 11 attack tests across 4 services
```

**Alert Router (Mac):**
```bash
make run-alert-router
# Open: http://localhost:8888
```

---

## Documentation

| Doc | Description |
|-----|-------------|
| [MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md) | Full ATT&CK technique mapping — 14 rules, all severities and response actions |
| [DETECTION-POLICY.md](docs/DETECTION-POLICY.md) | Whitelist rationale and per-environment noise policy |
| [VALIDATION.md](docs/VALIDATION.md) | Docker VM — 13 attack test cases with expected alerts |
| [VALIDATION-GKE.md](docs/VALIDATION-GKE.md) | GKE — 11 attack test cases distributed across services |
| [NOTES.md](docs/NOTES.md) | Development notes, debugging reference, key technical decisions |
| [REPORT.md](docs/REPORT.md) | Full project report — architecture, implementation, results |
