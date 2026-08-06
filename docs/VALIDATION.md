# Validation

Two automated scripts are the source of truth — they carry the exact attack commands and expected
alerts, self-documented inline:

- **`validate.sh`** — Docker VM, 12 tests, run against the order-processor stack.
- **`validate-do-k8s.sh`** — DigitalOcean K8s, 11 tests (V2–V12), run against the health-ai stack.

This doc is the map: how to run them, what each test covers, and how results are read. When a command
changes, it changes in the script, not here.

## How to run

```bash
sudo ./validate.sh                          # Docker VM (agent + order-processor containers running)
./validate-do-k8s.sh [--context <ctx>]      # DO K8s (agent DaemonSet + health-ai deployed)
```

Both run attack cases while normal traffic runs concurrently, validating two things at once:
**detection** (each rule fires at the right severity/response) and **no false positives** (normal
traffic produces no CRITICAL/HIGH). Each prints `PASS` / `FAIL` / `SKIP` and a summary.

Alerts are matched by tailing the alert log (Docker) or `kubectl logs` (K8s), scoped to a timestamp
captured at test start — so a run never matches stale alerts from a previous run.

## Docker matrix — `validate.sh`

Tests are spread across services to confirm the resolver identifies each one.

| # | Technique | Service | Expected | Response |
|---|-----------|---------|----------|----------|
| T1 | T1059.004 / T1609 shell spawn | user_service | CRITICAL `T1059_unix_shell_execution` | — |
| T2 | T1003.008 `/etc/shadow` | order_service | CRITICAL `T1003_008_os_credential_dumping` | kill_process |
| T3 | T1552.004 SSH key (`/tmp/id_rsa`) | user_service | HIGH `T1552_004_private_keys` | kill_process |
| T4 | T1041 / T1048 external connect + block | auth_service | HIGH `T1041_exfiltration_over_c2` | block_ip |
| T5 | T1082 `/etc/passwd` | insights_service | MEDIUM `T1082_system_info_discovery` | — |
| T6 | T1036 masquerade (`/tmp/sshd`) | order_service | HIGH `T1036_masquerading` | — |
| T7 | T1053.003 `/etc/crontab` | user_service | HIGH `T1053_003_scheduled_task_cron` | — |
| T8 | T1070.003 `/tmp/.bash_history` | insights_service | MEDIUM `T1070_003_clear_command_history` | — |
| T9 | T1552.001 `.env` (`/tmp/app.env`) | user_service | HIGH `T1552_001_credentials_in_files` | — |
| T10 | T1613 container-mgmt tool (docker) | auth_service | HIGH `T1613_container_resource_discovery` | — |
| T11 | T1105 / T1095 ingress tool (wget) | auth_service | HIGH `T1105_ingress_tool_transfer` | — |
| T12 | allowlist check — external connect | inventory_service | **no alert** (T1041 suppressed) | — |

Behaviors worth knowing when reading the script:
- **T1 uses `docker exec -t`** — T1059 now gates on `tty_required`, so an attached pseudo-TTY is
  needed to fire (a non-interactive `sh -c` is intentionally *not* flagged).
- **File tests (T3, T7, T8, T9) stage the file with `docker cp`, then `docker exec cat`** — creating
  it via a shell would spawn bash (T1059) and, for kill-response rules, get killed before the write.
- **T11 uses wget** (a `download_tools` suffix match) staged via `docker cp` — nc/ncat would need a
  reverse-shell flag (`-e`) to fire under the tightened rule, so wget is the simpler trigger.
- **T4 also verifies kernel blocking**: reconnect to the same IP must return `EPERM`, a private IP
  must not. (Only effective once the `blocked_ips` map is compiled — otherwise alert-only.)

## K8s matrix — `validate-do-k8s.sh` (namespace `health-ai`)

| # | Technique | Service | Expected |
|---|-----------|---------|----------|
| V2 | T1059 shell spawn | provider-service | CRITICAL `T1059_unix_shell_execution` |
| V3 | T1003.008 `/etc/shadow` | auth-service | CRITICAL `T1003_008_os_credential_dumping` (killed) |
| V4 | T1041 external connect (8.8.8.8) | gateway | HIGH `T1041_exfiltration_over_c2` |
| V5 | allowlist passive check | ai-service | **no HIGH** for allowed external connect |
| V6 | normal-traffic FP check | gateway | **no CRITICAL** from real traffic |
| V7 | T1552.004 SSH key (`/root/.ssh/id_rsa`) | provider-service | CRITICAL `T1552_004_private_keys` (killed) |
| V8 | T1105 network recon tool (external connect) | auth-service | HIGH `T1041_exfiltration_over_c2` — SKIP if wget/nc absent |
| V9 | T1082 `/etc/passwd` | gateway | MEDIUM `T1082_system_info_discovery` |
| V10 | reverse shell | auth-service | CRITICAL `T1059` **and** HIGH `T1041` |
| V11 | T1552.001 `.env` (`/tmp/app.env`) | provider-service | HIGH `T1552_001_credentials_in_files` |
| V12 | T1613 container-mgmt tool (kubectl) | gateway | HIGH `T1613_container_resource_discovery` |

## Not automated

- **T1611 host-reads-container-overlay** (`T1611_escape_to_host_fs`) — the rule is disabled pending
  its host allowlist (see HANDOFF deferred issues), so no script exercises it. When re-enabled, the
  manual trigger is a host read of a container's overlay merged dir:

  ```bash
  MERGED=$(docker inspect order-processor-order_service --format '{{.GraphDriver.Data.MergedDir}}')
  cat "${MERGED}/etc/hostname"   # expect (when active): CRITICAL T1611_escape_to_host_fs
  ```

## Out of scope

| Scenario | Why |
|----------|-----|
| SSH login detection | Host-level auth — outside the container threat model |
| Container escape via kernel CVE | Requires a real exploit — impractical to simulate safely |
| Scripting interpreter (`python -c`) | High FP risk on legitimate Python services |
| Network service scanning (burst) | Needs stateful sliding-window detection |
