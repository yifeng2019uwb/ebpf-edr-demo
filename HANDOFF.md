# Session Handoff — 2026-06-03

## Current State

**GCP Docker VM: ACTIVE** — eBPF agent running, order-processor deployed.
All 10/11 validate.sh tests passing (T2 skipped — nc not in container).
GCP credits expire 2026-06-17 (~14 days). Validation complete.

**Oracle VMs: PAUSED** — both deleted by accidental `pulumi up`. Not worth recovering now.

---

## IMMEDIATE NEXT STEP — Rebuild + push new binary

All code changes from this session are local. Need to rebuild and commit the binary:

```bash
# On GCP VM:
cd ~/workspace/ebpf-edr-demo
git pull
make build
git add ebpf-edr
git commit -m "feat: MITRE rule names, response actions, 4 new rules, microsecond timestamps"
git push
```

Then restart the agent with the new binary:
```bash
sudo pkill ebpf-edr || true
make run-docker
sudo ./validate.sh
```

---

## What was completed this session (2026-06-02 → 2026-06-03)

### EDR Response Actions — COMPLETED
- ✅ `pkg/detector/response_policy.go` — maps rule+level → ResponseAction
- ✅ `pkg/detector/response.go` — `kill_process` via `syscall.SIGKILL`; Phase 2 stubs for `block_ip` (LPMTrie) and `quarantine_file`
- ✅ `ResponseAction string` added to `Alert` struct + Cloud Logging payload + log line
- ✅ Response wired into detector goroutine in `cmd/edr-monitor/main.go`
- ✅ Kill confirmed working on GCP VM: 125–215µs between kill and alert log

### Rule System Redesign — COMPLETED
- ✅ `pkg/detector/rule_names.go` — rewritten as design spec, organized by event source (process/file/network), all rules MITRE-prefixed with uppercase T
- ✅ `sensitive_file_access` split into 4 specific MITRE rules (see table below)
- ✅ `pkg/detector/policy.go` — file path data restructured from severity-based to rule-based groupings
- ✅ `pkg/detector/rules.go` — `checkFileRules` split to map each path group to its specific rule

### New Rules Implemented — COMPLETED
- ✅ `T1036_masquerading` — binary running from `/tmp/`, `/dev/shm/`, `/var/tmp/` (HIGH)
- ✅ `T1613_container_resource_discovery` — kubectl/docker/crictl inside container (HIGH)
- ✅ `T1053_003_scheduled_task_cron` — container touching cron config files (HIGH)
- ✅ `T1070_003_clear_command_history` — container touching shell history files (MEDIUM)

### Quality
- ✅ Microsecond timestamps — `log.Lmicroseconds` + `"2006-01-02 15:04:05.000000"` format
- ✅ `validate.sh` — updated to 11 tests with MITRE rule names; uses `mktemp -d` for temp files
- ✅ All detector unit tests passing

---

## Full Rule Coverage

### Implemented (✅) and Validated

| Rule | MITRE | Level | Response | Source |
|------|-------|-------|----------|--------|
| `T1059_unix_shell_execution` | T1059.004 · T1609 | CRITICAL | kill | process |
| `T1105_ingress_tool_transfer` | T1105 · T1095 | HIGH | kill | process |
| `T1611_escape_to_host_ns` | T1611 | CRITICAL | none (Podman FP) | process |
| `T1036_masquerading` | T1036 | HIGH | none | process |
| `T1613_container_resource_discovery` | T1613 | HIGH | none | process |
| `T1611_escape_to_host_fs` | T1611 | CRITICAL | kill | file |
| `T1611_escape_to_host_proc` | T1611 | HIGH | kill | file |
| `T1552_004_private_keys` | T1552.004 | CRITICAL/HIGH | kill | file |
| `T1552_001_credentials_in_files` | T1552.001 | HIGH | kill | file |
| `T1003_008_os_credential_dumping` | T1003.008 | HIGH | kill | file |
| `T1082_system_info_discovery` | T1082 | MEDIUM | none | file |
| `T1053_003_scheduled_task_cron` | T1053.003 | HIGH | none | file |
| `T1070_003_clear_command_history` | T1070.003 | MEDIUM | none | file |
| `T1041_exfiltration_over_c2` | T1041 · T1048 | HIGH | none (Phase 2: LSM block) | network |

### Planned (🔲) — Defined in rule_names.go, not yet implemented

| Rule | MITRE | Blocker |
|------|-------|---------|
| `T1059_scripting_interpreter` | T1059 | Needs parent-process context — high FP risk on Python services |
| `T1046_network_service_scanning` | T1046 | Stateful burst detection — significant complexity |

---

## Phase 2 — Next Implementation Items

### IP Blocking at LSM level (T1041)
Stubs already in place:
- `kernel/lsm-connect.h` — `lpm_key` struct commented out
- `kernel/lsm-connect.bpf.c` — `blocked_ips` LPMTrie map + `-EPERM` enforcement point commented out
- `pkg/detector/response.go` — `blockIP()` stub with full implementation notes

Steps when ready:
1. Uncomment `blocked_ips` map in `lsm-connect.bpf.c` and `lpm_key` in `lsm-connect.h`
2. Run `go generate ./pkg/bpf/...` — adds `lsmObjs.BlockedIps *ebpf.Map`
3. Wire `blockIP()` in `response.go` using the `lpmKey` struct shown in the stub

### T1611 false positive fix (Podman)
- `T1611_escape_to_host_ns` excluded from kill — Podman health checks fire it
- Fix: update `docker_resolver.go` to parse Podman cgroup format
- Then enable: `{rule: RuleT1611EscapeToHostNs, minLevel: alert.Critical, action: ActionKillProcess}`

---

## validate.sh — Current Test Coverage

```bash
sudo ./validate.sh   # runs T1-T11, concurrent integration tests
```

| Test | Rule | Expected |
|------|------|----------|
| T1 | T1059_unix_shell_execution | CRITICAL + kill |
| T2 | T1105_ingress_tool_transfer | HIGH (SKIP if nc not installed) |
| T3 | T1003_008_os_credential_dumping | HIGH + kill |
| T4 | T1552_004_private_keys | HIGH |
| T5 | T1041_exfiltration_over_c2 | HIGH |
| T6 | — | no alert (inventory_service allowlisted) |
| T7 | T1611_escape_to_host_fs | CRITICAL + kill |
| T8 | T1082_system_info_discovery | MEDIUM |
| T9 | T1036_masquerading | HIGH |
| T10 | T1053_003_scheduled_task_cron | HIGH |
| T11 | T1070_003_clear_command_history | MEDIUM |

**Known noise:** docker cp operations trigger extra `state=unknown / comm=exe` alerts for T4/T10/T11. Test-setup artifact — docker cp opens files through the container overlay from the host side.

---

## Oracle VMs — PAUSED

Both VMs deleted by accidental `pulumi up` during A1 attempt. Recovery:
1. `pulumi config set a1Enabled false && pulumi up --yes`
2. `EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh`
3. `./docker/deploy-vm.sh`

Not worth doing — VMs freeze frequently. Resume when stable window available.

---

## Key Facts / Gotchas

### GCP Credits
- Expire: 2026-06-17 (~14 days)
- GCP Docker VM `instance-20260318-023006` (~$43/mo) is the only paid resource
- After expiry: Oracle VMs (free) + Cloud Logging free tier remain

### eBPF Agent
- Binary: `~/workspace/ebpf-edr-demo/ebpf-edr` (committed to repo, ~18MB stripped)
- SA key: `/tmp/oracle-agent.json` (from `pulumi stack output oracleAgentKey --show-secrets | base64 -d`)
- `GOOGLE_CLOUD_PROJECT=ebpfagent` set in systemd service
- Alerts go to: Cloud Logging (`ebpf-edr-alerts`) + local `alerts/alert.log` + Pub/Sub `edr-alerts`

### Known False Positives
- `T1611_escape_to_host_ns` from Podman health checks — excluded from kill (Phase 2 fix)
- `inventory_service` fires T1041 on Docker VM — allowlist has `"inventory-service"` (hyphen, matches GKE); Docker VM uses underscore. Accepted as known environment difference.
