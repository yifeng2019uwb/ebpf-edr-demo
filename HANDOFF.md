# Session Handoff — 2026-06-03

## Current State

**GCP Docker VM: ACTIVE** — eBPF agent running, all 11 validate.sh tests passing.
**Health-AI GKE Cluster: ACTIVE** — `health-ai-cluster-us-west1` (us-west1-a), eBPF DaemonSet deploying.
GCP credits expire 2026-06-17 (~14 days). Both resources run on project `ebpfagent`.

---

## IMMEDIATE NEXT STEP

eBPF binary rebuild in progress on GCP VM (BPF generated files required Linux for `go generate`).

Once binary is rebuilt and committed:
1. `git pull` on Mac
2. `make docker-push-prebuilt` — push updated image to Artifact Registry
3. `./deploy.sh app` (in `health-ai/kubernetes/`) — restarts DaemonSet with new image
4. `./validate-gke.sh` — expect V2/V5/V6/V8 still pass; V3/V4/V7/V9/V10 should now pass too

---

## What was completed this session (2026-06-03)

### Phase 7 — MITRE Rule Redesign + Response Actions (GCP Docker VM)
- ✅ All rule names renamed to MITRE ATT&CK format (`T1059_unix_shell_execution`, etc.)
- ✅ `sensitive_file_access` split into 4 specific rules: `T1552_004_private_keys`, `T1552_001_credentials_in_files`, `T1003_008_os_credential_dumping`, `T1611_escape_to_host_proc`
- ✅ 4 new rules: `T1036_masquerading`, `T1613_container_resource_discovery`, `T1053_003_scheduled_task_cron`, `T1070_003_clear_command_history`
- ✅ `Responder` struct — `kill_process` (SIGKILL) and `block_ip` (LPMTrie BPF map)
- ✅ `blocked_ips` LPMTrie in `lsm-connect.bpf.c` — pre-TCP EPERM for blocked IPs
- ✅ `validate.sh` — 11 tests passing on Docker VM

### Health-AI GKE Deployment (new this session)
- ✅ `health-ai/kubernetes/pulumi/` — Pulumi Go stack (cluster + SA + Artifact Registry)
- ✅ `health-ai/kubernetes/` — K8s manifests: namespace, configmap, deployment (4 services), service
- ✅ `health-ai/kubernetes/deploy.sh` — build | infra | app | rls | status | all
- ✅ `healthcare-infra/schema/enable-rls.sql` — RLS enabled on all 9 Supabase tables
- ✅ Database: Supabase (external, persistent) — no in-cluster PostgreSQL needed
- ✅ Integration tests passing: `GATEWAY_URL=http://8.229.162.35:8080 ./run-it.sh all`
- ✅ eBPF DaemonSet deploying to health-ai cluster (pending binary rebuild)

### Tooling fixes
- ✅ `Dockerfile` — fixed: was copying `ebpf-edr-demo` (old binary), now copies `ebpf-edr`
- ✅ `Makefile` — added `docker-push-prebuilt` target (skips Go build, uses committed binary)
- ✅ `docs/NOTES.md` — update workflow section: health-ai deploy steps + Mac BPF build caveat
- ✅ `validate-gke.sh` — retargeted for health-ai: MITRE rule names, `health-ai` namespace, `auth-service` target, all values in variables block at top

### validate-gke.sh partial results (old binary)
| Test | Result | Note |
|------|--------|------|
| V2 Shell spawn | ✅ PASS | Process monitor working |
| V3 Shadow read | ❌ FAIL | Old binary — file rules not updated |
| V4 External connect | ❌ FAIL | Old binary — lsm-connect rules not updated |
| V5 ai-service allowlist | ✅ PASS | |
| V6 No FP gateway | ✅ PASS | |
| V7 SSH key | ❌ FAIL | Old binary |
| V8 Network tool | ✅ PASS | Process monitor working |
| V9 /etc/passwd | ❌ FAIL | Old binary |
| V10 Reverse shell | ❌ FAIL | Old binary |

---

## Full Rule Coverage

### Implemented (✅) and Validated on GCP Docker VM

| Rule | MITRE | Level | Response | Source |
|------|-------|-------|----------|--------|
| `T1059_unix_shell_execution` | T1059.004 · T1609 | CRITICAL | kill_process | process |
| `T1105_ingress_tool_transfer` | T1105 · T1095 | HIGH | kill_process | process |
| `T1611_escape_to_host_ns` | T1611 | CRITICAL | none (Podman FP) | process |
| `T1036_masquerading` | T1036 | HIGH | none | process |
| `T1613_container_resource_discovery` | T1613 | HIGH | none | process |
| `T1611_escape_to_host_fs` | T1611 | CRITICAL | kill_process | file |
| `T1611_escape_to_host_proc` | T1611 | HIGH | kill_process | file |
| `T1552_004_private_keys` | T1552.004 | CRITICAL/HIGH | kill_process | file |
| `T1552_001_credentials_in_files` | T1552.001 | HIGH | kill_process | file |
| `T1003_008_os_credential_dumping` | T1003.008 | HIGH | kill_process | file |
| `T1082_system_info_discovery` | T1082 | MEDIUM | none | file |
| `T1053_003_scheduled_task_cron` | T1053.003 | HIGH | none | file |
| `T1070_003_clear_command_history` | T1070.003 | MEDIUM | none | file |
| `T1041_exfiltration_over_c2` | T1041 · T1048 | HIGH | block_ip | network |

### Planned (🔲) — Require Stateful Detection

| Rule | MITRE | Blocker |
|------|-------|---------|
| `T1059_scripting_interpreter` | T1059 | Needs parent-process context — high FP on Python services |
| `T1046_network_service_scanning` | T1046 | Stateful burst detection across events |

---

## Phase 2 — IP Blocking Design Notes

### Repeat-attempt visibility
Once an IP is in `blocked_ips`, subsequent connect attempts are silently denied at the LSM hook — no event emitted, no alert. This is intentional (sensor stays quiet; persistence detection belongs at SIEM layer).

If repeat-attempt visibility is needed:
- **Option A**: `block_counts` BPF hash map, increment on EPERM, poll from Go, emit LOW periodic summary
- **Option B**: Cloud Logging alert policy when `block_ip` appears >N× for same IP in time window

See comments in `kernel/lsm-connect.bpf.c` and `pkg/detector/response.go`.

### Blocked IP lifetime
IPs are blocked until the agent restarts (BPF map cleared on program unload).
`validate.sh` flushes the map via `bpftool map flush` before T5 to ensure repeatability.

---

## Key Facts / Gotchas

### GCP Credits
- Expire: 2026-06-17 (~14 days)
- Resources on `ebpfagent`: Docker VM `instance-20260318-023006` (~$43/mo) + health-ai GKE cluster
- After expiry: Cloud Logging free tier remains; setup docs in each project for redeployment

### eBPF Agent Binary
- `make docker-push` — requires Linux (BPF `go generate` needs clang/libbpf); run on GCP VM
- `make docker-push-prebuilt` — uses committed binary; safe to run on Mac
- After editing `.bpf.c`: run `make rebuild` on GCP VM → commit `pkg/bpf/*_bpfel.go` + `ebpf-edr` → pull on Mac → `make docker-push-prebuilt`

### Health-AI GKE
- Cluster: `health-ai-cluster-us-west1`, namespace: `health-ai`, project: `ebpfagent`
- Gateway: `http://8.229.162.35:8080`
- Pulumi: `health-ai/kubernetes/pulumi/` stack `gke-dev`
- Deploy: `health-ai/kubernetes/deploy.sh [all|build|infra|app|rls|status]`
- Integration tests: `GATEWAY_URL=http://8.229.162.35:8080 ./integration_tests/run-it.sh all`
- Validate eBPF: `./validate-gke.sh` (from ebpf-edr-demo/)
- DB: Supabase (external) — credentials in `health-ai/docker/.env`

### Alert Router (Mac)
- `make run-alert-router` — requires `gcloud auth application-default set-quota-project ebpfagent`
- In-memory only — clears on restart; historical data in Cloud Logging

### Known False Positives
- `T1611_escape_to_host_ns` from Podman health checks — excluded from kill response
- `inventory_service` fires `T1041` on Docker VM — allowlist uses hyphen (`inventory-service`); Docker uses underscore. Accepted environment difference.
- `docker cp` during validate.sh creates `state=unknown / comm=exe` alerts for T4/T10/T11 — test-setup artifact, not real threats.
- `ai-service` makes external Gemini API calls — add to `externalAllowedServices` in `policy.go` if HIGH alerts appear for it on GKE
