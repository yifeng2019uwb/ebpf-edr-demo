# Session Handoff — 2026-06-02

## Current State

**Oracle VMs: DOWN** — both deleted by accidental `pulumi up` during A1 attempt.
Recovering Oracle VMs requires full redeploy (setup-vm.sh + deploy-vm.sh + eBPF install).
Decision: pause Oracle VM work, focus EDR validation on GCP Docker VM (stable).

**GCP Docker VM: ACTIVE** — eBPF agent running, order-processor deployed, validate.sh works.
GCP credits expire 2026-06-17 (~16 days). Complete all validation before then.

---

## NEXT PHASE — EDR Response Actions (new, agreed 2026-06-02)

Design agreed in last session. **NOT YET IMPLEMENTED.**

### What to build

**Loop:** Detect → Block → Alert → Notify

**New files:**
- `pkg/detector/response_policy.go` — maps rule+level → response action
- `pkg/detector/response.go` — response implementations (kill_process)

**Response policy table (agreed):**

| Rule | Min Level | Action | Notes |
|------|-----------|--------|-------|
| shell_spawn_container | CRITICAL | kill_process | RCE — always bad |
| host_reads_container_fs | CRITICAL | kill_process | Container escape |
| sensitive_file_access | CRITICAL | kill_process | SSH key theft |
| sensitive_file_access | HIGH | kill_process | /etc/shadow, .key, .env |
| network_tool_container | HIGH | kill_process | Attacker staging tools |
| unknown_namespace_process | — | none | Podman false positive (Phase 2 fix) |
| unauthorized_external_connect | — | none | kill after connect is too late — LSM block is Phase 2 |

**Notification:** skip email. Send `response_action` field in alert payload → goes to Pub/Sub → dashboard shows action taken alongside alert.

**Open question before implementing:** Real-world EDR uses more than kill — block IP, quarantine, remove file. Need to decide final action set. See design discussion in session.

---

## IMMEDIATE NEXT STEP — EDR validation on GCP VM

SSH to GCP VM and run full validation:
```bash
gcloud compute ssh instance-20260318-023006 --zone=us-west1-b \
  --project=project-3f1d99fa-d525-4aff-a03

# On GCP VM:
cd ~/workspace/ebpf-edr-demo
git pull          # get latest: pmdaproc whitelist + DBG removal
make build
git add ebpf-edr && git commit -m "rebuild: pmdaproc whitelist + remove DBG logging" && git push
sudo pkill ebpf-edr || true
make run-docker   # restart with new binary
sudo ./validate.sh  # T1-T8 attack scenarios
```

Then confirm alerts in Cloud Logging:
```bash
gcloud logging read 'logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --project=ebpfagent --limit=10 \
  --format="table(timestamp,jsonPayload.env,jsonPayload.rule,jsonPayload.service)"
```

---

## Oracle VMs — PAUSED

Both VMs deleted by accidental `pulumi up` during A1 attempt. Recovery requires:
1. `pulumi config set a1Enabled false && pulumi up --yes` (recreates E2.1.Micro VMs)
2. `EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh` (install Podman + eBPF)
3. `./docker/deploy-vm.sh` (deploy healthcare services)

Not worth doing now — VMs freeze too frequently to be reliable for testing.
Resume when stable window available or A1 capacity opens.

---

## PREVIOUS NEXT STEP — Rebuild binary with policy changes

The current binary on Oracle VMs was built BEFORE these code changes were committed:
- `pmdaproc` + `pmdalinux` added to `fileCommWhitelist` (policy.go)
- DBG log lines removed entirely (rules.go, main.go)
- `-ldflags="-s -w"` added to Makefile (binary size reduction)

**On GCP VM:**
```bash
cd ~/workspace/ebpf-edr-demo
git pull
make build
git add ebpf-edr && git commit -m "rebuild: pmdaproc whitelist + remove DBG logging" && git push
```

**Then update both Oracle VMs** (from Mac, per docs/AGENT-DEPLOY.md):
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 "
  sudo curl -fsSL https://raw.githubusercontent.com/yifengzh/ebpf-edr-demo/main/ebpf-edr \
    -o /usr/local/bin/ebpf-edr &&
  sudo chmod +x /usr/local/bin/ebpf-edr &&
  sudo restorecon -v /usr/local/bin/ebpf-edr 2>/dev/null || true &&
  sudo systemctl restart ebpf-edr
"
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "
  sudo curl -fsSL https://raw.githubusercontent.com/yifengzh/ebpf-edr-demo/main/ebpf-edr \
    -o /usr/local/bin/ebpf-edr &&
  sudo chmod +x /usr/local/bin/ebpf-edr &&
  sudo restorecon -v /usr/local/bin/ebpf-edr 2>/dev/null || true &&
  sudo systemctl restart ebpf-edr
"
```

## Then — Validate end-to-end pipeline

```bash
# Trigger CRITICAL alert on VM1
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 \
  "sudo docker exec healthcare-gateway bash -c 'id'"

# Check Cloud Logging
gcloud logging read 'logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --project=ebpfagent --limit=5 \
  --format="table(timestamp,jsonPayload.env,jsonPayload.rule,jsonPayload.service)"
```

---

## What was completed this session (2026-05-30 → 2026-06-01)

### Infrastructure
- ✅ Fixed Pulumi state drift (`make infra-refresh` + `make infra-up`)
- ✅ Fixed `BACKEND_VM_IP` → now uses VM2 private IP (`10.0.1.55`) via `instance2PrivateIp` Pulumi export
- ✅ Updated `network.go` — SSH CIDR configurable via `pulumi config set sshAllowedCidr <ip>/32`
- ✅ Updated `deploy-vm.sh` — uses `VM2_PRIVATE_IP` for `BACKEND_VM_IP`; SSH/SCP still use public IP

### eBPF Agent
- ✅ Binary renamed `ebpf-edr-demo` → `ebpf-edr` everywhere (Makefile, setup-vm.sh)
- ✅ Binary built with `-ldflags="-s -w"` (~18MB, under GitHub raw 25MB limit)
- ✅ Binary committed to repo, downloaded via `raw.githubusercontent.com`
- ✅ `pmdaproc` + `pmdalinux` added to `fileCommWhitelist` (Oracle PCP monitoring daemons)
- ✅ All 4 DBG log lines removed (rules.go, main.go) — agent now silent except alerts
- ✅ `setup-vm.sh` updated — raw GitHub URL, `restorecon` for SELinux
- ✅ `setup-vm.sh` SA key note added (current: local file; future: Secret Manager)
- ✅ eBPF agent deployed + running on VM1 (systemd, auto-start)
- ✅ eBPF agent deployed + running on VM2 (systemd, auto-start)
- ✅ Pipeline confirmed working — CRITICAL alerts firing on VM2

### Integration Tests
- ✅ Fixed `pom.xml` — removed `gateway.url=localhost:8080` override
- ✅ `BaseIT.java` is now single source of truth for gateway URL
- ✅ Auth + provider integration tests passing

### Documentation
- ✅ `docs/DETECTION-POLICY.md` — new: per-environment noise policy, whitelist rationale, pending changes
- ✅ `docs/AGENT-DEPLOY.md` — new: deployment guide with ownership model, per-environment steps
- ✅ `docs/TESTING-GUIDE.md` — updated: Oracle VM steps, reboot recovery, correct test trigger
- ✅ `docs/SETUP.md` — existing, covers infra + GCP VM setup
- ✅ `oracle-vm-runbook.md` (health-ai) — existing, covers Oracle VM operations

---

## Key Facts / Gotchas

### Oracle VMs
- VM1: `163.192.46.25` (public) / `10.0.1.160` (private) — gateway + auth
- VM2: `163.192.30.193` (public) / `10.0.1.55` (private) — provider + ai
- Both freeze randomly (Oracle free tier platform instability — not fixable)
- **Run eBPF validation and integration tests separately** — combined load triggers freezes
- Services do NOT auto-start after reboot — always start VM2 first, then VM1
- eBPF agent DOES auto-start (systemd enabled on both VMs)
- `BACKEND_VM_IP` must be `10.0.1.55` (private IP) — public IP times out due to security list

### eBPF Agent
- Binary: `~/workspace/ebpf-edr-demo/ebpf-edr` (committed to repo, ~18MB stripped)
- SA key: `/tmp/oracle-agent.json` (from `pulumi stack output oracleAgentKey --show-secrets | base64 -d`)
- SA key note: currently local file; should move to GCP Secret Manager (see AGENT-DEPLOY.md)
- `GOOGLE_CLOUD_PROJECT=ebpfagent` set in systemd service
- Alerts go to: Cloud Logging (`ebpf-edr-alerts`) + local `/alerts/alert.log`

### Known False Positives (Phase 2 fixes)
- `unknown_namespace_process` CRITICAL from Podman health checks (`/bin/sh` + `wget`)
  - Root cause: `containerIDFromDockerCgroup` only parses Docker cgroup paths, not Podman
  - Podman exec creates new mount namespace per execution (different inode from container)
  - Fix: update `docker_resolver.go` to handle Podman cgroup format
  - Documented in `docs/DETECTION-POLICY.md`

### GCP Credits
- Expire: 2026-06-17 (~16 days)
- GCP Docker VM `instance-20260318-023006` (~$43/mo) is the only paid resource
- After expiry: Oracle VMs (free) remain; Cloud Logging free tier should cover alert volume
- Plan: complete eBPF validation before 2026-06-17

## Timeline
~2 weeks remaining. Priority: rebuild binary → validate pipeline → done.
