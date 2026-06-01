# Session Handoff — 2026-05-30

## Current Task
Deploy eBPF EDR agent to Oracle VMs (VM1 + VM2) and validate, so all environments
(GCP VM, GKE, Oracle VMs) report to one central Cloud Logging dashboard.

## IMMEDIATE NEXT STEP — fix Pulumi state drift
`sensor-vm` was manually deleted via gcloud (mistake), causing Pulumi state drift.
The last `pulumi up` left the stack with 1 errored resource (sensor-vm 404 on delete).

```bash
cd ~/workspace/ebpf-edr-demo
make infra-refresh    # pulumi refresh → reconcile → pulumi up
```

✅ Already created successfully: Oracle SA (`healthcare-oracle-agent`) + key, IAM bindings.

## Then — complete Oracle VM eBPF deployment

```bash
# 1. Get Oracle SA key
cd ~/workspace/ebpf-edr-demo/infra
pulumi stack output oracleAgentKey --show-secrets | base64 -d > /tmp/oracle-agent.json

# 2. Build binary ON GCP VM (Mac can't build — Pulumi GCP SDK OOMs, and BPF needs linux)
#    SSH to GCP VM first, then:
git checkout pkg/bpf/    # IMPORTANT: restore committed generated files
                         # (handle_valid_open vs HandleExit mismatch if make generate was run)
make build

# 3. Publish binary to GitHub release
make github-release VERSION=v0.1.0

# 4. Deploy to BOTH Oracle VMs (installs Podman/swap/compose + eBPF agent)
cd ~/workspace/github_projects/health-ai/healthcare-ai-microservices
EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh

# 5. Validate — see docs/TESTING-GUIDE.md Steps 2b, 3b
```

## What was completed this session

### Oracle VM healthcare deployment (DONE)
- Fixed VM freezing: sequential Docker builds, rsync (not scp), buffer-cache clear, SSH keepalive in deploy-vm.sh
- Memory tuning (all 4 services ~270MB total): JAVA_TOOL_OPTIONS, Hikari 5→2, actuator=health only, Tomcat threads 200→10, mem_limit + restart:unless-stopped in compose files
- Fixed setup-vm.sh: swap persisted in /etc/fstab, x86_64 docker-compose binary (VMs are x86_64 NOT arm)
- Services deployed on VM1 (163.192.46.25: gateway+auth) + VM2 (163.192.30.193: provider+ai), integration tests pass
- Security: removed hardcoded VM password from compute.go → Pulumi config secret `vmPassword`; Pulumi.dev.yaml gitignored

### eBPF code changes (DONE)
- `pkg/workload/identity.go`: added `Env` field to WorkloadIdentity
- `pkg/workload/resolver.go`: reads `ENV` env var → both resolvers
- `pkg/workload/docker_resolver.go`: `env` field + fallback to full container name (no fake Compose labels)
- `pkg/workload/k8s_resolver.go`: `env` propagated through crictlContainerMap
- `internal/alert/alert.go`: `Env` in log line + Cloud Logging JSON payload
- `infra/agents.go`: NEW — all agent SAs in one place; returns StringArray for base.go
  - GKE SA commented out (deleted with cluster — re-enable on `make test-env-up`)
  - sensor VM NOT here (sensor.go owns its own IAM)
- `infra/base.go`: takes agentMembers; uses IAMMember loop (not IAMBinding — avoids sensor.go conflict)
- `infra/main.go`: deployAgentIdentities → deployBase

### Makefile targets (DONE)
- `github-release VERSION=vX` — build + publish binary
- `test-env-up` / `test-env-down` — GKE + order-processor full cycle (~$100/mo when up)
- `infra-refresh` — fix state drift
- `sensor-up` / `sensor-down` — IoT sensor VM

### health-ai setup-vm.sh (DONE)
- Installs eBPF agent on BOTH Oracle VMs via GitHub release binary + SA key
- `--env=oracle-vm1` / `--env=oracle-vm2` per VM
- Requires `EBPF_SA_KEY_FILE` env var

### GCP cost cleanup (DONE — was ~$132/mo, only $35 credits left, expires 2026-06-17)
- Destroyed GKE cluster (`pulumi destroy` in order_processor/gcp_gke)
- Deleted sensor-vm (manual gcloud — caused the state drift above)
- Deleted GKE noise logs from Cloud Logging (kept ebpf-edr-alerts)
- Disabled GKE managed logging: pulumi_gke.go LoggingService=none, MonitoringService=none (~$31/mo saved)
- KEPT: GCP Docker VM `instance-20260318-023006` (e2-medium ~$43/mo), Oracle VMs (free)

### Docs created/updated
- ebpf: docs/oracle-vm-deploy-design.md, docs/TESTING-GUIDE.md, docs/SETUP.md (infra section)
- health-ai: docs/oracle-vm-runbook.md, docs/deploy-oracle-plan.md, BACKLOG.md, DAILY_WORK_LOG.md
- order_processor: docs/deployment-guide.md (GCP GKE deploy/destroy section)

## Key facts / gotchas
- Oracle VMs are x86_64 (not ARM) — `uname -m` = x86_64; the "aarch64" seen earlier was Cloud Shell
- Oracle free tier VMs freeze randomly — known platform issue; mem_limit + restart:unless-stopped mitigate
- Mac can't `go build` infra/ (Pulumi GCP SDK OOMs) — build on GCP VM
- BTF confirmed present on Oracle VM2: /sys/kernel/btf/vmlinux exists, kernel 6.12
- ALWAYS use Makefile targets for cloud resources, never raw gcloud/kubectl/pulumi (state drift)
- GCP free tier (90-day) expires 2026-06-17 — plan to finish testing before then or move eBPF to laptop/local Docker

## Timeline
User plans to complete all eBPF testing in ~2 weeks.
