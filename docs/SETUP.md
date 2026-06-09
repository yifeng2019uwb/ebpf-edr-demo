# Setup Guide

## One-time: Install Go 1.24 (Linux build VM)

```bash
wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Verify
go version  # should show go1.24.2
```

## One-time: Project Setup (Linux build VM)

```bash
mkdir ~/workspace/ebpf-edr-demo
cd ~/workspace/ebpf-edr-demo

go mod init ebpf-edr-demo
go get github.com/cilium/ebpf
go get -tool github.com/cilium/ebpf/cmd/bpf2go
go mod tidy
```

## Code Structure

```
kernel/          — BPF C programs (.bpf.c) and shared headers (.h)
pkg/bpf/gen.go  — go:generate directives; one per BPF program:
                    bpf2go compiles .bpf.c → .o + Go wrapper (_bpfel.go)
pkg/bpf/        — generated Go wrappers (committed, no clang needed in CI)
pkg/detector/   — detection rules (rules.go) and policy config (policy.go)
pkg/workload/   — WorkloadResolver: DockerResolver, K8sResolver
cmd/edr-monitor/ — main entry point
```

## Development Workflow

### When you change BPF C code (kernel/*.bpf.c or kernel/*.h)

`go generate` must run on Linux (requires clang + bpf2go). Run on GCP VM.

```bash
# Step 1 — on GCP VM: rebuild BPF objects + Go binary
make rebuild              # go generate + go build

# Step 2 — commit generated files and binary
git add pkg/bpf/ ebpf-edr && git commit -m "..." && git push

# Step 3 — on Mac: push image to ghcr.io
git pull
make docker-push-ghcr-prebuilt

# Step 4 — redeploy DaemonSet to GKE (from health-ai/kubernetes/)
./deploy.sh app

# Step 5 — validate
./validate-gke.sh
```

### When you change only Go code (pkg/ or cmd/)

`go generate` is not needed — BPF objects are unchanged. Safe to build on Mac.

```bash
make build                       # cross-compile linux/amd64 binary
make docker-push-ghcr-prebuilt   # push image to ghcr.io
git add -A && git commit -m "..." && git push
# in health-ai/kubernetes/
./deploy.sh app
./validate-gke.sh
```

### When you change only the DaemonSet YAML (k8s/ebpf-edr-ds.yaml)

No rebuild needed. The YAML is read from local repo by deploy.sh.

```bash
git add k8s/ebpf-edr-ds.yaml && git commit -m "..." && git push
# in health-ai/kubernetes/
./deploy.sh app
```

### Deploying health-ai + eBPF to GKE (full stack)

```bash
# Step 1 — bring up GKE cluster (if not running)
cd health-ai/kubernetes/pulumi
pulumi up

# Step 2 — deploy everything (builds images, deploys services, deploys eBPF DaemonSet)
cd ..
./deploy.sh all

# Step 3 — validate eBPF sensor
cd ~/workspace/ebpf-edr-demo
./validate-gke.sh

# Tear down when done (saves ~$100+/month)
./deploy.sh destroy
```

## go:generate — what it does

Defined in `pkg/bpf/gen.go`:
```go
//go:generate bpf2go process ../../kernel/execsnoop.bpf.c  → process_bpfel.go
//go:generate bpf2go file    ../../kernel/opensnoop.bpf.c  → file_bpfel.go
//go:generate bpf2go lsm     ../../kernel/lsm-connect.bpf.c → lsm_bpfel.go
```

Each directive compiles one `.bpf.c` file and generates a Go wrapper that:
- Embeds the compiled `.o` object
- Exposes BPF maps and programs as typed Go structs
- Handles loading into the kernel via `cilium/ebpf`

Run manually (Linux only):
```bash
make generate   # runs: go generate ./pkg/bpf/
```

## Infra Deployment (Pulumi)

Manages: Cloud Logging bucket, Pub/Sub topic, IAM for all eBPF agents.
Run once after initial clone, and again whenever agents are added/removed.

### Prerequisites

```bash
# Authenticated gcloud
gcloud auth application-default login

# Pulumi logged in
pulumi login
```

### Deploy / update infra

```bash
make infra-up
```

This provisions:
- Cloud Logging custom bucket (`ebpf-edr-security-logs-us-west1`, 365-day retention)
- Pub/Sub topic `edr-alerts` + subscription `edr-alerts-router-sub`
- IAM bindings for all agent SAs (`logging.logWriter`, `pubsub.publisher`)

### Add a new monitored environment

1. Add the new SA member string to `agentMembers` in `infra/agents.go`
2. Run `make infra-up`
3. Deploy the agent binary to the new host (see per-environment sections below)

### Tear down infra

```bash
make infra-down
```

---

## One-time VM setup

The Docker VM is in a different GCP project than `ebpfagent`. Run once after first SSH:

```bash
# persist env var across logins
echo "GOOGLE_CLOUD_PROJECT=ebpfagent" | sudo tee -a /etc/environment

# allow sudo to preserve GOOGLE_CLOUD_PROJECT
echo 'Defaults env_keep += "GOOGLE_CLOUD_PROJECT"' | sudo tee /etc/sudoers.d/ebpf-edr

# grant ADC credentials — VM default OAuth scopes don't include pubsub or cross-project logging
# --no-launch-browser is required (VM is headless)
sudo gcloud auth application-default login --no-launch-browser
sudo gcloud auth application-default set-quota-project ebpfagent
```

## Running the Full System

### On the Docker VM

**Terminal 1 — EDR agent:**

```bash
make build && make run-docker
```

Confirm startup:
```
Cloud Logging enabled: project=ebpfagent
Pub/Sub enabled: topic=edr-alerts
```

**Terminal 2 — Docker validation:**

```bash
sudo ./validate.sh
```

**Terminal 3 — Integration tests (optional, simulates normal traffic):**

```bash
bash /home/yifeng2019/workspace/cloud-native-order-processor/integration_tests/run_all_tests.sh all
```

### On your laptop

**Terminal 1 — Alert Router:**

```bash
make run-alert-router
```

Open **http://localhost:8888** — alerts from both Docker VM and GKE stream in real-time.

**Terminal 2 — GKE validation:**

```bash
./validate-gke.sh   # from cloud-native-order-processor/gcp_gke/
```

### Expected alerts in the UI after Docker validation (T1–T11)

| Test | Level    | Rule                                   | Response     | Details               |
|------|----------|----------------------------------------|--------------|-----------------------|
| T1   | CRITICAL | `T1059_unix_shell_execution`           | kill_process | comm=/usr/bin/bash    |
| T2   | HIGH     | `T1105_ingress_tool_transfer`          | kill_process | comm=nc or wget       |
| T3   | HIGH     | `T1003_008_os_credential_dumping`      | kill_process | /etc/shadow           |
| T4   | HIGH     | `T1552_004_private_keys`               | kill_process | /tmp/id_rsa           |
| T5   | HIGH     | `T1041_exfiltration_over_c2`           | block_ip     | 8.8.8.8:80            |
| T6   | (no alert — inventory_service allowlisted)                                       |
| T7   | CRITICAL | `T1611_escape_to_host_fs`              | kill_process | service=host          |
| T8   | MEDIUM   | `T1082_system_info_discovery`          | —            | /etc/passwd           |
| T9   | HIGH     | `T1036_masquerading`                   | —            | comm=/tmp/sshd        |
| T10  | HIGH     | `T1053_003_scheduled_task_cron`        | —            | /etc/crontab          |
| T11  | MEDIUM   | `T1070_003_clear_command_history`      | —            | /tmp/.bash_history    |

---

## Verifying Cloud Logging

After deploying to GKE (`./deploy.sh daemonset`), confirm alerts are flowing:

```bash
# All GKE alerts — run from Mac
gcloud logging read \
  'logName="projects/ebpfagent/logs/ebpf-edr-alerts" AND jsonPayload.runtime="k8s"' \
  --project=ebpfagent --limit=5 --format=json
```

Expected fields in each log entry:
- `jsonPayload.cluster` — GKE cluster name (e.g. `order-processor-cluster-us-west1`)
- `jsonPayload.level` — alert level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- `jsonPayload.runtime` — `k8s`
- `jsonPayload.uid` — Linux UID of the triggering process; `0` = root
- `severity` — Cloud Logging severity mapped from alert level: `HIGH→ERROR`, `MEDIUM→WARNING`, `CRITICAL→CRITICAL`, `LOW→INFO`

If the query returns `[]`:
1. Check the agent is running: `kubectl logs -n kube-system -l app=ebpf-edr -f`
2. Confirm startup line: `Cloud Logging enabled: project=ebpfagent`
3. Run `./validate-gke.sh` to trigger alerts, then query again
4. Always pass `--project=ebpfagent` — your Mac's active gcloud project may differ
