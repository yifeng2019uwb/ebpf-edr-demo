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

`go generate` must run on Linux (requires clang + bpf2go).
It is called automatically inside the Docker builder via `make docker-push`.

```bash
# Step 1 — rebuild BPF objects + Go binary + push image to Artifact Registry
make docker-push

# Step 2 — commit and push source to GitHub
git add -A && git commit -m "..." && git push

# Step 3 — redeploy DaemonSet to GKE (from cloud-native-order-processor/gcp_gke/)
./deploy.sh daemonset

# Step 4 — validate
./validate-gke.sh
```

### When you change only Go code (pkg/ or cmd/)

`go generate` is not needed — BPF objects are unchanged.

```bash
make docker-push          # rebuilds Go binary only, pushes image
git add -A && git commit -m "..." && git push
# in cloud-native-order-processor/gcp_gke/
./deploy.sh daemonset
./validate-gke.sh
```

### When you change only the DaemonSet YAML (k8s/ebpf-edr-ds.yaml)

No rebuild needed — `deploy.sh daemonset` downloads YAML fresh from GitHub.

```bash
git add k8s/ebpf-edr-ds.yaml && git commit -m "..." && git push
# in cloud-native-order-processor/gcp_gke/
./deploy.sh daemonset
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
- Oracle VM SA (`healthcare-oracle-agent`) + key (see below)

### Oracle VM — get SA key after deploy

Oracle VMs have no GCE metadata server, so they use an explicit SA key file.
After `make infra-up`, retrieve the key:

```bash
cd infra && pulumi stack output oracleAgentKey --show-secrets | base64 -d > /tmp/oracle-agent.json
```

Deploy to both Oracle VMs (VM1 + VM2) via the health-ai setup script:

```bash
# In healthcare-ai-microservices repo:
EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh
```

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

### Expected alerts in the UI after Docker validation (T1–T8)

| Test | Level    | Rule                            | Details               |
|------|----------|---------------------------------|-----------------------|
| T1   | CRITICAL | `shell_spawn_container`         | comm=bash             |
| T2   | HIGH     | `network_tool_container`        | comm=nc or wget       |
| T3   | HIGH     | `sensitive_file_access`         | /etc/shadow           |
| T4   | CRITICAL | `sensitive_file_access`         | /root/.ssh/id_rsa     |
| T5   | HIGH     | `unauthorized_external_connect` | 8.8.8.8:80            |
| T6   | (no alert — inventory-service external connects are allowlisted) | |
| T7   | CRITICAL | `host_reads_container_fs`       | service=host          |
| T8   | MEDIUM   | `sensitive_file_access`         | /etc/passwd           |

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
