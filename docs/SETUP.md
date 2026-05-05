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

## Running Locally (Docker VM)

```bash
# build binary (cross-compiles linux/amd64 from macOS or Linux)
make build

# run on GCP VM (requires root for eBPF)
# GOOGLE_CLOUD_PROJECT must be exported before sudo — sudo drops env vars unless
# /etc/sudoers.d/ebpf-edr has: Defaults env_keep += "GOOGLE_CLOUD_PROJECT"
export GOOGLE_CLOUD_PROJECT=ebpfagent
sudo ./ebpf-edr-demo --runtime=docker
```

### One-time VM setup (cross-project Cloud Logging + Pub/Sub auth)

The Docker VM is in a different GCP project than `ebpfagent`. Run once after first SSH:

```bash
# persist env var across logins
echo "GOOGLE_CLOUD_PROJECT=ebpfagent" | sudo tee -a /etc/environment

# allow sudo to preserve GOOGLE_CLOUD_PROJECT
echo 'Defaults env_keep += "GOOGLE_CLOUD_PROJECT"' | sudo tee /etc/sudoers.d/ebpf-edr

# grant Pub/Sub scope — VM default OAuth scopes don't include pubsub
# --no-launch-browser is required (VM is headless)
gcloud auth application-default login --no-launch-browser
```

After this, new SSH sessions only need:
```bash
export GOOGLE_CLOUD_PROJECT=ebpfagent
sudo ./ebpf-edr-demo --runtime=docker
```

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
