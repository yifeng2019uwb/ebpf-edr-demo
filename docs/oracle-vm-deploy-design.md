# eBPF EDR — Oracle Cloud VM Deployment Design

> Status: **Planning — research complete, implementation not yet started**
> Research date: 2026-05-29
> Target: Oracle Cloud Free Tier VM2 (163.192.30.193) running provider-service + ai-service

---

## 1. Goal

Deploy the eBPF EDR agent to the Oracle Cloud VM running healthcare-ai backend services,
so all three monitored environments report to the same Cloud Logging destination:

```
GCP VM (OpenClaw)   → eBPF agent (DockerResolver) → Cloud Logging (ebpfagent) ✅
GKE                 → eBPF agent (K8sResolver)    → Cloud Logging (ebpfagent) ✅
Oracle VM2          → eBPF agent (DockerResolver?) → Cloud Logging (ebpfagent) ← this plan
```

Only VM2 (`healthcare-backend`, 163.192.30.193) is targeted — that's where the interesting
clinical traffic is: provider-service writing patient data, ai-service calling Gemini API.
VM1 (gateway + auth) is lower value for security monitoring.

---

## 2. Environment Facts (researched 2026-05-29)

### VM2 specs

| Property | Value |
|----------|-------|
| Provider | Oracle Cloud Free Tier |
| Shape | VM.Standard.E2.1.Micro |
| OS | Oracle Linux 9 |
| Kernel | `6.12.0-202.76.4.1.el9uek.x86_64` |
| CPU arch | **x86_64** (NOT ARM — confirmed with `uname -m`) |
| RAM | ~500MB + 4GB swap |
| Container runtime | **Podman** (not Docker) — `docker` CLI aliased to `podman` |
| Compose | Docker Compose v2 plugin (`docker-compose-linux-x86_64` binary) |
| Services | healthcare-provider (8083), healthcare-ai (8085) |
| SSH user | `opc` |

### Key difference from GCP VMs

Oracle VM has **no GCE metadata server**. GCP VMs get credentials automatically via
`http://metadata.google.internal/...` — Oracle VM cannot use this. Explicit credentials
(service account key file) are required.

### eBPF kernel compatibility

| Check | Result |
|-------|--------|
| Kernel version | 6.12 — exceeds minimum of 6.0 for LSM socket_connect ✅ |
| BTF | Not yet verified — check `ls /sys/kernel/btf/vmlinux` on VM2 |
| CO-RE | Expected to work — same BPF C programs as GCP/GKE deployments |
| Architecture | x86_64 — build with `GOOS=linux GOARCH=amd64` ✅ |

---

## 3. Critical Finding — Podman Container Visibility

### Problem

The existing `DockerResolver` identifies containers using:
1. `docker ps --no-trunc --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.service"}}'`
2. `/proc/<pid>/cgroup` parsing for container ID

On Oracle VM with Podman, two issues were found:

**Issue 1 — Rootful containers invisible to non-root users**

Healthcare services are started with `sudo docker compose up -d`. In Podman, rootful
containers (started as root) are NOT visible to non-root users. Running `docker ps` as
`opc` returns empty even when containers are running.

**Resolution**: Agent must run as root (required anyway for BPF capabilities). As root,
`docker ps` will see all containers.

**Issue 2 — Docker Compose labels may not be set**

Running `docker ps --format '{{.Names}} {{.Label "com.docker.compose.service"}}'` as root
returned empty labels. Root cause not yet confirmed — two possibilities:
- Podman Go template syntax: Docker uses `{{.Label "key"}}`, Podman may need `{{index .Labels "key"}}`
- Docker Compose v2 not setting labels when run via Podman compatibility shim

**Unverified**: Need to run as root on VM2 and inspect with `sudo docker inspect healthcare-provider | grep -A5 '"Labels"'`

### Design decision — do NOT add fake labels to compose files

Adding `com.docker.compose.service` labels to compose files just to satisfy the resolver
is the wrong approach. Container names (`healthcare-provider`, `healthcare-ai`) are already
meaningful identifiers. The resolver should use them directly.

**Fix 1 — `docker_resolver.go`**: fall back to container name when compose label is empty.
This makes the resolver robust for any environment where Docker Compose labels aren't set
(Podman, bare metal, future runtimes).

```go
// After reading label, fall back to container name if empty
service := label  // com.docker.compose.service
if service == "" {
    service = name  // container name (e.g. "healthcare-provider")
}
```

**Fix 2 — environment tagging**: add `--env=<name>` flag to the agent so every log entry
is stamped with which environment it came from. Without this, Cloud Logging has no way to
distinguish Oracle VM events from GCP VM events.

```
oracle-vm2  → healthcare-provider, healthcare-ai
gcp-vm      → order-processor, api-gateway, ...
gke         → order-processor (pod), ...
```

This change touches `WorkloadIdentity` struct (add `Env` field) and the alert publisher
(include `env` in log payload). Small but high-value for multi-environment visibility.

---

## 4. Authentication Design

### GCP VM approach (current)

```
GCP VM compute SA → GCE metadata server → OAuth token → Cloud Logging
```
No key file needed. `GOOGLE_CLOUD_PROJECT=ebpfagent` is sufficient.

### Oracle VM approach (this plan)

```
Dedicated SA key file on VM → GOOGLE_APPLICATION_CREDENTIALS → Cloud Logging
```

Steps:
1. Create SA: `healthcare-oracle-agent@ebpfagent.iam.gserviceaccount.com`
2. Download key: `gcloud iam service-accounts keys create /tmp/oracle-agent.json --iam-account=...`
3. Add IAM grants in `infra/base.go` (logging.logWriter + pubsub.publisher)
4. Copy key to VM2: `scp ... /tmp/oracle-agent.json opc@163.192.30.193:/etc/ebpf-creds.json`
5. Set in systemd: `Environment=GOOGLE_APPLICATION_CREDENTIALS=/etc/ebpf-creds.json`

### Security note

Key file at `/etc/ebpf-creds.json` should be owned by root, mode 600.
The systemd service runs as root so this is sufficient.

---

## 5. Changes Required

### `infra/base.go`

Uncomment and fill in the healthcare VM section, but use dedicated SA (not compute SA):

```go
const oracleVMSA = "serviceAccount:healthcare-oracle-agent@ebpfagent.iam.gserviceaccount.com"

// Oracle Cloud VM2 — healthcare-ai backend (provider-service + ai-service)
_, err = projects.NewIAMMember(ctx, "oracle-vm-logging-writer", &projects.IAMMemberArgs{
    Project: pulumi.String(project),
    Role:    pulumi.String("roles/logging.logWriter"),
    Member:  pulumi.String(oracleVMSA),
})

_, err = pubsub.NewTopicIAMMember(ctx, "oracle-vm-pubsub-publisher", &pubsub.TopicIAMMemberArgs{
    Topic:   topic.Name,
    Project: pulumi.String(project),
    Role:    pulumi.String("roles/pubsub.publisher"),
    Member:  pulumi.String(oracleVMSA),
})
```

### `infra/scripts/oracle-vm-deploy.sh` (new)

Deploy script for Oracle VM — handles SA key, binary copy, systemd service.
Different from `sensor-startup.sh` (GCP VM) in two ways:
- Uses `GOOGLE_APPLICATION_CREDENTIALS` key file (not GCE metadata)
- Targets Podman: systemd unit uses `After=podman.socket` not `After=docker.service`

### `pkg/workload/docker_resolver.go`

Fall back to container name when `com.docker.compose.service` label is empty.
Makes resolver work on Podman, bare metal, and any runtime without Compose labels.

### `cmd/edr-monitor/main.go`

Add `--env=<name>` flag (e.g. `--env=oracle-vm2`). Passed into `WorkloadIdentity`.

### `pkg/workload/workload.go` (or wherever `WorkloadIdentity` is defined)

Add `Env string` field to `WorkloadIdentity` struct.

### `internal/alert/alert.go`

Include `env` field in Cloud Logging payload so events are queryable by environment.

### No changes to `docker/compose-backend.yml` in health-ai project

Container names (`healthcare-provider`, `healthcare-ai`) are used directly — no fake labels needed.

---

## 6. Systemd Service (Oracle VM)

```ini
[Unit]
Description=eBPF EDR Agent
After=podman.socket
Wants=podman.socket

[Service]
Type=simple
ExecStart=/usr/local/bin/ebpf-edr --runtime=docker
Restart=on-failure
RestartSec=5
Environment=GOOGLE_CLOUD_PROJECT=ebpfagent
Environment=GOOGLE_APPLICATION_CREDENTIALS=/etc/ebpf-creds.json

[Install]
WantedBy=multi-user.target
```

---

## 7. Implementation Steps

### Step 1 — Verify BTF on VM2
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "ls /sys/kernel/btf/vmlinux"
```
If missing → eBPF cannot run on this VM. (Unlikely given kernel 6.12.)

### Step 2 — Verify Docker Compose labels
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 \
  "sudo docker inspect healthcare-provider | grep -A 20 '\"Labels\"'"
```
If `com.docker.compose.service` label is present → DockerResolver works as-is.
If missing → add explicit labels to `compose-backend.yml`.

### Step 3 — Create GCP SA and IAM
```bash
gcloud iam service-accounts create healthcare-oracle-agent \
  --project=ebpfagent \
  --display-name="Healthcare Oracle VM eBPF agent"

gcloud iam service-accounts keys create /tmp/oracle-agent.json \
  --iam-account=healthcare-oracle-agent@ebpfagent.iam.gserviceaccount.com
```
Then update `infra/base.go` and run `cd infra && pulumi up`.

### Step 4 — Build binary
```bash
cd /path/to/ebpf-edr-demo
GOOS=linux GOARCH=amd64 go build -o ebpf-edr-linux-amd64 ./cmd/edr-monitor
```

### Step 5 — Copy binary and key to VM2
```bash
scp -i ~/.ssh/oracle_vm ebpf-edr-linux-amd64 opc@163.192.30.193:/tmp/
scp -i ~/.ssh/oracle_vm /tmp/oracle-agent.json opc@163.192.30.193:/tmp/

ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "
  sudo mv /tmp/ebpf-edr-linux-amd64 /usr/local/bin/ebpf-edr
  sudo chmod +x /usr/local/bin/ebpf-edr
  sudo mv /tmp/oracle-agent.json /etc/ebpf-creds.json
  sudo chmod 600 /etc/ebpf-creds.json
"
```

### Step 6 — Install and start systemd service
Write the systemd unit (see Section 6), enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ebpf-edr
sudo systemctl start ebpf-edr
sudo systemctl status ebpf-edr
```

### Step 7 — Validate
```bash
# Check agent is running and logging
sudo journalctl -u ebpf-edr -f

# Run healthcare integration tests to generate traffic
./integration_tests/run-it.sh all

# Check Cloud Logging for Oracle VM events
gcloud logging read 'logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --project=ebpfagent \
  --format=json | grep oracle
```

---

## 8. Open Questions

| # | Question | How to resolve |
|---|----------|----------------|
| Q1 | Does `sudo docker inspect` show `com.docker.compose.service` label? | Step 2 above |
| Q2 | Is `/sys/kernel/btf/vmlinux` present on Oracle Linux 9 kernel 6.12? | Step 1 above |
| Q3 | Does `--runtime docker` correctly resolve container names on Podman? | Deploy + check Cloud Logging output |
| Q4 | Should agent run on VM1 (gateway + auth) too? | Low priority — VM1 traffic less interesting |

---

## 9. Deferred

- **Automated key rotation** — SA key is static; GCP VM uses ephemeral metadata tokens. For
  now acceptable (personal project). Production would use Workload Identity Federation.
- **VM1 deployment** — gateway + auth traffic is lower value. Add later if needed.
- **MITRE coverage additions** — healthcare-specific rules (FHIR endpoint access, Gemini API calls).
  See `cnop-ebpf-monitor-design.md` for planned rules.
