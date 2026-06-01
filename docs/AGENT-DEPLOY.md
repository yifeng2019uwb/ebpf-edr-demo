# eBPF Agent Deployment Guide

How to deploy the eBPF EDR agent to each monitored environment.

For detection rules and policy, see [DETECTION-POLICY.md](DETECTION-POLICY.md).
For testing and validation after deploy, see [TESTING-GUIDE.md](TESTING-GUIDE.md).

---

## Ownership Model

```
eBPF team (ebpf-edr-demo)            Consuming team
─────────────────────────            ──────────────
Publishes binary → GitHub release    Downloads binary via setup script
Provisions SA + IAM → Pulumi         Uses SA key to authenticate agent
Owns detection rules + policy        Owns VM / cluster setup
```

No cross-team SSH access required.

---

## Prerequisites (all environments)

Both must be done before deploying to any environment:

### 1. Central logging infra

```bash
cd ~/workspace/ebpf-edr-demo
make infra-up
```

Provisions: Cloud Logging bucket, Pub/Sub topic `edr-alerts`, IAM for all agent SAs, Oracle VM SA + key.
Run once after initial setup, and again when adding a new environment.

### 2. Build and publish binary (must run on GCP VM — Mac cannot build BPF)

```bash
# SSH to GCP VM
gcloud compute ssh instance-20260318-023006 --zone=us-west1-b \
  --project=project-3f1d99fa-d525-4aff-a03

# On GCP VM
cd ~/workspace/ebpf-edr-demo
git pull
make build
git add ebpf-edr && git commit -m "update binary" && git push
```

The binary `ebpf-edr` is committed to the repo. All environments download from:
`https://raw.githubusercontent.com/yifengzh/ebpf-edr-demo/main/ebpf-edr`

---

## Environments

### GCP Docker VM (`instance-20260318-023006`)

**Owner**: eBPF team  
**Auth**: GCP metadata server — no key file (VM compute SA has `logging.logWriter`)  
**Runtime**: `--runtime=docker`

```bash
# On GCP VM — download latest release and run
curl -fsSL https://raw.githubusercontent.com/yifengzh/ebpf-edr-demo/main/ebpf-edr \
  -o ~/workspace/ebpf-edr-demo/ebpf-edr
chmod +x ~/workspace/ebpf-edr-demo/ebpf-edr
make run-docker
```

**Validate**: `sudo ./validate.sh` — see [VALIDATION.md](VALIDATION.md)

---

### Oracle VM1 + VM2 (healthcare-ai-microservices)

**Owner**: health-ai team runs deployment; eBPF team provides binary (GitHub release) + SA key (Pulumi)  
**Auth**: SA key file `/etc/ebpf-creds.json`  
**Runtime**: `--runtime=docker` via systemd `ebpf-edr` (auto-starts on reboot)

| VM | Public IP | Private IP | Services | ENV tag |
|----|-----------|------------|----------|---------|
| VM1 | 163.192.46.25 | 10.0.1.160 | gateway + auth | `oracle-vm1` |
| VM2 | 163.192.30.193 | 10.0.1.55 | provider + ai | `oracle-vm2` |

**Step 1 — Get SA key** (eBPF team):
```bash
cd ~/workspace/ebpf-edr-demo/infra
pulumi stack output oracleAgentKey --show-secrets | base64 -d > /tmp/oracle-agent.json
```

**Step 2 — Deploy to both VMs** (health-ai team, in healthcare-ai-microservices repo):
```bash
EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh
```

> **Note**: `EBPF_SA_KEY_FILE` currently points to a local file exported from Pulumi.
> The proper approach is to store the SA key in GCP Secret Manager so the health-ai team
> can fetch it independently without sharing Pulumi access. Simplified here for now.

Downloads binary from GitHub repo, installs systemd service with correct `ENV` tag on each VM.

**After a new release — update both VMs:**
```bash
# VM1
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 "
  sudo curl -fsSL https://raw.githubusercontent.com/yifengzh/ebpf-edr-demo/main/ebpf-edr \
    -o /usr/local/bin/ebpf-edr &&
  sudo chmod +x /usr/local/bin/ebpf-edr &&
  sudo restorecon -v /usr/local/bin/ebpf-edr 2>/dev/null || true &&
  sudo systemctl restart ebpf-edr
"

# VM2
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "
  sudo curl -fsSL https://raw.githubusercontent.com/yifengzh/ebpf-edr-demo/main/ebpf-edr \
    -o /usr/local/bin/ebpf-edr &&
  sudo chmod +x /usr/local/bin/ebpf-edr &&
  sudo restorecon -v /usr/local/bin/ebpf-edr 2>/dev/null || true &&
  sudo systemctl restart ebpf-edr
"
```

**Check status:**
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 "systemctl is-active ebpf-edr"
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "systemctl is-active ebpf-edr"
```

**Validate**: see [TESTING-GUIDE.md](TESTING-GUIDE.md) Steps 2b and 3b

---

### GKE (on-demand — ~$100/month while running)

**Owner**: order-processor team runs deployment; eBPF team provides Docker image + Workload Identity IAM  
**Auth**: Workload Identity — no key file  
**Runtime**: `--runtime=k8s` via DaemonSet in `kube-system`

```bash
# Bring up GKE + deploy everything
make test-env-up

# Or update DaemonSet only (from cloud-native-order-processor/gcp_gke/)
make docker-push
./deploy.sh daemonset
```

**Tear down when done** (stops ~$100/month cost):
```bash
make test-env-down
```

**Validate**: `./validate-gke.sh` — see [VALIDATION-GKE.md](VALIDATION-GKE.md)

---

## Adding a New Environment

1. Add SA member to `infra/agents.go` → `make infra-up`
2. Get SA key (non-GCP) or grant Workload Identity (GCP/GKE)
3. Deploy agent binary with `ENV=<env-tag>` set
4. Add environment to [DETECTION-POLICY.md](DETECTION-POLICY.md) — document noise sources
5. Add environment to [TESTING-GUIDE.md](TESTING-GUIDE.md) — add validation steps
