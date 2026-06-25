# DigitalOcean Migration — Quick Test Guide

Goal: spin up both environments for a few hours, verify everything works, then tear down.
No permanent setup needed — $200 / 60-day credit covers this easily.

---

## Prerequisites

```bash
# Install doctl (DO CLI)
brew install doctl

# Authenticate
doctl auth init   # paste DO API token from console → API → Tokens

# Verify
doctl account get
```

Existing assets — no changes needed:
- Images: `ghcr.io/yifeng2019uwb/{ebpf-edr,auth-service,provider-service,ai-service,gateway}:latest` (public)
- DB: Supabase external — works from any cloud
- Creds: `github_projects/health-ai/healthcare-ai-microservices/docker/.env`

---

## Option A — Droplet (Docker VM)

Mirrors the current GCP Docker VM setup.

### 1. Create Droplet

```bash
doctl compute droplet create ebpf-test \
  --image ubuntu-22-04-x64 \
  --size s-2vcpu-4gb \
  --region nyc3 \
  --ssh-keys $(doctl compute ssh-key list --no-header --format ID | head -1)

# Get IP
doctl compute droplet get ebpf-test --format PublicIPv4
```

### 2. Bootstrap

```bash
ssh root@<DROPLET_IP>

apt update && apt install -y docker.io docker-compose-plugin
systemctl enable --now docker
```

### 3. Deploy health-ai services

```bash
# Copy .env to droplet
scp github_projects/health-ai/healthcare-ai-microservices/docker/.env root@<DROPLET_IP>:/root/.env

# On droplet — run all services
docker run -d --name auth-service    --env-file .env -p 8081:8080 ghcr.io/yifeng2019uwb/auth-service:latest
docker run -d --name provider-service --env-file .env -p 8082:8080 ghcr.io/yifeng2019uwb/provider-service:latest
docker run -d --name ai-service      --env-file .env -p 8083:8080 ghcr.io/yifeng2019uwb/ai-service:latest
docker run -d --name gateway         --env-file .env -p 8080:8080 ghcr.io/yifeng2019uwb/gateway:latest
```

### 4. Deploy eBPF agent

```bash
# On droplet
docker run -d \
  --name ebpf-edr \
  --privileged \
  --pid host \
  --network host \
  -v /sys:/sys \
  -v /proc:/proc \
  -e GOOGLE_CLOUD_PROJECT=ebpfagent \
  ghcr.io/yifeng2019uwb/ebpf-edr:latest

docker logs -f ebpf-edr
```

> GCP Cloud Logging still works from DO — the agent calls GCP APIs over the internet.
> If you don't need Cloud Logging, omit `GOOGLE_CLOUD_PROJECT`; alerts print to stdout only.

### 5. Validate

```bash
# From Mac — run validate.sh against droplet IP
# Edit validate.sh: replace container exec targets with docker exec equivalents
# Or manually trigger test cases per VALIDATION.md
curl http://<DROPLET_IP>:8080/health
```

---

## Option B — DOKS (Kubernetes)

Mirrors the current GKE setup.

### 1. Create cluster

```bash
doctl kubernetes cluster create health-ai-do \
  --region nyc3 \
  --node-pool "name=default;size=s-2vcpu-4gb;count=2" \
  --wait

# Merge kubeconfig
doctl kubernetes cluster kubeconfig save health-ai-do

# Verify
kubectl get nodes
```

> Check kernel version — must be ≥ 5.11 for `lsm.s/file_open` (bpf_d_path support):
> ```bash
> kubectl get nodes -o wide   # shows OS image
> ```
> DOKS nodes run Ubuntu 22.04 with kernel ~5.15 — should be fine.

### 2. Create namespace + secrets

```bash
kubectl create namespace health-ai

# Supabase credentials (from docker/.env)
kubectl create secret generic supabase-creds \
  --namespace health-ai \
  --from-env-file=github_projects/health-ai/healthcare-ai-microservices/docker/.env
```

### 3. Deploy health-ai services

```bash
cd github_projects/health-ai/healthcare-ai-microservices/kubernetes

# Images already point to ghcr.io — no changes needed
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

kubectl get pods -n health-ai -w
```

> If deployment.yaml references GCP-specific env vars or annotations, remove them.
> Secret ref in deployment.yaml may need updating to match `supabase-creds` secret name above.

### 4. Deploy eBPF DaemonSet

```bash
cd ebpf-edr-demo

# Set env vars and apply
export REGION=nyc3
export CLUSTER_NAME=health-ai-do
export GOOGLE_CLOUD_PROJECT=ebpfagent

envsubst < k8s/ebpf-edr-ds.yaml | kubectl apply -f -

kubectl get pods -n health-ai -l app=ebpf-edr
kubectl logs -n health-ai -l app=ebpf-edr -f
```

### 5. Validate

```bash
# Update validate-gke.sh: replace GKE-specific context with DO cluster context
# It already uses kubectl exec — should work unchanged once KUBECONFIG points to DO

./validate-gke.sh
```

---

## Teardown

```bash
# Option A — delete droplet
doctl compute droplet delete ebpf-test

# Option B — delete DOKS cluster (also deletes all nodes/load balancers)
doctl kubernetes cluster delete health-ai-do

# Verify nothing left running (avoid surprise charges)
doctl compute droplet list
doctl kubernetes cluster list
```

---

## Known Differences vs GCP

| | GCP | DigitalOcean |
|---|---|---|
| Container registry | ghcr.io (already migrated) | Same — no change |
| DB | Supabase external | Same — no change |
| Cloud Logging | Native | Remote API call — works, just adds latency |
| Alert Pub/Sub | GCP Pub/Sub | Not available — stdout only on DO |
| Cluster provisioning | Pulumi | `doctl` CLI (simpler for short test) |
| K8s auth | gcloud + kubeconfig | `doctl kubernetes cluster kubeconfig save` |
