# eBPF Agent Deployment Guide

This guide explains how to deploy the eBPF agent to any Kubernetes cluster.

## For eBPF Project Maintainers

### Publish the eBPF Image

```bash
# Build and push image to container registry
docker build -t ghcr.io/yifeng2019uwb/ebpf-edr:latest -f Dockerfile .
docker push ghcr.io/yifeng2019uwb/ebpf-edr:latest

# Ensure k8s/ebpf-edr-ds.yaml is in main branch (used by services)
git push origin main
```

That's it! The image and DaemonSet YAML are now publicly available for any service to use.

---

## For Service Teams (Health-AI, Order-Processor, etc.)

### Option 1: Add to Service Makefile (Recommended)

This is the cleanest approach — no script duplication, uses existing project configuration.

1. **Add target to your service's `Makefile`:**
```makefile
deploy-ebpf-k8s: ## Deploy eBPF agent to K8s cluster
	@echo "[INFO] Deploying eBPF agent to K8s..."
	@if [ ! -f docker/.env ]; then echo "ERROR: docker/.env not found"; exit 1; fi
	@set -a && source docker/.env && set +a && \
		bash <(curl -fsSL https://raw.githubusercontent.com/yifeng2019uwb/ebpf-edr-demo/main/scripts/deploy-ebpf-k8s.sh)
```

2. **Ensure your `.env` file has K8s cluster info:**
```bash
# docker/.env
CLUSTER_NAME=my-cluster
REGION=us-east-1

# Optional: eBPF configuration
DATABASE_URL=https://your-db.example.com
DATABASE_KEY=your-api-key
PUBSUB_ADDR=redis://your-redis:6379
PUBSUB_KEY=your-password
```

3. **Deploy with one command:**
```bash
make deploy-ebpf-k8s
```

**Example: health-ai**
```bash
cd healthcare-ai-microservices
make deploy-ebpf-k8s
```

This loads CLUSTER_NAME, REGION from `docker/.env` and deploys automatically.

---

## For Local VM / Docker Testing

For testing on a local VM (not Kubernetes), add a `deploy-ebpf-docker` target to your service's Makefile:

```makefile
deploy-ebpf-docker: ## Deploy eBPF agent locally (Docker/VM)
	@echo "[INFO] Deploying eBPF agent to local environment..."
	docker pull ghcr.io/yifeng2019uwb/ebpf-edr:latest
	docker run -d \
		--privileged \
		--pid=host \
		--network=host \
		-v /proc:/proc:ro \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		-v /var/log/ebpf:/var/log/ebpf \
		-e RUNTIME=docker \
		-e DATABASE_URL="${DATABASE_URL}" \
		-e DATABASE_KEY="${DATABASE_KEY}" \
		-e PUBSUB_ADDR="${PUBSUB_ADDR}" \
		-e PUBSUB_KEY="${PUBSUB_KEY}" \
		--name ebpf-edr \
		ghcr.io/yifeng2019uwb/ebpf-edr:latest
	@echo "✓ eBPF agent deployed locally"
	@echo "View logs: docker logs -f ebpf-edr"
```

Then use:
```bash
make deploy-ebpf-docker
```

Environment variables are loaded from your service's `.env` file.

---

### Option 2: Create Standalone Deploy Script

For services without a Makefile, create a simple script:

```bash
#!/bin/bash
# kubernetes/deploy-ebpf.sh
set -a
source ../docker/.env  # or your .env location
set +a

bash <(curl -fsSL https://raw.githubusercontent.com/yifeng2019uwb/ebpf-edr-demo/main/scripts/deploy-ebpf-k8s.sh)
```

Then run:
```bash
bash kubernetes/deploy-ebpf.sh
```

---

### Option 3: Integrate into Service Deploy Script

If you have a custom `kubernetes/deploy.sh`, add this function:

```bash
deploy_ebpf_agent() {
    info "Deploying eBPF agent..."
    bash <(curl -fsSL https://raw.githubusercontent.com/yifeng2019uwb/ebpf-edr-demo/main/scripts/deploy-ebpf-k8s.sh)
}

# Call in your main deploy flow:
# deploy_ebpf_agent
```

---

### Option 4: Manual Deployment

If you just want to deploy without a script:

```bash
# 1. Download the DaemonSet
curl -fsSL https://raw.githubusercontent.com/yifeng2019uwb/ebpf-edr-demo/main/k8s/ebpf-edr-ds.yaml \
    > ebpf-edr-ds.yaml

# 2. Edit it with your cluster info
CLUSTER_NAME=my-cluster REGION=us-east-1 envsubst < ebpf-edr-ds.yaml > ebpf-edr-ds-custom.yaml

# 3. Apply
kubectl apply -f ebpf-edr-ds-custom.yaml

# 4. Verify
kubectl get daemonset -n kube-system -l app=ebpf-edr
```

---

## Verification

```bash
# Check DaemonSet
kubectl get daemonset -n kube-system

# Check pods
kubectl get pods -n kube-system -l app=ebpf-edr

# Check logs
kubectl logs -n kube-system -l app=ebpf-edr -f

# Verify alerts are being generated
kubectl describe daemonset/ebpf-edr -n kube-system
```

---

## Configuration

### Required Environment Variables

- `CLUSTER_NAME` — Name of your K8s cluster (for alert enrichment)
- `REGION` — Region/location of your cluster (for alert enrichment)

### Optional Configuration (if using database/pub-sub sinks)

- `DATABASE_URL` — PostgreSQL or Supabase connection string
- `DATABASE_KEY` — API key for database access
- `PUBSUB_ADDR` — Redis or other pub-sub address
- `PUBSUB_KEY` — Authentication key for pub-sub

These are passed via K8s Secret and ConfigMap.

---

## Troubleshooting

**DaemonSet not creating pods?**
```bash
kubectl describe daemonset/ebpf-edr -n kube-system
kubectl describe node <node-name>  # Check for taints
```

**Pods stuck in pending?**
```bash
kubectl describe pod <pod-name> -n kube-system
kubectl logs <pod-name> -n kube-system
```

**Image pull error?**
```bash
# Check if image is accessible
docker pull ghcr.io/yifeng2019uwb/ebpf-edr:latest
```

---

## Support

- GitHub repo: https://github.com/yifeng2019uwb/ebpf-edr-demo
- eBPF DaemonSet YAML: https://github.com/yifeng2019uwb/ebpf-edr-demo/blob/main/k8s/ebpf-edr-ds.yaml
- Raw DaemonSet (for curl): https://raw.githubusercontent.com/yifeng2019uwb/ebpf-edr-demo/main/k8s/ebpf-edr-ds.yaml
