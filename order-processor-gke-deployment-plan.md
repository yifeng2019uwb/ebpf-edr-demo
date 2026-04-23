# GKE Deployment Plan — cloud-native-order-processor

> Status: **Planning / Discussion** — no decisions finalized, pending research items.
> Discussion date: 2026-04-22
> Related: `ebpf-edr-demo/gke-expansion-design.md`

---

## Goal

Deploy cloud-native-order-processor on GKE Standard as a second workload environment
alongside the existing Docker VM. Primary motivations:

1. Practice K8s-based deployment with HPA (auto-scaling simulation)
2. Provide a K8s workload for the eBPF EDR agent to monitor (hybrid demo)
3. Run integration tests from local laptop against GKE gateway to simulate external traffic

---

## Why This Project (not healthcare-ai)

- K8s manifests already exist (`kubernetes/prod/`) — not starting from scratch
- Integration tests are stable and cover all 8 services
- Existing detection rules in the eBPF agent are tuned for these services
- healthcare-ai is in active development — GKE complexity deferred until it stabilizes

---

## Target Architecture

```
GKE Standard cluster (single node, Ubuntu node pool)
  namespace: order-processor

  Deployments (multiple replicas each, HPA-managed):
    gateway           ← exposed externally (LoadBalancer or NodePort)
    auth_service
    user_service
    inventory_service
    order_service
    insights_service
    redis

  Deployment (single replica, ephemeral for dev):
    localstack        ← DynamoDB emulation, port 4566

  eBPF DaemonSet (privileged):
    edr-monitor       ← monitors all pods on this node
```

---

## Existing K8s Manifests: What Needs Adapting

The existing `kubernetes/prod/` manifests are AWS/EKS-oriented. Changes needed for GKE:

| Item | Current (EKS) | GKE target |
|------|--------------|------------|
| Image registry | ECR (`imagePullSecrets: ecr-registry-secret`) | GCR or Artifact Registry |
| DynamoDB backend | Real AWS DynamoDB | LocalStack (same as Docker local) |
| Load balancer annotations | `aws-load-balancer-type: nlb` | Remove or replace with GCP annotations |
| IAM / credentials | IRSA (`AWS_WEB_IDENTITY_TOKEN_FILE`) | `ENVIRONMENT=local` + dummy creds |
| Secrets | AWS Secrets Manager references | K8s Secrets or GCP Secret Manager |
| Storage class | EBS (implied) | GCP standard PD (if needed) |

No application code changes required — all differences are in manifest env vars and infra config.

---

## Database Connection: No Code Change Required

The `DynamoDBManager` in `services/common/src/data/database/dynamodb_connection.py`
already has a 3-way branch:

```python
if ENVIRONMENT == "local":
    # dummy creds + AWS_ENDPOINT_URL → LocalStack
elif AWS_WEB_IDENTITY_TOKEN_FILE:
    # IRSA (EKS native)
elif AWS_ROLE_ARN:
    # STS assume_role
```

For GKE dev deployment, use the `local` branch:
- `ENVIRONMENT=local`
- `AWS_ENDPOINT_URL=http://localstack:4566`
- `AWS_ACCESS_KEY_ID=test`
- `AWS_SECRET_ACCESS_KEY=test`

In K8s, `http://localstack:4566` resolves via the K8s Service named `localstack`
within the same namespace — identical to Docker Compose hostname resolution.

---

## LocalStack in K8s

LocalStack runs as a standard Deployment (ephemeral, data resets on pod restart).
This matches the Docker Compose local behavior — integration tests re-seed data on each run.

Required K8s resources:
- `Deployment`: `localstack/localstack:3.8.1`, port 4566 (same image as Docker Compose)
- `Service`: ClusterIP, named `localstack`, port 4566
- Health check: `GET http://localhost:4566/_localstack/health`

No StatefulSet or PersistentVolumeClaim needed for dev/demo environment.

---

## Scaling Simulation

No real traffic exists to drive CPU-based HPA. Instead, use `kubectl scale` directly
to manually trigger replica changes — gives full control over when pods appear and
disappear, which is what we actually need to validate.

```bash
# scale up — new pods spin up, eBPF must detect new namespaces
kubectl scale deployment auth-service --replicas=3 -n order-processor

# scale back down — pods terminate
kubectl scale deployment auth-service --replicas=1 -n order-processor
```

A simple shell script can cycle through all services:
```bash
for svc in auth-service user-service inventory-service order-service; do
  kubectl scale deployment $svc --replicas=3 -n order-processor
done
# observe eBPF alerts, then scale back
for svc in auth-service user-service inventory-service order-service; do
  kubectl scale deployment $svc --replicas=1 -n order-processor
done
```

**What this validates for eBPF:**
- New pod spins up → new mnt_ns_id appears → K8sResolver cache miss → rescan → pod name resolved
- Pod terminates → stale ns removed from cache
- No false positives from normal pod lifecycle events

No HPA, no Metrics Server needed.

---

## Integration Test Validation from Local Laptop

With gateway exposed via GKE LoadBalancer, integration tests run from the local laptop
against the GKE IP — same tests, different target URL.

```bash
GATEWAY_URL=http://<gke-external-ip>:8080 ./integration_tests/run-it.sh all
```

This exercises:
- Normal service traffic (should produce zero CRITICAL/HIGH eBPF alerts)
- External traffic → gateway → internal services (validates lsm-connect rules)
- The `inventory_service` → CoinGecko path (should produce LOW audit log only)

Same validation methodology as the Docker VM — reuse existing test suite.

---

## Open Research Items

| # | Question | How to answer | Blocks |
|---|----------|---------------|--------|
| R1 | GKE Ubuntu node kernel version | `kubectl describe node \| grep "Kernel Version"` | eBPF CO-RE decision |
| R2 | BTF available on GKE Ubuntu node | SSH to node: `ls /sys/kernel/btf/vmlinux` | eBPF CO-RE decision |

Both answered by the same first GKE node deployment.

---

## Scope Breakdown

| Item | Description | Status |
|------|-------------|--------|
| GKE cluster | GKE Standard, Ubuntu node pool, single node | Not started |
| Image registry | Push service images to GCR/Artifact Registry | Not started |
| Base manifests | Adapt `kubernetes/prod/` for GKE (env vars, registry, annotations) | Not started |
| LocalStack manifest | Deployment + ClusterIP Service | Not started |
| ConfigMap | `ENVIRONMENT=local`, `AWS_ENDPOINT_URL`, table names | Not started |
| Secrets | JWT secret, Redis endpoint | Not started |
| Scale script | Shell script to manually scale replicas up/down | Not started |
| Gateway exposure | LoadBalancer Service for external access | Not started |
| Integration test target | Point test runner at GKE external IP | Not started |

---

## Decisions Not Yet Made

- GKE node machine type (affects how many replicas fit on a single node)
- Image registry: GCR vs Artifact Registry
- Whether a separate GKE overlay (`kubernetes/overlays/gke/`) is created or `prod/` is adapted in place
