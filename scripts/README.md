# scripts/ — Deployment & Utility Scripts

Automated deployment and validation scripts for all environments.

## Scripts

**deploy-ebpf-k8s.sh** — Deploy eBPF agent to any Kubernetes cluster
- Loads credentials from `infra/.env`
- Creates ConfigMap + Secret with environment variables
- Downloads DaemonSet from GitHub repo
- Applies to current kubectl context
- Works on any K8s cluster (GKE, DO, EKS, AKS, etc.)

Usage:
```bash
bash scripts/deploy-ebpf-k8s.sh
```

**validate-do-k8s.sh** — Functional validation for DigitalOcean K8s (or any K8s)
- 12 MITRE detection scenarios
- Tests alert generation and routing
- Uses kubectl logs for alert fetching
- Reports pass/fail count

Usage:
```bash
./validate-do-k8s.sh [--context <kubectl-context>]
```

Tests (V1–V12):
- V2–V4, V9, V12: Detection across services
- V3, V8, V10: Auth-service specific
- V5–V7, V11: Cross-service validation
- Result: 12/12 should pass

## Configuration

Scripts read from `infra/.env`:

```bash
PUBSUB_ADDR=redis://user:pass@host:6379
DATABASE_URL=postgres://...
DATABASE_KEY=...
```

If not set, services are optional (file sink always works).

## Troubleshooting

**Deploy fails:**
- Check kubectl context: `kubectl config current-context`
- Check credentials: `cat infra/.env`
- Check DNS: `kubectl cluster-info`

**Validation times out:**
- Increase timeout in validate-do-k8s.sh
- Check pod logs: `kubectl logs -n kube-system -l app=ebpf-edr`
- Verify rules loaded: grep "rules: loaded" in logs

---

**Last Updated:** 2026-06-30
