# k8s/ — Kubernetes Deployment

DaemonSet manifest for deploying eBPF agent across all K8s nodes.

## Files

**ebpf-edr-ds.yaml** — DaemonSet manifest
- Runs one pod per node (tolerates control plane taints)
- Container image: `ghcr.io/yifeng2019uwb/ebpf-edr:latest`
- Privileged: true (required for eBPF)
- Host networking and PID namespace access
- Mounts: `/proc`, `/sys`, `/debugfs` (for eBPF)
- Config via ConfigMap + Secret (environment variables)

## Deployment

Manual deploy:
```bash
kubectl apply -f k8s/ebpf-edr-ds.yaml
```

Scripted deploy (includes credential handling):
```bash
bash scripts/deploy-ebpf-k8s.sh
```

## Configuration

Agent reads from K8s ConfigMap and Secret:

**ConfigMap: `ebpf-alerts`**
- `database-url` — Supabase connection string
- `pubsub-addr` — Redis connection string

**Secret: `ebpf-alerts`**
- `database-key` — Supabase auth token
- `pubsub-key` — Redis password (if needed)

Created by `scripts/deploy-ebpf-k8s.sh` from `infra/.env`.

## Verification

```bash
# Check DaemonSet status
kubectl get daemonset -n kube-system -l app=ebpf-edr

# Check pods
kubectl get pods -n kube-system -l app=ebpf-edr

# Stream logs
kubectl logs -n kube-system -l app=ebpf-edr -f

# Validate
./validate-do-k8s.sh
```

## Troubleshooting

| Issue | Check |
|-------|-------|
| Pod not starting | `kubectl describe pod POD_NAME` |
| No alerts | Check logs: `Rules loaded?`, `redis connected?` |
| CrashLoopBackOff | Kernel doesn't support eBPF (5.8+) or LSM hooks disabled |

---

**Last Updated:** 2026-06-30
