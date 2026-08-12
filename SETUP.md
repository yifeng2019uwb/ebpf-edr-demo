# Setup Guide — eBPF EDR Demo

Quick start. For details, see referenced files.

---

## One-time Setup (Linux VM)

```bash
# Install Go 1.24+, clang, llvm, libbpf-dev
sudo apt-get install -y clang llvm libbpf-dev
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Project
cd ~/workspace/ebpf-edr-demo
go mod tidy
make generate   # compile eBPF programs
```

See: [DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed environment setup

---

## Building

```bash
make rebuild              # Full rebuild (BPF + binary) — Linux only
make build                # Binary only — safe on Mac
make docker-push-ghcr     # Push image to ghcr.io
make test                 # Run unit tests
```

---

## Deployment

### DigitalOcean Kubernetes (primary)

**Initial deploy:**
```bash
bash scripts/deploy-ebpf-k8s.sh
./validate-do-k8s.sh
```

**Update existing deployment:**
- If agent code changed → `make docker-push-ghcr` then `bash scripts/deploy-ebpf-k8s.sh`
- If only config/rules changed → just `bash scripts/deploy-ebpf-k8s.sh` (no rebuild needed)

See: [DEPLOYMENT.md](docs/DEPLOYMENT.md#digitalocean-kubernetes)

### Local Docker VM testing

```bash
make run-docker
tail -f alerts/alert.log
```

See: [DEPLOYMENT.md](docs/DEPLOYMENT.md#local-docker-vm)

---

## Configuration

Set environment variables in `infra/.env`:

```bash
PUBSUB_ADDR=redis://user:pass@host:6379
DATABASE_URL=postgres://...pooler.supabase.com:6543
DATABASE_KEY=...
```

See: [DEPLOYMENT.md](docs/DEPLOYMENT.md#configuration)

---

## Project Structure

```
kernel/          → eBPF C programs
pkg/bpf/         → Generated Go wrappers (from bpf2go)
pkg/detector/    → Detection rules (YAML-based)
pkg/rules/       → Rule loader + common.yaml
pkg/workload/    → Container/pod resolver
pkg/alertsink/   → Alert outputs (file, Redis, Supabase)
cmd/edr-monitor/ → Main agent binary
k8s/             → DaemonSet manifest
scripts/         → Deployment scripts
rules/           → Detection rules in YAML
```

---

## Key Workflows

| Change Type         | Command             | See                              |
|---------------------|---------------------|---------------------------------|
| BPF C code          | `make rebuild`      | [DEPLOYMENT.md](docs/DEPLOYMENT.md)   |
| Go code only        | `make build`        | [DEPLOYMENT.md](docs/DEPLOYMENT.md)   |
| Detection rules     | Edit `rules/*.yaml`  | [HANDOFF.md](HANDOFF.md)   |
| DaemonSet config    | Edit `k8s/ebpf-edr-ds.yaml` | [DEPLOYMENT.md](docs/DEPLOYMENT.md) |

---

## Testing & Validation

```bash
./validate-do-k8s.sh        # 12 MITRE detection scenarios
make test                   # Unit tests
```

See: [HANDOFF.md](HANDOFF.md) (Validation section)

---

## Monitoring

```bash
make run-alert-router       # Web UI for alerts (http://localhost:8888)
kubectl logs -n kube-system -l app=ebpf-edr -f
redis-cli -u redis://... SUBSCRIBE edr-alerts
```

---

## Documentation

- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** — Full deployment guide (K8s, Docker, config)
- **[HANDOFF.md](HANDOFF.md)** — Session progress, architecture, known issues
- **[rules/](rules/)** — Detection rules (self-documented): per-sensor detections in
  `process.yaml`/`file.yaml`/`network.yaml`, shared lists in `common.yaml`
- **[MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md)** — Supported attack techniques

---

**Last Updated:** 2026-06-30
