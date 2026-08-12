# Setup Guide

An eBPF EDR sensor: kernel sensors + a Go detection pipeline. Cloud-neutral — runs on any Linux
host (bare Docker) or any managed Kubernetes cluster. Alerts flow to a local file plus optional
Redis (live dashboard) and Postgres/Supabase (persistence); no cloud-provider lock-in.

Architecture and the source tree are in [CURRENT_DESIGN.md](CURRENT_DESIGN.md) — not repeated here.
Every command below is a `make` target (see the `Makefile`) or a checked-in script; edit those, not
this doc, when a command changes.

## Prerequisites

- **Run the agent:** a Linux host, root (loads eBPF + LSM programs), a kernel with BTF
  (`/sys/kernel/btf/vmlinux`) and BPF-LSM enabled. cgroup v2 unified hierarchy (the agent fails
  fast on cgroup v1 — see [FILE-EVENT-DESIGN.md](FILE-EVENT-DESIGN.md)).
- **Build the Go binary:** Go 1.24+. Cross-compiles to linux/amd64 from any host (incl. macOS).
- **Regenerate BPF objects** (only when a `kernel/*.bpf.c` or `event.h` changes): a Linux host with
  `clang`, `llvm`, `libbpf-dev`, `bpftool`.

## Build · test

```bash
make build     # cross-compile linux/amd64 → bin/ebpf-edr (any host)
make test      # unit tests (see the Makefile for the package list)
make vet       # go vet on the non-BPF packages
```

BPF changes need a Linux box with the toolchain above:

```bash
make generate  # bpftool BTF dump + go generate → regenerates pkg/bpf/*_bpfel.go
make rebuild   # generate + build
```

The generated `pkg/bpf/*_bpfel.go` wrappers are committed, so CI and macOS builds need no clang.

## Run

### Docker host

```bash
make build && make run-docker   # agent, as root
sudo ./validate.sh              # attack simulation + no-FP check (Docker VM)
```

### Kubernetes

```bash
make docker-push-ghcr-prebuilt  # push image from the committed binary (needs GHCR_TOKEN)
./k8s/deploy.sh                 # applies k8s/ebpf-edr-ds.yaml; auto-detects cluster from kubectl context
./validate-do-k8s.sh            # attack simulation on the cluster
```

For deploying the published image into a *separate* service's cluster (health-ai, order-processor),
see [DEPLOYMENT.md](DEPLOYMENT.md) — that path curls the manifest from GitHub via
`scripts/deploy-ebpf-k8s.sh`.

### Alert Router UI

```bash
make run-alert-router           # http://localhost:8888 — live stream from all agents via Redis
```

## Sink configuration

Config comes from environment variables (loaded from `infra/.env` locally; injected by the
DaemonSet manifest on K8s). `infra/.env` holds secrets and is **not** committed. See
`internal/config/config.go`.

| Env var | Sink | Notes |
|---|---|---|
| `ALERT_LOG_PATH` | File (always on) | Defaults to `alerts/alert.log`. On K8s use a hostPath so alerts survive pod restarts. |
| `PUBSUB_ADDR` (+ `PUBSUB_KEY`) | Redis pub/sub | Feeds the Alert Router UI. Unset → skipped. **LOW alerts are dropped** from this channel (telemetry only). |
| `DATABASE_URL` + `DATABASE_KEY` | Postgres/Supabase | Persists all levels incl. LOW. Unset → skipped. |
| `REGION`, `CLUSTER_NAME`, `ENV` | — | Workload identity stamped onto alerts. |
| `SERVICE_CIDR` | — | Optional; marks in-cluster service traffic as internal. |

## Verify alerts are flowing

The file sink lands first — no cloud query needed.

```bash
tail -f alerts/alert.log                       # Docker (or your ALERT_LOG_PATH)
kubectl logs -n kube-system -l app=ebpf-edr -f # K8s
```

If nothing appears: confirm the agent loaded its BPF programs (startup logs), confirm the expected
`redis sink connected` / `supabase sink connected` lines, then trigger the validation script for
your environment. Per-rule attack commands and expected alerts are in
[VALIDATION.md](VALIDATION.md) and [MITRE-COVERAGE.md](MITRE-COVERAGE.md).
