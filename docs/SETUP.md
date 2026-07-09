# Setup Guide

This project is an **eBPF EDR sensor** — the core is the kernel sensors + Go detection
pipeline. It is cloud-neutral: it runs on any Linux host (bare Docker) or any managed
Kubernetes cluster. Alerts flow to local file + optional Redis + optional Postgres/Supabase;
there is no cloud-provider lock-in. (An earlier GCP Cloud-Logging/Pub-Sub path was retired for
cost — it is not part of the current system.)

## One-time: Install Go 1.24 (Linux build VM)

BPF regeneration requires a Linux host with `clang`, `llvm`, `libbpf-dev`, and `bpftool`.
Any cloud VM or local Linux box works.

```bash
wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Verify
go version  # should show go1.24.2
```

## One-time: Project Setup

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
pkg/bpf/gen.go   — go:generate directives; one per BPF program:
                     bpf2go compiles .bpf.c → .o + Go wrapper (_bpfel.go)
pkg/bpf/         — generated Go wrappers (committed, no clang needed in CI)
pkg/detector/    — detection engine: yaml_detector.go (matching + severity),
                     response_policy.go (kill/block actions), ancestry_cache.go
rules/default.yaml — detection rule data (self-documented)
pkg/workload/    — WorkloadResolver: DockerResolver, K8sResolver
pkg/alertsink/   — file / redis / supabase sinks
internal/config/ — env-var config (sinks, workload identity)
cmd/edr-monitor/ — main entry point
```

## Development Workflow

### When you change BPF C code (kernel/*.bpf.c or kernel/*.h)

`go generate` must run on Linux (requires clang + bpftool + bpf2go).

```bash
# Step 1 — on the Linux build VM: rebuild BPF objects + Go binary
make rebuild              # go generate + go build → bin/ebpf-edr

# Step 2 — commit generated wrappers (so CI needs no clang)
git add pkg/bpf/ && git commit -m "..." && git push

# Step 3 — build + push the container image
make docker-push-ghcr-prebuilt   # builds & pushes ghcr.io/.../ebpf-edr:latest

# Step 4 — redeploy the DaemonSet to your managed K8s cluster
bash scripts/deploy-ebpf-k8s.sh
# Or in health_ai, run ./deploy.sh app(all) to deploy the ebpf agent to health-ai
# Using ./deploy.sh destroy for removing

# Step 5 — validate
./validate-do-k8s.sh
```

### When you change only Go code (pkg/ or cmd/) or rules (rules/default.yaml)

`go generate` is not needed — BPF objects are unchanged. Safe to build on any machine.

```bash
make build                       # cross-compile linux/amd64 → bin/ebpf-edr
make docker-push-ghcr-prebuilt   # push image to ghcr.io
git add -A && git commit -m "..." && git push
bash scripts/deploy-ebpf-k8s.sh  # redeploy DaemonSet
./validate-do-k8s.sh
```

### When you change only the DaemonSet YAML (k8s/ebpf-edr-ds.yaml)

No rebuild needed — `deploy-ebpf-k8s.sh` applies the manifest from the repo.

```bash
git add k8s/ebpf-edr-ds.yaml && git commit -m "..." && git push
bash scripts/deploy-ebpf-k8s.sh
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
make generate   # dumps vmlinux.h via bpftool, then runs go generate ./pkg/bpf/
```

## Alert sinks & configuration

The agent writes every alert to a **local file** and, when configured, fans out to a
**pub/sub** channel (real-time dashboard) and a **database** (persistence). All three are
backend-agnostic; the current deployment uses file + Redis + Supabase.

Configuration is read from environment variables (loaded from `infra/.env` for local runs;
provided by the DaemonSet manifest on K8s). See `internal/config/config.go`.

| Env var | Sink | Notes |
|---|---|---|
| `ALERT_LOG_PATH`   | File (always on)  | Defaults to `alerts/alert.log`. On K8s set to a hostPath mount (e.g. `/alerts/alert.log`) so alerts survive pod restarts. |
| `PUBSUB_ADDR`      | Redis pub/sub     | e.g. `redis://host:port`. Feeds the Alert Router UI. If unset, sink is skipped. `LOW` alerts are dropped from this channel (telemetry only). |
| `DATABASE_URL` + `DATABASE_KEY` | Postgres/Supabase | Persistent store for all levels (incl. `LOW` telemetry). If unset, sink is skipped. |
| `REGION`, `CLUSTER_NAME`, `ENV` | — | Workload identity stamped onto alerts. |
| `SERVICE_CIDR`     | — | Optional; marks in-cluster service traffic as internal. |

`infra/.env` holds these credentials and is **not** committed (secrets live on the host/VM).

## Running the Full System

### On a Docker host

**Terminal 1 — EDR agent (must run as root):**

```bash
make build && make run-docker
```

On startup the agent logs which sinks connected, e.g.:
```
redis sink connected: redis://...
supabase sink connected
```
(The file sink is always active; Redis/Supabase log only when their env vars are set.)

**Terminal 2 — Docker validation:**

```bash
sudo ./validate.sh
```

### On managed Kubernetes

```bash
bash scripts/deploy-ebpf-k8s.sh   # applies the DaemonSet from k8s/ebpf-edr-ds.yaml
./validate-do-k8s.sh              # expect 11/11
```

### Alert Router UI (any machine)

```bash
make run-alert-router
```

Open **http://localhost:8888** — subscribes to the Redis channel and streams alerts from all
agents (Docker + K8s) in real time.

### Expected alerts after Docker validation (`validate.sh`, 10 tests)

Service assignment: `user_service` (T1/T3/T7/T9), `order_service` (T2/T6),
`insights_service` (T5/T8), `auth_service` (T4/T10).

| Test | Level    | Rule                                   | Response     | Trigger                |
|------|----------|----------------------------------------|--------------|------------------------|
| T1   | CRITICAL | `T1059_unix_shell_execution`           | —            | shell spawn in container |
| T2   | CRITICAL | `T1003_008_os_credential_dumping`      | kill_process | `/etc/shadow`          |
| T3   | HIGH     | `T1552_004_private_keys`               | kill_process | `/tmp/id_rsa`          |
| T4   | HIGH     | `T1041_exfiltration_over_c2`           | block_ip     | connect to `8.8.8.8`   |
| T5   | MEDIUM   | `T1082_system_info_discovery`          | —            | `/etc/passwd`          |
| T6   | HIGH     | `T1036_masquerading`                   | —            | renamed binary         |
| T7   | HIGH     | `T1053_003_scheduled_task_cron`        | —            | `/etc/crontab`         |
| T8   | MEDIUM   | `T1070_003_clear_command_history`      | —            | `/tmp/.bash_history`   |
| T9   | HIGH     | `T1552_001_credentials_in_files`       | —            | `/tmp/app.env`         |
| T10  | HIGH     | `T1613_container_resource_discovery`   | —            | container mgmt tool exec |

Response actions come from `pkg/detector/response_policy.go`: `kill_process` for
credential-dumping and private-key reads, `block_ip` for C2 exfiltration. (T1611 host-escape
kill is present but commented out until its allowlist is complete.)

## Verifying alerts are flowing

The agent needs no cloud query to verify — alerts land in the local file first.

```bash
# On the agent host / node — tail the alert log
tail -f alerts/alert.log            # Docker (or the ALERT_LOG_PATH you set)

# On K8s — check the agent pods and the hostPath log
kubectl logs -n kube-system -l app=ebpf-edr -f
```

If no alerts appear:
1. Confirm the agent is running and loaded its BPF programs (check its startup logs).
2. Confirm sink connect lines (`redis sink connected` / `supabase sink connected`) if you
   expect those sinks.
3. Trigger alerts with `./validate.sh` (Docker) or `./validate-do-k8s.sh` (K8s), then re-check.
4. For the live UI, confirm `PUBSUB_ADDR` is set and the Alert Router shows "Connected to Redis".
