# eBPF EDR Demo

Runtime security monitor for Kubernetes. Detects container escapes, privilege abuse, and data exfiltration using eBPF kernel monitoring. Zero-footprint: no agent inside containers, no application changes.

---

## Quick Start

**Kubernetes Deployment:**
```bash
# Prerequisites: kubectl configured + any workloads deployed
bash scripts/deploy-ebpf-k8s.sh
./validate-do-k8s.sh

# Optional: configure Redis/Supabase in infra/.env for real-time alerts
```

**Docker VM Deployment:**
```bash
# Prerequisites: Linux VM with Docker
make build && make run-docker
tail -f alerts/alert.log

# Optional: set PUBSUB_ADDR or DATABASE_URL for real-time/persistent alerts
```

**Alerts work without Redis/Supabase** — file sink always active. Optional backends enable real-time streaming and persistence.

Full guide: [SETUP.md](SETUP.md)

---

## ⚙️ How It Works

Three specialized eBPF programs monitor strategic kernel hooks and stream events via Linux ring buffer to a Go userspace pipeline:

```
KERNEL SPACE
────────────────────────────────────────────────────────────
    execsnoop              opensnoop            lsm-connect
(sys_enter_execve)      (lsm/file_open)     (lsm/socket_connect)
        │                      │                     │
        └──────────────────────┴─────────────────────┘
                               │ 
                               ▼ BPF Ring Buffer
USERSPACE (Go Agent)
────────────────────────────────────────────────────────────
 [Enricher] ──► [Detector] ──► [Responder] ──► [AlertHandler]
```

**Pipeline:** Event capture → Namespace resolution → YAML rule detection → Active response (kill, block) → Alert dispatch (file, Redis, Supabase)

---

## 🏗️ Architecture & Project Structure

**Monitoring Layer:**
- `kernel/` — C-based eBPF programs for process, file, and network monitoring via ring buffer

**Resolution & Detection:**
- `pkg/workload/` — Real-time container and pod identity resolution
- `pkg/detector/` + `pkg/rules/` — Detection engine with YAML-based ruleset (`rules/*.yaml`:
  per-sensor detections + response, shared lists in `common.yaml`)
- `pkg/detector/response.go` — Active mitigation (kill_process, block_ip)

**Alert Distribution:**
- `pkg/alertsink/` — Multi-destination alerting (file, Redis Pub/Sub, Supabase)

**Deployment:**
- `k8s/ebpf-edr-ds.yaml` — Kubernetes DaemonSet for node-level coverage
- `scripts/deploy-ebpf-k8s.sh` — Generic K8s deployment script
- `cmd/edr-monitor/` — Main agent binary and pipeline orchestration

---

## ✨ Key Features

- ✅ **15 MITRE Techniques** — Container escape, credential access, data exfiltration, discovery, and more
- ✅ **Declarative YAML Rules** — Match, severity, order, exceptions, and response per detection; no BPF or Go changes to tune
- ✅ **Environment-Aware** — Workload identity (Docker/K8s) + ancestry-based trust to suppress infrastructure noise
- ✅ **Active Response** — Immediate automated actions: kill process, block IP (IPv4), with audit trail
- ✅ **Real-Time Alerts** — Instant dispatch via Redis Pub/Sub + persistent storage in Supabase
- ✅ **Zero Footprint** — No sidecar agents, no application changes

---

## 📚 Documentation

**Getting Started:**
- 🛠️ [SETUP.md](SETUP.md) — Quick build, deploy, and validate commands using Makefile and scripts.
- 🌐 [DEPLOYMENT.md](DEPLOYMENT.md) — Detailed configuration for Kubernetes and Docker VM deployments with environment setup.
- 🗺️ [HANDOFF.md](HANDOFF.md) — Current project state, known limitations, and future research roadmap.

**Component Details:**
- 🛡️ [rules/](rules/) — MITRE detection rules, self-documented: per-sensor detections in `process.yaml`/`file.yaml`/`network.yaml`, shared lists + Layer 1/2 config in `common.yaml`.
- 📊 [MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md) — Full mapping of eBPF hooks to MITRE ATT&CK techniques.
- 📖 `pkg/*/README.md` — Deep dives into each component (detector, rules, workload resolver, alertsink).
- 🔧 `kernel/README.md` — eBPF C programs, limitations, and extending detection logic.

---

## 🤝 Contributing

**Bug Reports & Features:**
- Open an issue in the [Issue Tracker](../../issues)

**Development:**
- Reference [SETUP.md](SETUP.md) for build workflow
- See [HANDOFF.md](HANDOFF.md) for current development state
- Run tests: `./validate-do-k8s.sh`

**Questions:**
- See [HANDOFF.md](HANDOFF.md) for known limitations and research roadmap

---

**Last Updated:** 2026-06-30 (DigitalOcean K8s validation complete)
