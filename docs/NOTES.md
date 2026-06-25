# Operational Notes

## Current Status

**Coverage:** 15 of ~15 single-event-detectable MITRE techniques implemented and validated
- Docker VM: 13 tests pass
- GKE: 11 tests pass
- See [MITRE-COVERAGE.md](MITRE-COVERAGE.md) for complete technique list

**Architecture:** 2-service design
1. **eBPF Agent** (deployed everywhere) — detects & enforces rules in < 10ms
2. **Central Control Service** (single deployment, planned) — dashboard + behavioral analysis

**Scope Status:**
- ✅ Single-event detection (current)
- 🔲 Stateful detection (Phase 2: T1046 network scanning, T1059 scripting interpreter)
- 🔲 Behavioral/anomaly detection (planned for Central Control Service)

**Next Evaluation:** See [CAPABILITY_CONSIDERATIONS.md](../../CAPABILITY_CONSIDERATIONS.md) — checkpoint document for deciding which capabilities to add next (command-line args, DNS monitoring, behavioral baselines, anomaly detection, etc.)

---

## Deployment Workflow

### Go-only changes (safe on Mac)

```bash
make build                       # cross-compile linux/amd64 binary
make docker-push-ghcr-prebuilt   # build image from committed binary, push to ghcr.io
```

Then redeploy:
- **Docker VM**: restart the agent
- **K8s**: restart the DaemonSet pod

### BPF C changes (requires Linux rebuild)

Must run on a Linux VM with clang + libbpf-dev:

```bash
make rebuild                     # go generate + go build
git add pkg/bpf/ ebpf-edr && git commit -m "..."
make docker-push-ghcr-prebuilt   # build and push image
```

---

## Monitoring Alerts

### Local file + stdout (always-on)

```bash
# Docker VM
tail -f /alerts/alert.log

# K8s
kubectl logs -f -l app=ebpf-edr
```

### Alert format

Each alert line contains:
- `level`: CRITICAL, HIGH, MEDIUM
- `rule`: MITRE technique (e.g., T1059_unix_shell_execution)
- `service`: workload name (k8s pod or Docker container)
- `pid`, `uid`, `comm`: process info
- `action`: response taken (kill_process, block_ip, none)
- `filename` or `dst`: file path or network destination (if applicable)

### Real-time monitoring service

If enabled via `GOOGLE_CLOUD_PROJECT` env var:
- **Cloud Logging**: GCP console or `gcloud logging read` CLI (if GOOGLE_CLOUD_PROJECT set)
- **Pub/Sub**: Alert Router WebSocket UI (if configured)

---

## Troubleshooting

### Agent not starting

```bash
# Check if eBPF programs load
sudo ./ebpf-edr --runtime=docker

# Common errors:
# - BPF verifier: unsupported instruction — Linux kernel too old
# - Permission denied — not running as root
# - Map full — adjust ring buffer size in .bpf.c (RINGBUF_SIZE)
```

### No alerts appearing

1. Check agent is running: `sudo ./ebpf-edr` should show startup logs
2. Check alerts file: `cat /alerts/alert.log`
3. Generate test alert: `echo "test" > /tmp/test` (should trigger T1036_masquerading)
4. Check workload resolver: service name should appear in alert (not "unknown")

### High false positive rate

See [DETECTION-POLICY.md](DETECTION-POLICY.md) — update whitelists in `pkg/detector/policy.go`

---

## Known Limitations

- **GCP metadata server call**: `gkeServiceCIDR()` in `policy.go` auto-detects GKE service CIDR from GCP metadata — only works if running in GCP
- **IP blocking disabled**: LPMTrie map removed due to BPF verifier limits on some kernels
- **No DNS monitoring**: Limited to process, file, network syscalls
- **Deduplication window**: 1 second — same file opened by same PID twice within 1s is counted as one alert

---

## Environment Variables

| Var | Purpose | Required? |
|-----|---------|-----------|
| `GOOGLE_CLOUD_PROJECT` | GCP project for Cloud Logging + Pub/Sub (optional) | No |
| `CLUSTER_NAME` | K8s cluster name (logged in alerts) | For K8s |
| `REGION` | GCP region (logged in alerts) | For K8s |

If not set, agent works with local file + stdout only.

---

## Reference — Archived Documentation

Infrastructure and deployment docs for past environments (GCP, DigitalOcean transition):

- `docs/archive/SETUP.md` — GCP infrastructure setup (Pulumi, GKE, credentials)
- `docs/archive/TESTING-GUIDE.md` — Full system testing on GCP + GKE
- `docs/archive/AGENT-DEPLOY.md` — Agent deployment procedures (GCP-specific)
- `docs/archive/DO-MIGRATE.md` — DigitalOcean migration guide
- `docs/archive/NOTES-legacy.md` — Implementation work log (detailed history)

These are kept for reference if setting up similar infrastructure. For current operations, use this NOTES.md.
