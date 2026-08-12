# cmd/edr-monitor — Main eBPF Agent Binary

Entry point that orchestrates the full eBPF monitoring pipeline. Runs in every pod/VM you want to monitor.

## What It Does

1. Load eBPF programs into kernel
2. Start workload resolver (identify containers)
3. Load detection rules from YAML
4. Route events through pipeline:
   - Kernel events (ring buffer) → Enricher → Detector → Responder → AlertHandler
5. Handle graceful shutdown on SIGTERM

## Key Components

**Event Pipeline:**
- `execsnoop` → raw process events
- `lsm-file` → raw file events
- `lsm-connect` → raw network events
- Enricher: Add workload identity
- Detector: Apply YAML rules
- Responder: Execute actions (kill; block_ip is alert-only, kernel side not compiled)
- AlertHandler: Send to sinks

**Pending Buffer:**
- Container starting = namespace not yet in resolver cache
- Events buffered for 60 seconds with retries
- After timeout, promoted to `StateUnknown` — ancestry-verified infrastructure is
  suppressed; the rest goes to LOW telemetry (visibility gap, not an escape signal)

**Deduplication:**
- File events from multi-threaded processes deduplicated (1s window) — `internal/dedup`
- Prevents alert spam
- Swept on a 10s ticker; entries are keyed by `{pid, filename}`, so without the sweep the
  maps would grow for the lifetime of the process

## Configuration

Environment variables in `infra/.env`:

```bash
PUBSUB_ADDR=redis://...           # For alerts (optional)
DATABASE_URL=postgres://...       # For persistent storage (optional)
DATABASE_KEY=...                  # Supabase auth (optional)
GOOGLE_CLOUD_PROJECT=...          # GCP only, for local Docker testing
```

## Usage

```bash
# Build (cross-compiles to linux/amd64; needs pkg/bpf/*.o from `make generate`)
make build

# Run — takes no flags. The container runtime is detected per event from the cgroup
# by pkg/workload.Engine, so one binary handles Docker and CRI on the same host.
sudo ./bin/ebpf-edr
```

## Logs

Useful log patterns:

```
rules: loaded from rules/common.yaml
rules: loaded 4 detections from rules/process.yaml   (+ file.yaml, network.yaml)
resolver engine: cgroup v2 (unified hierarchy) confirmed on /sys/fs/cgroup
resolver engine: prewarm resolved N container namespaces from /proc
redis sink connected: redis://...
supabase sink connected via ...
ALERT level=CRITICAL rule=T1059_unix_shell_execution ...
response: killed pid=... comm=... rule=T1552_004_private_keys ...
```

Signs of degraded operation:

```
resolver engine: metadata lookup failed for container ... — falling back to short-id
warning: rawCh full, N kernel events dropped
ERROR: alertCh full, alert dropped: ...
```

Per-event `DEBUG:` tracing was removed in the 2026-08-12 close-out; what remains is startup
state, errors, and degradation.

See: `SETUP.md` for troubleshooting.

---

**Last Updated:** 2026-08-12
