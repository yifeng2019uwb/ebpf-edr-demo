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
- `opensnoop` → raw file events  
- `lsm-connect` → raw network events
- Enricher: Add workload identity
- Detector: Apply YAML rules
- Responder: Execute actions (kill, block)
- AlertHandler: Send to sinks

**Pending Buffer:**
- Container starting = namespace not yet in resolver cache
- Events buffered for 60 seconds with retries
- After timeout, promoted to `StateUnknown` (possible escape)

**Deduplication:**
- File events from multi-threaded processes deduplicated (1s window)
- Prevents alert spam

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
# Build
make build

# Run (auto-detects environment)
./ebpf-edr --runtime=k8s        # Kubernetes mode
./ebpf-edr --runtime=docker     # Docker mode
./ebpf-edr --runtime=auto       # Auto-detect
```

## Logs

Useful log patterns:

```
rules: loaded from rules/default.yaml
redis sink connected: redis://...
supabase sink connection test passed
BPF programs loaded: execsnoop, opensnoop, lsm-connect
ALERT level=CRITICAL rule=T1059_unix_shell_execution ...
```

See: `SETUP.md` for troubleshooting.

---

**Last Updated:** 2026-06-30
