# pkg/alertsink — Alert Output Handlers

Routes detected alerts to different backends: local file, Redis pub/sub, Supabase database.

## What It Does

Implements pluggable alert sinks so alerts reach multiple destinations simultaneously:
- **File** — Always active (`alerts/alert.log`)
- **Redis** — Real-time pub/sub if `PUBSUB_ADDR` configured
- **Supabase** — Persistent storage if `DATABASE_URL` configured

## Files

- **file_sink.go** — Write alerts to local file
  - One alert per line (JSON)
  - Always enabled
  - For local debugging and audit trail
  
- **redis_sink.go** — Publish alerts to Redis channel
  - Channel: `edr-alerts`
  - Real-time delivery to subscribers
  - Feeds Alert Router web UI
  
- **supabase_sink.go** — Write alerts to PostgreSQL (Supabase)
  - Persistent storage for historical analysis
  - Uses Supavisor pooler endpoint (IPv4)
  - Handles schema and connection pooling

## Configuration

Set environment variables in `infra/.env`:

```bash
# File sink (no config needed, always active)

# Redis pub/sub
PUBSUB_ADDR=redis://user:pass@host:6379

# Supabase PostgreSQL
DATABASE_URL=postgres://postgres.PROJECT_ID:PASS@aws-1-REGION.pooler.supabase.com:6543/postgres
DATABASE_KEY=eyJhbGc...  # from Supabase dashboard
```

## Usage

```go
// Create sinks
fileSink, _ := alertsink.NewFileSink("alerts/alert.log")
redisSink, _ := alertsink.NewRedisSink(os.Getenv("PUBSUB_ADDR"))
supasink, _ := alertsink.NewSupabaseSink(os.Getenv("DATABASE_URL"), os.Getenv("DATABASE_KEY"))

// Add to handler
handler := alert.NewHandler([]alert.Sink{fileSink, redisSink, supasink})

// Send alert
handler.Send(alert)
```

See: `cmd/edr-monitor/main.go` for full pipeline.

## Alert Format

Alerts contain:
- `level` — CRITICAL, HIGH, MEDIUM, LOW
- `rule` — MITRE technique (T1059_unix_shell_execution)
- `service` — container/pod name
- `namespace` — K8s namespace
- `pid`, `ppid`, `uid` — process IDs
- `comm` — process command
- `message` — human-readable description
- `response_action` — kill_process, blockIP, none

---

**Last Updated:** 2026-06-30
