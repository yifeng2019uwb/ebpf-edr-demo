# eBPF EDR Demo

eBPF-based runtime security monitor for containerized workloads. Detects and responds to threats at the kernel level — no agent inside containers, no application changes required.

## Status

| Environment | Tests | Status |
|-------------|-------|--------|
| **Docker VM** | 13 | ✅ 13/13 pass |
| **GKE** | 11 | ✅ 11/11 pass |

---

## How It Works

Three eBPF programs attach to kernel hooks and stream events via ring buffer to a Go userspace pipeline:

```
KERNEL
─────────────────────────────────────────────────────
execsnoop            lsm-file              lsm-connect
sys_enter_execve     lsm/file_open         lsm/socket_connect
     │                     │                     │
     └─────────────────────┴─────────────────────┘
                           │  ring buffer
USERSPACE (Go)
─────────────────────────────────────────────────────
Enricher → Detector → Responder → AlertHandler
```

**Pipeline:** Mount namespace ID → Workload identity → Detection rules → Response actions (kill, block) → Alerts (local file, monitoring service)

---

## Documentation

**Project Overview:**
- [MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md) — 15 techniques covered, detection rules
- [DETECTION-POLICY.md](docs/DETECTION-POLICY.md) — whitelists, false positive handling

**Testing & Validation:**
- [VALIDATION.md](docs/VALIDATION.md) — Docker VM test guide
- [VALIDATION-GKE.md](docs/VALIDATION-GKE.md) — GKE test guide

**Operations:**
- [NOTES.md](docs/NOTES.md) — deployment, monitoring, troubleshooting
- [ENV-FINDINGS.md](docs/ENV-FINDINGS.md) — environment observations, findings

**Detailed Reference:**
- [REPORT.md](docs/REPORT.md) — full architecture, pipeline, implementation details
- [HANDOFF.md](HANDOFF.md) — session handoff, current state, next priorities

**Archived:**
- `docs/archive/` — old designs, infrastructure setups, and work logs (see [NOTES.md](docs/NOTES.md) for reference links)
