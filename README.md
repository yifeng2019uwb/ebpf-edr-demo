# eBPF EDR Demo

A runtime security monitor for containers and Kubernetes. It detects container escapes,
credential access, and data exfiltration from the Linux kernel using eBPF — with no agent inside
containers and no application changes.

> **Status: archived (2026-08-12).** Working and validated on Docker and DigitalOcean Kubernetes,
> but no longer developed — the test cluster it was validated against is gone, and a runtime
> security agent should not be changed without somewhere to run it. Read
> [Known limitations](#known-limitations) before running this anywhere real.

---

## How it works

eBPF sensors in the kernel observe process, file, and network activity and stream events to a Go
agent in userspace. The agent resolves each event's workload identity, matches it against
detection rules, takes a response where warranted, and dispatches alerts.

```
KERNEL      process · file · network sensors (eBPF)
              │  ring buffer
USERSPACE   enrich (workload identity) → detect (rules) → respond → alert
```

Detection rules and their responses are declarative (YAML) — tuning a rule needs no kernel or Go
change. Alerts always write to a local file; optional backends add real-time streaming and
persistence.

---

## Repository layout

- `kernel/` — eBPF sensors (process, file, network)
- `pkg/workload/` — container / pod identity resolution
- `pkg/detector/`, `pkg/rules/`, `rules/` — detection engine and declarative rules
- `pkg/alertsink/` — alert delivery (file, streaming, persistence)
- `cmd/` — the agent and the alert-router
- `k8s/`, `scripts/` — deployment

---

## Known limitations

Stated plainly — [HANDOFF.md](HANDOFF.md#known-limitations) has the full list with reasoning and
comparisons to how production EDRs solve each one.

- **`kill_process` can signal the wrong process.** Events may be up to 60s old when the responder
  runs, and nothing checks that the pid still refers to the process that generated the event.
  Tetragon avoids this by keying identity on pid + process start time.
- **Whitelisting matches on `comm`, not on the application.** This is not theoretical: it caused
  the agent to SIGKILL cilium on a live cluster. Do not deploy to a cilium cluster as-is.
- **Network responses are alert-only.** The `block_ip` kernel map is not compiled in.
- **Detection is per-event.** No correlation, sequencing, or behavioral baseline.
- **Alert delivery is synchronous with no timeout** — a slow database sink stalls the alert path
  and alerts get dropped.
- **On GKE, ClusterIP traffic is flagged as external.** GKE service CIDRs sit outside RFC 1918 and
  are missing from `private_ranges` (one YAML entry away). DOKS is unaffected.
- **Load testing was never completed**, so the agent's own throughput ceiling is unmeasured.

---

## Documentation

- **Build / deploy / validate** — [SETUP.md](SETUP.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- **Architecture & design** — [docs/CURRENT_DESIGN.md](docs/CURRENT_DESIGN.md) plus the per-sensor
  and detection design docs under `docs/`
- **Coverage** — [docs/MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md) (techniques ↔ rules)
- **Rules** — [rules/](rules/) (self-documented YAML)
- **Final status, known gaps, close-out notes** — [HANDOFF.md](HANDOFF.md)
- **Components** — each package's `README.md`
