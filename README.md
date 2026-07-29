# eBPF EDR Demo

A runtime security monitor for containers and Kubernetes. It detects container escapes,
credential access, and data exfiltration from the Linux kernel using eBPF — with no agent inside
containers and no application changes.

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

## Documentation

- **Build / deploy / validate** — [SETUP.md](SETUP.md), [DEPLOYMENT.md](DEPLOYMENT.md)
- **Architecture & design** — [docs/CURRENT_DESIGN.md](docs/CURRENT_DESIGN.md) plus the per-sensor
  and detection design docs under `docs/`
- **Coverage** — [docs/MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md) (techniques ↔ rules)
- **Rules** — [rules/](rules/) (self-documented YAML)
- **Current status & roadmap** — [HANDOFF.md](HANDOFF.md)
- **Components** — each package's `README.md`
