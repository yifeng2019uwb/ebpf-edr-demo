# Alert Router Design

## Goal

Provide real-time alert delivery from the eBPF agent to a monitoring UI, separate from Cloud Logging's compliance/retention path.

**Two-path architecture:**
- **Cloud Logging**: 30-90s latency, long-term retention (365 days), compliance
- **Pub/Sub → Alert Router**: <1s latency, real-time monitoring UI, extensible notification outputs

---

## Architecture

```
Agent (GKE DaemonSet / Docker VM)
  │
  ├── local file + stdout        (always-on: ops debug, no external dependency)
  │
  ├── Cloud Logging              (retention/compliance, 365 days)
  │
  └── Pub/Sub topic: edr-alerts  (real-time stream, <1s latency)
       │
       └── Alert Router
              ├── WebSocket → Monitoring Dashboard
              ├── PagerDuty / OpsGenie (extensibility point)
              ├── Slack webhook (extensibility point)
              └── Email digest (extensibility point)
```

---

## Design Principles

### AlertOutput Interface

Extensibility via interface: adding a new notification output requires implementing one interface and registering at startup. Zero changes to agent or router core.

```go
type AlertOutput interface {
    Name() string
    Send(ctx context.Context, alert alert.Alert) error
}
```

### Two-Tier Notification Pattern

| Severity | Destination | SLA |
|----------|-------------|-----|
| CRITICAL | PagerDuty/OpsGenie (page on-call) | <1 min |
| HIGH | Slack (team visibility) | — |
| MEDIUM/LOW | Cloud Logging (query on demand) | — |

---

## Relation to Centralized Logging

See [centralized-logging.md](centralized-logging.md) for the compliance/retention path.

Alert Router (post-detection alerts) is distinct from potential future cross-node correlation (pre-detection events).
