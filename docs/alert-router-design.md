# eBPF EDR — Monitoring Service Design

## Goal

Cloud Logging (Phase 6) provides centralized retention and compliance, but has 30–90s
ingestion latency — unacceptable for a real-time security monitoring UI. The monitoring
service is a separate real-time path: alerts flow from the agent to a browser dashboard
in under one second, while Cloud Logging handles the compliance/retention side independently.

---

## Scope

### Prerequisites

- Agent writes structured alerts with versioned JSON payload
- Agent deployed on GKE DaemonSet and Docker VM
- GCP project with Pub/Sub API enabled
- `GOOGLE_CLOUD_PROJECT` env var injected in DaemonSet

### Current — Phase 7

Real-time alert delivery from every agent node to a browser dashboard, with an
extensible routing layer that can adopt new outputs without agent changes.

### Future — not yet scoped

| Feature | Why deferred |
|---|---|
| PagerDuty / OpsGenie | Requires external account + on-call schedule setup; `AlertOutput` interface makes it a one-file addition when needed |
| Slack webhook | Requires Slack workspace setup; trivial to add once interface exists |
| Email digest | Format and schedule decisions need real ops experience; SMTP/SendGrid is an external dependency |
| Alert deduplication in router | Needs real event volume data to choose dedup window and thresholds — guessing now would produce wrong numbers |
| Alert Router HA (multiple replicas) | Pub/Sub competing-consumer pattern handles this naturally; not needed for single-cluster demo |
| Cross-node correlation (EventForwarder) | Different design and different data — see `gke-expansion-design.md §5`; operates on all enriched events (pre-detection), not alerts |

The `AlertOutput` interface is the key extensibility point — future outputs require implementing one interface and registering at startup. No changes to the router core or agent.

---

## Why Two Paths (not one)

| | Cloud Logging | Pub/Sub → Alert Router |
|---|---|---|
| Ingestion latency | 30–90s | <1s |
| Purpose | Compliance, forensics, long-term retention | Real-time monitoring, notification |
| Consumer | Query on demand (gcloud, Cloud Console) | WebSocket UI, future notification outputs |
| Retention | 365 days hot + 3 years cold | 7-day message TTL (stream only) |
| Cost (low volume) | ~free (50 GiB/month free tier) | ~free (10 GiB/month free tier) |

Pub/Sub and Cloud Logging are complementary, not alternatives. Both paths are always active.

---

## Three-Path Agent Output

```
Agent (GKE DaemonSet / Docker VM)
  │
  ├── local file + stdout        (always-on: ops debug, node-level audit, no external dependency)
  │
  ├── Cloud Logging SDK          (retention/compliance — see centralized-logging.md)
  │
  └── Pub/Sub topic: edr-alerts  (real-time stream, <1s latency)
       └── Alert Router
              ├── WebSocket → Monitoring UI    [Phase 7, planned]
              ├── PagerDuty / OpsGenie         [future — extensibility point, not yet scoped]
              ├── Slack webhook                [future — extensibility point, not yet scoped]
              └── Email digest                 [future — extensibility point, not yet scoped]
```

### Agent publish behavior

- Publish is fire-and-forget (async) — does not block local write or Cloud Logging path
- CRITICAL and HIGH always published; MEDIUM/LOW configurable
- If Pub/Sub publish fails: log and continue — Cloud Logging is the source of truth for retention
- No retry on Pub/Sub publish failure: real-time path is best-effort; compliance path is durable

---

## Alert Router — falcosidekick Pattern

The Alert Router is a small, always-running service that subscribes to the Pub/Sub topic
and routes alerts to one or more outputs. This follows the same separation-of-concerns
pattern as [falcosidekick](https://github.com/falcosecurity/falcosidekick): the agent emits
a stream; routing and notification are a separate concern.

### AlertOutput interface

```go
type AlertOutput interface {
    Name() string
    Send(ctx context.Context, alert alert.Alert) error
}
```

The router holds `[]AlertOutput`. Adding a new destination = implement one interface and
register it at startup. Zero changes to the router core or the agent.

### Phase 7 scope — WebSocket output only

```go
type WebSocketOutput struct {
    hub *Hub  // manages connected browser clients
}
```

- Alert Router subscribes to Pub/Sub `edr-alerts` (pull subscription)
- On each message: deserialize alert JSON, call `hub.Broadcast(alert)`
- Hub fans out to all connected WebSocket clients
- Browser UI opens WebSocket connection and displays live alert feed

### Future outputs (not yet scoped — implement when needed)

- **PagerDuty / OpsGenie** — CRITICAL alerts trigger immediate on-call page (<1 min SLA)
- **Slack webhook** — CRITICAL+HIGH alerts posted to security team channel
- **Email digest** — configurable daily/weekly summary

**Industry two-tier notification pattern (for reference when implementing):**
- Tier 1 (CRITICAL): immediate page via PagerDuty/OpsGenie — wake-up-at-3am severity
- Tier 2 (HIGH): Slack channel — team visibility, does not page on-call
- MEDIUM/LOW: Cloud Logging query on demand, no push notification

---

## Relation to gke-expansion-design.md §5 (Cross-Node Correlation)

`gke-expansion-design.md` §5 describes an `EventForwarder` for **cross-node correlation** —
all enriched events forwarded before detection, for distributed pattern detection
(e.g., 5 pods → same external IP within 60s). This is distinct from the Alert Router:

| | Alert Router (Phase 7) | EventForwarder (future) |
|---|---|---|
| What is forwarded | Alerts only (post-detection) | All enriched events (pre-detection) |
| Volume | Low (alerts are rare) | High (every kernel event) |
| Purpose | Real-time display, notification | Cross-node pattern detection |
| Consumer | WebSocket UI / notification outputs | Stateful correlation engine |

Both use Pub/Sub transport but serve different use cases. They should use separate topics:
- `edr-alerts` — Alert Router (this design)
- `edr-events` — EventForwarder / Correlation Engine (future)

---

## GCP Infrastructure (Phase 7, Pulumi-managed)

Resources needed:
- Pub/Sub topic: `edr-alerts`
- Pub/Sub subscription: `edr-alerts-router-sub` (pull, for Alert Router)
- IAM: agent service account → `roles/pubsub.publisher`
- IAM: Alert Router service account → `roles/pubsub.subscriber`
- Alert Router deployment: Cloud Run (stateless pull loop) or GKE Deployment

---

## Implementation Status

- [ ] Agent — add Pub/Sub async publish to alert path (alongside Cloud Logging write)
- [ ] Pub/Sub topic + subscription + IAM (Pulumi, extend existing `infra/` stack)
- [ ] Alert Router service — subscribe, deserialize, fan out via `AlertOutput` interface
- [ ] WebSocket hub — manage browser client connections, broadcast alerts
- [ ] Browser UI — WebSocket client, live alert feed display
