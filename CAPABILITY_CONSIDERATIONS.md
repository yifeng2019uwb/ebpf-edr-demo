# Capability Considerations

Checkpoint for evaluating features to add next. Compared against industry standard (Falco).

---

## Monitoring Capabilities

| Capability            | What                                          | Current | Falco |
|:---|:---|:---:|:---:|
| Command-Line Args     | Full process cmdline (not just binary name)   | ❌ | ✅ |
| DNS Monitoring        | Capture domain queries (C2, exfil detection)  | ❌ | ✅ |
| Privilege Escalation  | Detect sudo, setuid, CAP changes              | ❌ | ✅ |
| Kernel Module Tracking | Monitor loaded kernel modules                | ❌ | ✅ |

---

## Response Capabilities

| Capability        | What                                  | Current | Falco |
|:---|:---|:---:|:---:|
| Network Blocking  | Block unauthorized connections        | ❌ Disabled | ❌ |
| Process Kill      | Terminate malicious processes         | ✅ | ⚠️ |
| Process Isolation | Isolate process (network namespace)   | ❌ | ✅ |
| File Quarantine   | Prevent access to suspicious files    | ❌ | ❌ |

---

## Detection Capabilities

| Capability                | What                              | Current | Falco |
|:---|:---|:---:|:---:|
| Single-Event Rules        | Detect from one event             | ✅ 15 | ✅ 100+ |
| Multi-Event Correlation   | Detect attack chains              | ❌ | ✅ |
| Behavioral Baselines      | Learn normal, alert on deviation  | ❌ | ✅ |
| Anomaly Detection         | Detect statistical deviations     | ❌ | ✅ |
| Threat Intelligence       | Integration with malware/C2 feeds | ❌ | ⚠️ |

---

## Storage & Visibility

| Capability            | What                          | Current | Falco |
|:---|:---|:---:|:---:|
| Local File Logging    | Write alerts to local file    | ✅ | ✅ |
| Centralized Logging   | Queryable database storage    | ❌ | ✅ |
| Real-Time Dashboard   | Live alert monitoring UI      | ❌ | ✅ |
| Alert Search          | Query historical alerts       | ❌ | ⚠️ |

---

## Rule Coverage

| Metric            | Current | Falco |
|:---|:---|:---|
| MITRE Techniques  | 15 (single-event) | 100+ |
| Detection Depth   | Signature-based | Signature + Behavioral + Stateful |
| FP Tuning         | Manual whitelists | Automated baselines |

---

## Validation & Feasibility

| Capability                | Can Validate?    | Blocks |
|:--------------------------|:-----------------|:---------------------------|
| Command-Line Args         | ✅ Local testing | Kernel memory safety       |
| DNS Monitoring            | ✅ Local testing | LSM hook (kernel 5.11+)    |
| Privilege Escalation      | ✅ Local testing | CAP tracking complexity    |
| Multi-Event Correlation   | ✅ Local testing | None (pure Go)             |
| Network Blocking          | ✅ Test on DO VM | BPF verifier (test kernel version) |
| Behavioral Baselines      | ✅ Real workload | Central DB setup, 24h baseline |
| Anomaly Detection         | ✅ Real workload | Central DB setup, data collection |
| Persistent Storage        | ✅ Real workload | Central DB credentials       |

---

---

## Proposed Architecture

**Current (2 services):**
- eBPF Agent (deployed everywhere) — detects & enforces
- Dashboard (central) — display alerts

**Proposed (still 2 services, consolidated):**
- eBPF Agent (deployed everywhere) — detects & enforces
- Central Control Service (central) — dashboard + behavioral analysis + policy publishing

**Why consolidated:**
- Single point for all central logic
- Dashboard and behavioral use same data (Central DB, Pub/Sub)
- Simpler deployment, shared infrastructure

---

## Communication Pattern

```
eBPF Agent (everywhere)          Central Control Service (once)
    │                                      │
    ├─ Generates alerts ───────────────→ Central DB
    │                                      │
    ├─ Subscribes to policies ← ← ← ← ← Pub/Sub
    │                                      │
    └─ Enforces (10ms)                    ├─ Dashboard (displays alerts)
                                          ├─ Behavioral analyzer
                                          │  (detects anomalies, publishes policies)
                                          └─ Policy publisher (Pub/Sub)
```

---

## Implementation Architecture (Industry-Validated)

### Dual-Path Approach

**Path 1: Real-time Agent Decisions** (< 10ms)
- Agent detects known patterns (T1059 shell, T1105 tool transfer)
- Agent enforces immediately (kill_process, block_ip)
- No central query needed
- Example: SentinelOne responds in milliseconds

**Path 2: Central Anomaly Detection** (500ms-2000ms)
- Central service queries Central DB historical data
- Central detects behavioral anomalies (scanning patterns, baselines)
- Central publishes policies to Pub/Sub
- Agents receive and enforce
- Latency acceptable: industry SLAs for anomaly response are 6-24 hours

### Why This Works

**Anomaly detection inherently requires:**
- Historical data analysis (can't be done in 10ms locally)
- Central processing (need full picture across services)
- 500ms-2000ms latency is NOT a problem for this class of threat

**Industry validation:**
- SentinelOne: millisecond responses on agent (real-time threats)
- CrowdStrike: 6-24 hour SLAs for incident containment (behavioral threats)
- Anomaly detection benefit: 91% noise reduction, 7-minute MTTD improvement

---

## Recommended Approach

Use **Pub/Sub for policy distribution** (same pattern as current alerts):

```
Central Service (Python/Go)
  └─ Detects anomaly from Central DB
  └─ Publishes policy to "edr-policies" topic
     ├─ {"action": "kill_process", "pattern": "filesystem_scanning"}
     └─ {"action": "block_ip", "pattern": "c2_communication"}

eBPF Agents (each environment)
  └─ Subscribe to "edr-policies"
  └─ Receive policy updates
  └─ Enforce locally (milliseconds after receiving)
```

**Latency**: 500ms-2000ms for anomaly-based response is acceptable per industry standards.

---

## Sources & Industry Validation

- [SentinelOne EDR Response Latency](https://www.decryptiondigest.com/blog/best-edr-platforms-2026)
- [Anomaly Detection at Scale](https://arxiv.org/pdf/2404.16887)
- [Incident Response SLA Standards](https://trainingcamp.com/glossary/incident-response-sla/)
- [Detection-Response Gap Analysis](https://medium.com/@jsocitblog/the-dangerous-gap-between-detection-and-response-854d4644b269)
- [CrowdStrike Agentic Security](https://www.crowdstrike.com/en-us/platform/)
- [EDR Response Capabilities 2025](https://fidelissecurity.com/cybersecurity-101/endpoint-security/future-of-edr/)

---

## Before Deciding

1. What can be validated on current infrastructure?
2. What blocks each capability (kernel version, BPF complexity, external deps)?
3. How would you test each one?
