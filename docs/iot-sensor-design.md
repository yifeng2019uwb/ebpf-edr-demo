# eBPF EDR — Continuous Telemetry Workload Design

> Status: **Planning — not yet implemented**
> Simulated with: IoT sensors (env-sensor, gps-tracker, device-health)

---

## 1. Goal

All current monitored workloads are **API services** — HTTP servers that respond to requests.
This adds a second workload domain: **continuous telemetry** — processes that emit data on a
loop with no request/response pattern.

From a runtime security perspective this is a distinct threat surface: the process runs
indefinitely, maintains persistent network egress, and has no legitimate reason to spawn a
shell or read credential files. The same eBPF rules apply, but the behavioral baseline is
different from an API service.

**Scope**: three simulated sensor containers in a `sensor-fleet` namespace, monitored by the
same eBPF agent, with 3 attack scenarios in `validate-gke.sh`.

---

## 2. What Changes (and What Doesn't)

**No changes to the eBPF agent.** The agent monitors by mount namespace ID — it picks up any
container on the node automatically, regardless of workload type or namespace.

**What we add:**

| Component | Description |
|-----------|-------------|
| `sensor/main.go` | Go binary — reads `SENSOR_TYPE` + `DEVICE_ID` env vars, streams JSON telemetry |
| `sensor/Dockerfile` | Multi-stage Go build. One image for all three sensor types |
| `k8s/sensor-deployment.yaml` | 3 Deployments in `sensor-fleet` namespace |
| `validate-gke.sh` V11–V13 | 3 attack scenarios, one per sensor type |

---

## 3. Sensor Types

One Go binary, three configurations via `SENSOR_TYPE` env var. Each type streams only the
fields its physical hardware produces, at a realistic interval.

| Sensor | Service name | Data fields | Interval |
|--------|-------------|-------------|----------|
| Environmental | `env-sensor` | temp_c, humidity_pct, pressure_hpa | 30s |
| GPS tracker | `gps-tracker` | lat, lon, speed_kmh, heading_deg, altitude_m | 2s |
| Device health | `device-health` | battery_pct, rssi_dbm, firmware_ver | 5m |

### Sample payloads

```json
// env-sensor
{ "device_id": "env-sensor-001", "ts": "...", "temp_c": 24.04, "humidity_pct": 43.6, "pressure_hpa": 1010.8 }

// gps-tracker
{ "device_id": "gps-tracker-001", "ts": "...", "lat": 47.6062, "lon": -122.3321, "speed_kmh": 12.4, "heading_deg": 270.0, "altitude_m": 52.1 }

// device-health
{ "device_id": "health-monitor-001", "ts": "...", "battery_pct": 78.3, "rssi_dbm": -72, "firmware_ver": "1.4.2" }
```

### Identity in alerts

All three sensors appear in ebpf alerts with `namespace=sensor-fleet` and the correct
`service=` name (`env-sensor`, `gps-tracker`, `device-health`).

---

## 4. Runtime Semantics

Each sensor type has a known behavioral baseline. Deviations from it are the detection signal —
not the rule firing in isolation.

| Sensor | Expected behavior | Deviation = threat signal |
|--------|------------------|--------------------------|
| `gps-tracker` | Persistent outbound telemetry to known endpoints | Connection to unknown IP or non-telemetry port |
| `device-health` | Periodic health reporting — no shell, no credential access | Any shell execution is unambiguous RCE |
| `env-sensor` | Reads sensors, signs and emits readings | Access to signing key material enables telemetry forgery |

This is what makes continuous telemetry a distinct security domain from API services: the
behavioral baseline is narrower. An API service might legitimately spawn subprocesses, read
config files, or connect to many backends. A telemetry process does one thing — emit data to
one destination. The smaller the expected behavior, the stronger every alert signal.

---

## 5. Attack Scenarios

### S1 — Firmware Shell Spawn (CRITICAL)

**Target**: `device-health`

**Threat**: Attacker compromises the firmware update path and spawns a shell. A device health
monitor has no legitimate reason to ever run a shell — any spawn is unambiguous RCE.

**Expected**: `CRITICAL shell_spawn_container service=device-health namespace=sensor-fleet`

---

### S2 — GPS Tracker C2 Beacon (HIGH)

**Target**: `gps-tracker`

**Threat**: Compromised GPS tracker connects to an attacker C2 server. Trackers have legitimate
network egress for telemetry — an attacker exploits this by redirecting to an unknown external
IP on a non-telemetry port.

**Expected**: `HIGH unauthorized_external_connect service=gps-tracker`

---

### S3 — Device Signing Key Theft (HIGH)

**Target**: `env-sensor`

**Threat**: Attacker reads the device signing key used to authenticate telemetry. Stealing it
enables telemetry forgery — injecting false sensor readings without backend detection.

**Expected**: `HIGH sensitive_file_access service=env-sensor` (`.key` suffix)

---

## 6. Out of Scope

| Item | Reason |
|------|--------|
| Real sensor protocols (MQTT, CoAP) | Simulation only — domain is the point, not the protocol |
| Telemetry collector/receiver | Sensors stream to stdout; no backend needed |
| New detection rules | Existing rules cover all 3 scenarios |
| Multi-sensor fleet scale | One pod per type is enough to validate the domain |
| healthcare-ai integration | Separate project, separate phase |

---

## 7. Implementation Plan

**Phase 1 — Sensor workload**
- `sensor/main.go` + `Dockerfile`
- `k8s/sensor-deployment.yaml` — `sensor-fleet` namespace, 3 Deployments
- Verify: ebpf alerts show correct `service=` and `namespace=sensor-fleet`

**Phase 2 — Attack validation**
- Add V11–V13 to `validate-gke.sh`
- Update `VALIDATION-GKE.md` and `README.md` to reflect 12/12

**Phase 3 — Docker VM (optional)**
- Add sensor to Docker Compose, add to `validate.sh`

---

## 8. Definition of Done

- Three sensor pods running in `sensor-fleet` namespace: `env-sensor`, `gps-tracker`, `device-health`
- Each pod logs correct JSON payload for its type at its interval
- `./validate-gke.sh` passes V11, V12, V13
- No new eBPF probes, no new detection rules, no agent changes
