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

**Scope**: three simulated sensor containers on a dedicated sensor VM, monitored by the same
eBPF agent in Docker mode, with 3 sensor-specific attack scenarios.

---

## 2. Deployment

**Separate GCP VM — not the existing Docker VM, not GKE.**

This simulates the real-world separation between edge sensor nodes and cloud backend services.
The VM is droppable — created for testing, destroyed when not needed.

Its OS and kernel version are intentionally not fixed to match the existing Docker VM.
This makes it the **CO-RE validation environment**: the eBPF agent binary must load BPF
programs on whatever kernel the new VM runs. If a compatibility gap is found, CO-RE support
must be implemented before sensor work proceeds.

All agents write to the same Cloud Logging destination and Pub/Sub topic — sensor alerts
appear in the Alert Router dashboard alongside Docker VM and GKE alerts.

---

## 3. Sensor Types

Each sensor type streams only the fields its physical hardware produces, at a realistic interval.

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

### Sensor environment

Each sensor container has:
- Device certificate + private key (mounted from host, simulating device identity provisioned at manufacturing)
- Config file (endpoint URL, device ID)
- Outbound connection to internal `telemetry-collector` (same Docker network, private IP)

This gives eBPF meaningful events to observe at startup (file reads) and runtime (network).

### Identity in alerts

Docker mode — no K8s namespace. Identity from container name:

| Field | Value |
|-------|-------|
| `service` | `env-sensor` / `gps-tracker` / `device-health` |
| `runtime` | `docker` |
| `namespace` | — |

---

## 4. Runtime Semantics

Each sensor type has a known behavioral baseline. Deviations from it are the detection signal —
not the rule firing in isolation.

| Sensor | Expected behavior | Deviation = threat signal |
|--------|------------------|--------------------------|
| `gps-tracker` | Persistent outbound telemetry to known internal endpoint | Connection to unknown external IP or non-telemetry port |
| `device-health` | Periodic health reporting — no shell, no credential access | Any shell execution is unambiguous RCE |
| `env-sensor` | Reads cert + key at startup, signs and emits readings | Access to key material by unexpected process enables telemetry forgery |

The behavioral baseline is narrower than an API service. A telemetry process does one thing —
emit data to one destination. The smaller the expected behavior, the stronger every alert signal.

---

## 5. Attack Scenarios

### S1 — Firmware Shell Spawn (CRITICAL)

**Target**: `device-health`

**Threat**: Attacker compromises the firmware update path and spawns a shell. A device health
monitor has no legitimate reason to ever run a shell — any spawn is unambiguous RCE.

**Expected**: `CRITICAL shell_spawn_container service=device-health`

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
| New detection rules | Existing rules cover all 3 scenarios |
| Multi-sensor fleet scale | One container per type is enough to validate the domain |
| healthcare-ai integration | Separate project, separate phase |
| Bare-metal / systemd sensors | Future direction — loses mount namespace identity needed by current workload resolver |

---

## 7. Implementation Phases

**Phase 1 — Sensor VM + CO-RE validation**
- Provision separate GCP VM
- Deploy eBPF agent — verify BPF programs load on this kernel
- If CO-RE gap: implement BTF relocation support before proceeding

**Phase 2 — Sensor environment**
- Device cert + key generation (one-time, simulates manufacturing provisioning)
- Sensor containers + internal telemetry collector
- Verify: eBPF alerts carry correct `service=` per sensor type

**Phase 3 — Attack validation**
- Attack scenarios for sensor VM
- Alerts appear in Alert Router alongside Docker VM and GKE alerts

---

## 8. Definition of Done

- Separate GCP sensor VM running, eBPF agent loaded — CO-RE result documented
- Three sensor containers running: `env-sensor`, `gps-tracker`, `device-health`
- Each container reads cert + key at startup, connects to internal telemetry collector
- eBPF alerts carry correct `service=` per sensor type
- All 3 attack scenarios pass
- Alerts visible in Alert Router dashboard alongside other environments
- No new eBPF probes, no new detection rules, no agent binary changes
