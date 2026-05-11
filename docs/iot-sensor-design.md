# eBPF EDR — IoT Sensor Simulation Design

> Status: **Planning — not yet implemented**
> Goal: Add a simulated sensor endpoint as a second workload domain for the eBPF EDR agent.

---

## 1. Goal

All current ebpf-edr-demo monitored workloads are **API services** — HTTP servers that respond to
requests (order-processor on Docker VM + GKE). The ebpf agent detects threats from any container,
but the observable behavior is always the same domain: API request handling.

This adds one new workload domain: an **IoT sensor endpoint** — a process that streams telemetry
data on a loop rather than serving HTTP. Different communication pattern, different attack surface.

**One sentence scope**: a containerized sensor process that streams fake telemetry in its own
`sensor-fleet` namespace, monitored by the same eBPF agent, with 3 sensor-specific attack
scenarios added to validate-gke.sh.

---

## 2. What Changes (and What Doesn't)

### No changes to the ebpf agent

The agent detects by mount namespace ID — it doesn't care what kind of workload is inside the
container. No new probes, no new rules, no pipeline changes needed.

### What we add

| Component | Description |
|-----------|-------------|
| `sensor/sensor.py` | Single Python script — reads `SENSOR_TYPE` env var, streams matching payload at type-specific interval |
| `sensor/Dockerfile` | One image for all three sensor types (`python:3.12-slim`) |
| `k8s/sensor-deployment.yaml` | 3 Deployments: `env-sensor` (30s), `gps-tracker` (2s), `device-health` (5m) |
| Attack scripts | 3 `kubectl exec` commands in `validate-gke.sh` (V11–V13), one per sensor type |

---

## 3. Sensor Workload Design

### Three sensor types — one image

Each sensor type is a separate container running the same `sensor.py` script, configured via
environment variables (`SENSOR_TYPE`, `DEVICE_ID`). Data fields and streaming interval match
real-world IoT conventions — each type reports only what its physical hardware would produce.

| Sensor | Service name | Data fields | Interval | Rationale |
|--------|-------------|-------------|----------|-----------|
| Environmental | `env-sensor` | temp_c, humidity_pct, pressure_hpa | 30s | Same physical chip — slow-changing ambient data |
| GPS tracker | `gps-tracker` | lat, lon, speed_kmh, heading_deg, altitude_m | 2s | Position tracking needs high frequency |
| Device health | `device-health` | battery_pct, rssi_dbm, firmware_ver | 5m | Fleet management — very slow-changing |

### Payload examples (real-world format)

```json
// env-sensor — every 30s
{
  "device_id": "env-sensor-001",
  "ts": "2026-05-11T10:00:00Z",
  "temp_c": 24.04,
  "humidity_pct": 43.6,
  "pressure_hpa": 1010.8
}

// gps-tracker — every 2s
{
  "device_id": "gps-tracker-001",
  "ts": "2026-05-11T10:00:01Z",
  "lat": 47.6062,
  "lon": -122.3321,
  "speed_kmh": 12.4,
  "heading_deg": 270.0,
  "altitude_m": 52.1
}

// device-health — every 5min
{
  "device_id": "health-monitor-001",
  "ts": "2026-05-11T10:00:00Z",
  "battery_pct": 78.3,
  "rssi_dbm": -72,
  "signal_quality": "good",
  "firmware_ver": "1.4.2"
}
```

GPS includes speed + heading (not just lat/lon) — bare coordinates are not actionable without
direction and velocity. Device health includes `rssi_dbm` and `firmware_ver` — standard fields
in any real sensor fleet management system.

### Identity in ebpf alerts

| Field | env-sensor | gps-tracker | device-health |
|-------|------------|-------------|---------------|
| `service` | `env-sensor` | `gps-tracker` | `device-health` |
| `namespace` | `sensor-fleet` | `sensor-fleet` | `sensor-fleet` |
| `runtime` | `k8s` (GKE) or `docker` (VM) | same | same |

Sensors live in the `sensor-fleet` namespace — separate from `order-processor`.
No agent changes — identity comes from K8s pod labels. The agent monitors all namespaces
on the node by mount namespace ID, so `sensor-fleet` is picked up automatically.

---

## 4. Attack Scenarios

Targeted at specific sensor types — each scenario matches the real threat model for that device.

### S1 — Firmware Shell Spawn on Device Health Sensor (CRITICAL)

**Target**: `device-health` pod

**Threat**: Attacker compromises the firmware update path on a device health monitor and spawns
a shell. Health monitors are attractive targets because they have persistent network connectivity
for fleet management callbacks.

**Trigger**:
```bash
kubectl exec <device-health-pod> -n sensor-fleet -- bash -c "echo 'fake firmware update'"
```

**Expected**: `CRITICAL shell_spawn_container service=device-health namespace=sensor-fleet`

**Why sensor-specific**: A health monitor process has no legitimate reason to spawn a shell.
Any shell from inside this container is unambiguous RCE — cleaner signal than an API service
where shell tools sometimes appear in init scripts.

---

### S2 — GPS Tracker C2 Beacon (HIGH)

**Target**: `gps-tracker` pod

**Threat**: Compromised GPS tracker phones home to attacker C2 server. GPS trackers already
have network egress for legitimate position reporting — an attacker exploits this existing
channel by redirecting to a C2 IP on an unusual port.

**Trigger**:
```bash
kubectl exec <gps-tracker-pod> -n sensor-fleet -- \
  python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('8.8.8.8',4444)); s.close()"
```

**Expected**: `HIGH unauthorized_external_connect service=gps-tracker dst_ip=8.8.8.8 dst_port=4444`

**Why sensor-specific**: GPS trackers send telemetry to known backend endpoints on known ports.
A connection to an unknown IP on port 4444 (not a telemetry port) is a strong exfiltration signal.

---

### S3 — Device Signing Key Theft from Environmental Sensor (HIGH)

**Target**: `env-sensor` pod

**Threat**: Attacker reads the device signing key used to authenticate telemetry data to the
backend. Forging telemetry (fake temperature/pressure readings) is a real attack vector in
industrial and defense sensor networks.

**Trigger**:
```bash
kubectl exec <env-sensor-pod> -n sensor-fleet -- bash -c \
  "mkdir -p /etc/sensor && echo 'signing-key-material' > /etc/sensor/device.key && cat /etc/sensor/device.key"
```

**Expected**: `HIGH sensitive_file_access service=env-sensor` (`.key` suffix match)

**Why sensor-specific**: Device signing keys authenticate telemetry to the backend. Reading them
enables telemetry forgery — an attacker can inject false environmental readings into the data
stream without being detected by the backend.

---

## 5. Out of Scope

| Item | Reason |
|------|--------|
| Real sensor hardware/protocol (MQTT, CoAP) | Simulation only — the domain is the point, not the protocol |
| Telemetry collector service | Sensor streams to stdout; no receiver needed |
| Sensor-specific detection rules | Existing rules cover all 3 scenarios — no new rules needed |
| Multi-sensor fleet | One sensor pod is enough to validate the domain type |
| healthcare-ai integration | Separate project, separate phase |

---

## 6. Implementation Plan

### Phase 1 — Sensor container (Day 1)

1. Write `sensor/sensor.py` — telemetry loop, no dependencies beyond stdlib
2. Write `sensor/Dockerfile` — `python:3.12-slim`, single file, no build step
3. Write `k8s/sensor-deployment.yaml` — 3 Deployments with correct service labels, `sensor-fleet` namespace
4. Deploy: `kubectl create namespace sensor-fleet && kubectl apply -f k8s/sensor-deployment.yaml`
5. Verify: `kubectl logs <pod> -n sensor-fleet` shows correct JSON payload for each sensor type

**Done when**: logs show sensor readings and ebpf alerts carry `service=env-sensor` / `gps-tracker` / `device-health` with `namespace=sensor-fleet`.

### Phase 2 — Attack validation (Day 1–2)

1. Add V11–V13 to `validate-gke.sh` (S1, S2, S3 above)
2. Run `./validate-gke.sh` — confirm 3 new PASS entries
3. Update `VALIDATION-GKE.md` results checklist (12/12)
4. Update `README.md` GKE table (12/12)

**Done when**: `./validate-gke.sh` passes all V2–V13 with no new SKIP or FAIL.

### Phase 3 — Docker VM (optional, after GKE passes)

Add sensor to Docker Compose on VM, add to `validate.sh`. Same 3 scenarios.

---

## 7. File Layout

```
sensor/
  sensor.py                    — single script, reads SENSOR_TYPE + DEVICE_ID from env
  Dockerfile                   — python:3.12-slim, one image for all three sensor types
k8s/
  sensor-deployment.yaml       — 3 Deployments: env-sensor, gps-tracker, device-health
validate-gke.sh                — add V11 (device-health shell), V12 (gps C2), V13 (env key theft)
docs/
  VALIDATION-GKE.md            — add S1–S3 test cases, update checklist to 12/12
  README.md                    — update GKE table to 12/12
```

---

## 8. Definition of Done

- Three sensor pods running in `sensor-fleet` namespace on GKE: `env-sensor`, `gps-tracker`, `device-health`
- `kubectl logs` for each pod shows correct JSON payload for its type at its interval
- ebpf alerts carry the correct `service=` name per sensor type (`env-sensor`, `gps-tracker`, `device-health`)
- `./validate-gke.sh` passes V11 (device-health shell spawn), V12 (gps-tracker C2 beacon), V13 (env-sensor key theft)
- README and VALIDATION-GKE.md updated to reflect 12/12

No new eBPF probes. No new detection rules. No changes to the agent binary.
The sensor is a new domain — the existing rules already cover it.
