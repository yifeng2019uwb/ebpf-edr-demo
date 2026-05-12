# Sensor VM — Implementation Notes

Reference design: [iot-sensor-design.md](iot-sensor-design.md)

---

## Phase 1 — Sensor VM Setup

### Provision all infra

Enable sensor in stack config, then deploy:

```bash
pulumi config set sensorEnabled true  --cwd infra
make infra-up     # deploys base infra + sensor VM + certs
make infra-down   # destroys everything (drop when not in use)
```

Record actual OS and kernel after provisioning:
- OS: _______________
- Kernel: `uname -r` → _______________
- Docker: `docker --version` → _______________

---

## Phase 2 — CO-RE Validation

### Check BTF availability on sensor VM

```bash
ls /sys/kernel/btf/vmlinux   # must exist for CO-RE
```

### Build and load eBPF agent

```bash
# clone repo
git clone https://github.com/yifengzh/ebpf-edr-demo.git
cd ebpf-edr-demo
make build

# run
sudo ./ebpf-edr-demo --runtime=docker
```

**CO-RE result** — record outcome:
- [ ] BPF programs load cleanly on kernel `___`
- [ ] Load fails — error: _______________
- [ ] CO-RE fix required before proceeding

If load fails, check:
```bash
sudo dmesg | grep -i bpf    # verifier errors
sudo ./ebpf-edr-demo --runtime=docker 2>&1 | head -20
```

---

## Phase 3 — Sensor Containers

### Docker network

```bash
docker network create sensor-net
```

### Telemetry collector

Simple HTTP receiver — accepts POST from sensors, logs payload.
Runs on `sensor-net`, ClusterIP equivalent (not exposed externally).

### Sensor containers

Each reads cert + key at startup, POSTs telemetry to `telemetry-collector:8080`.

Verify eBPF observes startup file reads:
```bash
# in agent logs — expect these on sensor container start:
# opensnoop: comm=sensor  file=/etc/sensor/tls/device.key
# opensnoop: comm=sensor  file=/etc/sensor/tls/device.crt
# lsm-connect: comm=sensor  dst=<telemetry-collector IP>:8080 (private → no alert)
```

---

## Phase 4 — Attack Validation

### S1 — Shell spawn on device-health

```bash
docker exec device-health bash -c "echo test"
# expect: CRITICAL shell_spawn_container service=device-health
```

### S2 — C2 beacon from gps-tracker

```bash
docker exec gps-tracker nc -w 3 8.8.8.8 4444 || true
# expect: HIGH unauthorized_external_connect service=gps-tracker
```

### S3 — Key theft from env-sensor

```bash
docker exec env-sensor cat /etc/sensor/tls/device.key
# expect: HIGH sensitive_file_access service=env-sensor
```

---

## Current State

- [ ] Phase 1 — VM provisioned, certs deployed (`make infra-up`)
- [ ] Phase 2 — CO-RE validated
- [ ] Phase 3 — Sensor containers running, eBPF observing file reads + network
- [ ] Phase 4 — All 3 attack scenarios pass
- [ ] Alerts visible in Alert Router

## Notes / Discoveries

_fill in during implementation_
