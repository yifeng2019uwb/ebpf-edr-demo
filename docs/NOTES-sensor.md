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

### BUG FIXED — `service=1` for Docker Compose v2 containers

**Symptom:** Alerts showed `service=1` instead of `service=env-sensor`.

**Root cause:** `normalizeServiceName()` in `pkg/workload/docker_resolver.go` stripped everything after the last `-`. Docker Compose v2 names containers as `<project>-<service>-<replica>` (e.g. `sensor-env-sensor-1`), so the function returned `"1"` instead of `"env-sensor"`.

**Fix:** Replaced `normalizeServiceName` with `dockerIDToInfo()` which reads the `com.docker.compose.service` label from `docker ps` output directly. This correctly resolves `sensor-env-sensor-1` → `env-sensor` via the compose label.

---

### OPEN ISSUE — `sensitive_file_access` never fires for `cat` via `docker exec`

**Symptom:** T1 (shell spawn) and T2/T6 (network tool) alerts fire correctly. T3 (`cat /etc/sensor/tls/device.key`) and T5 (`cat /etc/passwd`) produce no alert.

**What we confirmed works:**
- Host `cat` IS captured by the eBPF probe (`mntNsID=host`, state=host, alert fires)
- `nsenter -t <container_pid> -m cat` IS captured (also shows as host mntNsID — see note below)
- The four BPF programs are loaded and attached (`bpftool prog list` confirms `handle_enter`, `handle_exit`, `handle_connect`, `tracepoint__syscalls__sys_enter_execve`)
- Alpine's busybox `cat` uses `sys_openat` (not the old `sys_open`) — confirmed via kernel ftrace

**What we ruled out:**
1. `tgid != tid` filter blocking events — `/proc/$PID/status` confirms `Tgid == Pid` for docker exec'd processes (single-threaded, tgid = tid)
2. `cat` using `open()` instead of `openat()` — kernel ftrace shows `sys_openat` for cat-<PID>
3. BPF programs not loaded or detached
4. Ring buffer full — other host events (sshd, landscape-sysin) continue flowing through
5. seccomp blocking openat — cat succeeds and reads files correctly

**Key clue — kernel ftrace sees cat but eBPF does not:**
Kernel ftrace (`/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat`) confirms `cat-<PID>` IS calling `sys_openat` when run via `docker exec`. But the eBPF `handle_enter` tracepoint, attached to the same event, does NOT capture these events — nothing appears in `file-enrich` DBG logs.

**Hypothesis — compiled binary is out of date:**
Current source has `int handle_valid_open(...)` as the exit function, but the running binary uses the old name `handle_exit`. The generated Go struct (`fileProgramSpecs`) also expects `handle_exit`. This means `make generate` has not been re-run after renaming the function. The deployed BPF binary and Go wrapper are internally consistent (both use `handle_exit`) but diverge from the current source.

**Hypothesis — cgroup or namespace scoping on tracepoint attachment:**
nsenter cat is captured but docker exec cat is not. nsenter directly calls `setns()` from a host process. Docker exec goes through dockerd → containerd → runc. runc creates the container process via `clone()` with cgroup constraints. A possible (unconfirmed) cause: the tracepoint BPF program may be restricted by a cgroup attachment or a kernel policy that limits tracepoint visibility for processes created under certain cgroup hierarchies.

**Investigation commands:**
```bash
# Verify BPF programs are still attached
sudo bpftool prog list

# Check pending_opens map contents live
sudo bpftool map dump id 36

# Confirm tgid == tid for a docker exec'd process
sudo docker exec -d sensor-env-sensor-1 sleep 30; sleep 0.3
PID=$(pgrep -n sleep)
cat /proc/$PID/status | grep -E '^(Pid|Tgid|NSpid|Threads)'

# See if ftrace (not eBPF) captures cat
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo > /sys/kernel/debug/tracing/trace
echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on
sudo docker exec sensor-env-sensor-1 cat /etc/passwd > /dev/null
grep cat /sys/kernel/debug/tracing/trace | head -5

# Check if eBPF sees openat events at all (counts)
sudo bpftool prog show id 146   # handle_enter — look for run_cnt if kernel supports it
```

**Recommended next steps:**
1. Re-run `make generate` to sync the BPF source, compiled binary, and Go bindings — the rename to `handle_valid_open` has never been compiled and deployed.
2. After regenerating, rebuild with `make build` and redeploy (`make docker-push` + restart service on VM).
3. If still broken after regenerating: add a `bpf_printk` debug log inside `handle_enter` to confirm the BPF hook IS running for docker exec'd PIDs, then check `sudo cat /sys/kernel/debug/tracing/trace_pipe`.
4. `make generate` requires clang 14+ on a Linux host — the sensor VM has `clang 14` installed (`sudo apt-get install -y clang llvm libbpf-dev`).
