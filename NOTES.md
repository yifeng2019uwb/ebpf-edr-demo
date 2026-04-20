# Work Log / Notes

---

## Completed

- [x] `execsnoop.bpf.c` + `main.go` — process monitor capturing execve events
- [x] `exitsnoop.bpf.c` — exit monitor with ring buffer, both running concurrently
- [x] Integration tests pass while monitor runs — no false positives (snapshot: PrintProcess&Exit.png)
- [x] `curl_from_container` MEDIUM alert confirmed — triggered inside container, logged correctly
- [x] Fix `alert.go` format string bug — `comm=%!s(int32=...)` → correct output ✅
- [x] `rules.go` — detection rules: shell spawn, network tools, curl, short-lived exit
- [x] `alert.go` — Alert struct with Ppid, Uid, Container fields
- [x] `mnt_ns` container correlation — `execsnoop.bpf.c` reads `mnt_ns_id` via CO-RE, `container.go` resolves to container name
- [x] Fix `ExitEvent` struct alignment bug — Go struct field order did not match C struct (see below)

---

## Key Technical Notes

### TASK_COMM_LEN: 16 → 128
Changed `#define TASK_COMM_LEN 16` to `128` in `execsnoop.h` to capture full executable paths.
Must match Go struct field size — `Comm [128]byte`.

### mnt_ns_id — use __u32 not __u64
Kernel's `ns.inum` is `unsigned int` (32-bit). Use `__u32 mnt_ns_id` in C struct and `uint32` in Go.
`BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)` — requires kernel 5.8+ BTF (6.1 confirmed working).

### Container name resolution
Docker sets `HOSTNAME` env var to container ID (short hash), NOT container name.
Reliable approach: `docker ps --no-trunc` → build full container ID → name map.
Then `/proc/<pid>/cgroup` → extract container ID → look up name.

### ExitEvent struct alignment bug (fixed)
Original C struct had implicit 4-byte padding before `duration_ns`:
```
int pid (4) + int ppid (4) + unsigned exit_code (4) + [4 pad] + unsigned long long duration_ns (8) + comm (128) = 152 bytes
```
Go struct had wrong field order (DurationNs first) → all fields read as garbage.

Fix: reordered `exitsnoop.h` — `duration_ns` first, explicit `unsigned int pad`:
```
duration_ns (8) + pid (4) + ppid (4) + exit_code (4) + pad (4) + comm (128) = 152 bytes, no implicit padding
```
Go `ExitEvent` updated to match exactly.

### Perf Buffer vs Ring Buffer
`execsnoop.bpf.c` still uses `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (perf buffer, older).
`exitsnoop.bpf.c` uses `BPF_MAP_TYPE_RINGBUF` (ring buffer, modern — lower overhead).
New `.bpf.c` files (opensnoop, lsm-connect) use ring buffer.

### Detection rule design
- Host processes: silently skipped via `mnt_ns` (no uid-based hacks needed)
- `curlAllowedContainers` list — scale by adding entries, no logic change
- `allowedMarketAPI = "api.coingecko.com"` — reserved for lsm-connect IP enforcement

---

## To Do

- [ ] Rewrite `opensnoop.bpf.c` with ring buffer + full event struct + file access rules
- [ ] Rewrite `lsm-connect.bpf.c` with ring buffer + Go integration
- [ ] Wire opensnoop and lsm-connect into `main.go`
- [ ] Go unit tests — `rules_test.go`, `container_test.go`
- [ ] Final validation: all rules trigger + integration tests pass simultaneously
