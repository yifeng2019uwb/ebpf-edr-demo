# Work Log / Notes

---

## 2026-04-17

### Phase 1 — Process monitor done
- `execsnoop.bpf.c` + `main.go` working, capturing execve events
- Confirmed running via snapshot

---

## 2026-04-18 — Day 2

- [x] Added exitsnoop alongside execsnoop — both running concurrently in main.go
- [x] exitsnoop uses ring buffer, execsnoop uses perf buffer — good side-by-side comparison before migration
- [x] Integration tests pass while monitor runs — no false positives confirmed (snapshot: PrintProcess&Exit.png)
- [x] Validate detection against CNOP — trigger known events, confirm alerts fire
- [ ] Modify existing .bpf.c files to capture additional fields (mnt_ns, container info)
- [ ] lsm-connect — compile and test (CONFIG_BPF_LSM=y confirmed)

### Manual validation — alert confirmed working
- Triggered `curl` inside container → `[ALERT] level=MEDIUM rule=curl_from_container` fired correctly
- Alert written to stdout and `alerts/alert.log`
- Integration tests running simultaneously — no false positives from normal test traffic
- Screenshot: `legacy/screenshots/ebpf-alert1.png`
- ⚠️ Bug in alert.log output: `comm=%!s(int32=...)` — format string mismatch in `alert.go Send()`
  - Format has `pid=%d comm=%s msg=%s` but passes `Pid, Ppid, Uid, Comm, Message`
  - Fix: `pid=%d ppid=%d uid=%d comm=%s msg=%s`

### rules.go — detection rules added
- Whitelist: `sshd`, `runc`, `dockerd`, `containerd` — never alert
- Shell rule: alert only on uid=0 shells (uid=1000 = your SSH session, skip)
- Network rule: `nc`, `ncat`, `wget` from uid=0
- `curl` handled separately — MEDIUM alert, TODO for container name check in Phase 2
- `checkExitRules`: short-lived process with non-zero exit code → LOW alert
- `networkPolicy` map: intent per container (inventory allowed CoinGecko, others no external)

### alert.go — Alert struct updated
- Added `Ppid` and `Uid` fields to `Alert` struct
- ⚠️ Bug: `Send()` format string missing `ppid=%d uid=%d` — fix before running:
  ```
  fmt.Sprintf("... pid=%d ppid=%d uid=%d comm=%s msg=%s\n", ...)
  ```

---

### TASK_COMM_LEN: 16 → 128
Changed `#define TASK_COMM_LEN 16` to `128` in `execsnoop.bpf.c` to capture full executable paths instead of truncated 16-char names.
Must match the Go struct field size — `Comm [128]byte` in `main.go`.

### Integration tests pass alongside monitor
Ran full integration test suite while monitor was running — all tests passed.
Confirms no false positives during normal order processor operation.
Snapshot: `2026-04-17 at 10.04.14 PM`, `10.16.10 PM`

### Perf Buffer vs Ring Buffer
Current `execsnoop.bpf.c` uses `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (perf buffer, older).
Ring buffer (`BPF_MAP_TYPE_RINGBUF`) is newer, more efficient, lower overhead — preferred for production EDR.

Not a blocker for Phase 1 because changing requires updating both `.bpf.c` and Go code.

**When writing new `.bpf.c` files from scratch (Phase 2/3), use ring buffer:**
- C side: `BPF_MAP_TYPE_RINGBUF` + `bpf_ringbuf_submit()`
- Go side: `ringbuf.NewReader` instead of `perf.NewReader`
