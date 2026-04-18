# Work Log / Notes

---

## 2026-04-17

### Phase 1 — Process monitor done
- `execsnoop.bpf.c` + `main.go` working, capturing execve events
- Confirmed running via snapshot

---

## 2026-04-18 — Day 2 Plan

- [ ] Understand and run remaining 3 BPF programs (opensnoop, tcpconnlat, kprobe/fentry)
- [ ] Migrate all to ring buffer — consistent pattern across all monitors
- [ ] Add detection rules — alert on suspicious behavior
- [ ] Test against CNOP — validate with real services

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
