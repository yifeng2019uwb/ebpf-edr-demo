// Originally downloaded from https://github.com/eunomia-bpf/bpf-developer-tutorial (lesson 07 exitsnoop)
// Modified:
//   - reordered fields: duration_ns moved first to eliminate implicit C alignment padding
//   - added explicit unsigned int pad to prevent tail padding (ensures Go binary.Read matches exactly)
//   - TASK_COMM_LEN increased 16 → 128 to capture full process names
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 128
#define MAX_FILENAME_LEN 127

// ── Why unsigned long long for duration_ns? ──────────────────────────────────
// bpf_ktime_get_ns() returns u64 (nanoseconds since boot).
// unsigned int (u32) overflows at 4,294,967,295 ns = ~4.29 seconds.
// Any process running longer than 4.29s would silently wrap to a small number.
// We saw python3 at 12,595 ms in real output — that's 12,595,000,000 ns,
// which is 3× over the u32 limit.  Must stay unsigned long long (u64).
//
// ── Why explicit unsigned int pad? ───────────────────────────────────────────
// C guarantees fields are aligned to their own size.
// After exit_code (offset 16, 4 bytes), the struct is 20 bytes.
// comm[128] starts at offset 24 (no alignment need — char is 1-byte aligned).
// So C adds NO implicit padding before comm.
// BUT C also rounds sizeof() up to the largest alignment (= 8 for u64).
// Without explicit pad: sizeof = 8+4+4+4 + (4 implicit tail) + 128 = 152
//   C: sizeof=152    Go binary.Size=148   → 4-byte mismatch → all fields wrong
// With explicit pad:  sizeof = 8+4+4+4+4 + 128 = 152
//   C: sizeof=152    Go binary.Size=152   → exact match → binary.Read works
// Rule: explicit pad moves tail padding to the middle so both sides agree.
struct event {
	unsigned long long duration_ns; // offset 0  — put 8-byte field first, no implicit padding
	int pid;                        // offset 8
	int ppid;                       // offset 12
	unsigned exit_code;             // offset 16
	unsigned int pad;               // offset 20 — explicit padding keeps sizeof=152 with no tail padding
	char comm[TASK_COMM_LEN];       // offset 24
	// total: 8+4+4+4+4+128 = 152 bytes — matches Go binary.Size(ExitEvent{}) exactly
};

#endif /* __BOOTSTRAP_H */
