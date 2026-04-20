// Originally downloaded from https://github.com/eunomia-bpf/bpf-developer-tutorial (lesson 04 opensnoop)
// Rewritten from scratch:
//   - original had no header file (only bpf_printk stub)
//   - added full file_event struct with mnt_ns_id, pid, ppid, uid, comm, filename
//   - field order chosen to avoid implicit C alignment padding
// opensnoop.h — struct file_event shared between opensnoop.bpf.c and Go userspace
// struct pending_open (BPF-internal scratch space) is defined in opensnoop.bpf.c only
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 128
#define MAX_FILENAME_LEN 256

// ── Why __u64 for mnt_ns_id? ─────────────────────────────────────────────────
// BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum) returns the inode number of
// the mount namespace.  Kernel defines ns.inum as unsigned int (32-bit), but
// we store it as __u64 to:
//   1. Put an 8-byte field first — avoids implicit padding before it.
//   2. Future-proof: inode numbers are increasingly 64-bit on modern kernels.
// Go side: uint64 MntNsId at offset 0 matches exactly.
//
// ── Why explicit __u32 pad? ──────────────────────────────────────────────────
// After uid (offset 16, 4 bytes) the struct is at offset 20.
// comm[128] is char — 1-byte aligned, no gap needed before it.
// But C rounds sizeof() up to the largest member alignment (= 8 for __u64).
// Without explicit pad: sizeof = 8+4+4+4 + (4 implicit tail) + 128+256 = 408
//   C: sizeof=408    Go binary.Size=404   → 4-byte mismatch → all fields wrong
// With explicit pad:  sizeof = 8+4+4+4+4 + 128+256 = 408
//   C: sizeof=408    Go binary.Size=408   → exact match → binary.Read works
// Rule: explicit pad converts invisible tail padding into a named field that
//       both C and Go count the same way.
struct file_event {
	__u64 mnt_ns_id;              // offset 0   — mount namespace ID (container identity)
	int   pid;                    // offset 8   — process ID
	int   ppid;                   // offset 12  — parent process ID
	__u32 uid;                    // offset 16  — user ID
	__u32 pad;                    // offset 20  — explicit padding (see note above)
	char  comm[TASK_COMM_LEN];    // offset 24  — process name (e.g. "python3")
	char  filename[MAX_FILENAME_LEN]; // offset 152 — file path being opened
	// total: 8+4+4+4+4+128+256 = 408 bytes — matches Go binary.Size(FileEvent{}) exactly
};

#endif /* __OPENSNOOP_H */
