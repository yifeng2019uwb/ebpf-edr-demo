// event.h — all sensor event structs shared between kernel/*.bpf.c and Go userspace.
// Consolidates the former execsnoop.h, opensnoop.h, and lsm-connect.h.
// Design rationale per field: docs/EXECVE-EVENT-DESIGN.md, docs/FILE-EVENT-DESIGN.md.
//
// Go maps raw kernel bytes directly onto mirror structs in internal/processor —
// there is no serialization layer, so every layout here must be byte-perfect and
// free of implicit padding (explicit pad fields convert invisible tail padding
// into named fields both C and Go count the same way).
//
// ── Why __u64 mnt_ns_id in file/net events? ──────────────────────────────────
// BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum) returns unsigned int (32-bit),
// but storing it as __u64 puts an 8-byte field first, avoiding padding before it.
// (exec_event predates this convention and keeps __u32 mnt_ns_id mid-struct.)

#ifndef __EVENT_H
#define __EVENT_H

#define TASK_COMM_LEN    16 // task->comm is ≤16 bytes
#define EXEC_PATH_LEN    256 // invoked path — 256 makes basename truncation rare
#define MAX_FILENAME_LEN 256 // canonical path from bpf_d_path
#define CGROUP_LEN       128 // leaf cgroup — "cri-containerd-<64hex>.scope" ≈ 85 B; 64 truncates the ID
#define ARGS_LEN         128 // argv[1:], space-joined, bounded — see MAX_ARGS in execsnoop.bpf.c
#define MAX_ARGS         4   // argv entries read past argv[0] — verifier requires a compile-time bound
#define ARG_CHUNK        32  // max bytes read per arg — a compile-time constant, not computed
                              // "remaining space", so the verifier can prove bounds (see execsnoop.bpf.c)

// ── exec_event — execsnoop.bpf.c (tracepoint/syscalls/sys_enter_execve) ──────
// Grows past the 512-byte BPF stack limit (see total below) — held in a per-CPU
// scratch map (exec_scratch in execsnoop.bpf.c), not a stack-local variable.
//
// cwd is NOT captured (considered and deferred): resolving it needs bpf_d_path(),
// which requires a sleepable program (see lsm-file.bpf.c's "WHY lsm.s" comment);
// this hook is a plain, non-sleepable tracepoint. Adding cwd would mean switching to
// a different (sleepable) attach point, not just adding a field — a bigger change
// that needs its own re-evaluation, out of scope for now. Until then, T1036's
// `cd /dev/shm && ./x` (relative-exec) bypass stays open — see rules/process.yaml.
struct exec_event {
	int   pid;                      // offset 0   — response target, dedup key
	int   ppid;                     // offset 4   — ppid==1 short-circuit, ancestry walk
	int   uid;                      // offset 8   — alert context
	__u32 mnt_ns_id;                // offset 12  — container-context gating
	__u64 event_time;               // offset 16  — bpf_ktime_get_ns(); anomaly service (future)
	char  exec_path[EXEC_PATH_LEN]; // offset 24  — path as invoked (execve arg 0); T1036/T1059/T1105/T1613
	char  cgroup[CGROUP_LEN];       // offset 280 — leaf cgroup name; replaces /proc/<pid>/cgroup read
	__u32 has_tty;                  // offset 408 — 1 = controlling terminal attached (interactive); T1059
	char  args[ARGS_LEN];           // offset 412 — argv[1:], space-joined, bounded; T1105/T1036
	__u32 pad;                      // offset 540 — explicit padding (keeps size an 8-multiple)
	// total: 408+4+128+4 = 544 bytes
};

// ── file_event — lsm-file.bpf.c (lsm.s/file_open + do_sys_openat2 probes) ────
struct file_event {
	__u64 mnt_ns_id;                  // offset 0   — mount namespace ID (container identity)
	__u64 event_time;                 // offset 8   — bpf_ktime_get_ns(); behavior analysis (future)
	int   pid;                        // offset 16  — process ID
	int   ppid;                       // offset 20  — parent process ID
	__u32 uid;                        // offset 24  — user ID
	__u32 f_mode;                     // offset 28  — FMODE_READ(0x1)/FMODE_WRITE(0x2); write bit scopes T1053/T1070
	__s32 ret;                        // offset 32  — 0 = success (lsm hook); -EACCES/-EPERM = denied (kprobe)
	__u32 pad;                        // offset 36  — explicit padding (keeps size an 8-multiple)
	char  comm[TASK_COMM_LEN];        // offset 40  — process name (e.g. "python3")
	char  filename[MAX_FILENAME_LEN]; // offset 56  — canonical path (lsm hook) or raw user string (denial probe)
	char  cgroup[CGROUP_LEN];         // offset 312 — leaf cgroup name; replaces /proc/<pid>/cgroup read
	// total: 8+8+4+4+4+4+4+4+16+256+128 = 440 bytes
};

// ── net_event — lsm-connect.bpf.c (lsm/socket_connect) ──────────────────────
//
// dst_ip and dst_port are stored in network byte order (big-endian), exactly as
// the kernel holds them — no conversion in BPF. Go converts via byte extraction
// (processor.NetIP / processor.NetPort).
struct net_event {
	__u64 mnt_ns_id;           // offset 0  — mount namespace ID (container identity)
	__u64 event_time;          // offset 8  — bpf_ktime_get_ns(); behavior analysis (future)
	__u32 dst_ip;              // offset 16 — destination IP (network byte order)
	__u16 dst_port;            // offset 20 — destination port (network byte order)
	__u16 pad1;                // offset 22 — explicit padding
	int   pid;                 // offset 24 — process ID
	int   ppid;                // offset 28 — parent process ID
	__u32 uid;                 // offset 32 — user ID
	__u32 pad2;                // offset 36 — explicit padding
	char  comm[TASK_COMM_LEN]; // offset 40 — process name
	// total: 8+8+4+2+2+4+4+4+4+16 = 56 bytes
};

// lpm_key: key type for the blocked_ips LPMTrie map in lsm-connect.bpf.c.
// prefixlen must be the first field; the kernel uses it as the CIDR prefix length.
// Set prefixlen=32 for a single host; set < 32 for a CIDR range.
// addr must be in network byte order (same representation as net_event.dst_ip).
struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

#endif /* __EVENT_H */
