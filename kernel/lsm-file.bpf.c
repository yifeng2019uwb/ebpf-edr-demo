// lsm.s/file_open sensor — captures file open events for all processes.
//
// WHY lsm.s/file_open instead of tracepoint/sys_enter_openat:
//   openat tracepoint only fires for SYS_openat (syscall 257).
//   Alpine Linux busybox (sh, cat) calls SYS_open (syscall 2) directly —
//   the openat tracepoint never fires for those processes.
//   lsm/file_open is a kernel LSM hook inside do_dentry_open(), which runs
//   for every file open regardless of which syscall was used:
//   open(), openat(), openat2(), io_uring — all covered by one hook.
//
// WHY lsm.s (sleepable):
//   bpf_d_path() resolves the full absolute path from struct path.
//   It requires a sleepable BPF program. bpf_lsm_file_open is in the
//   kernel's sleepable LSM hook set (Linux 5.11+, GKE 6.8 ✅).
//   BPF_MAP_TYPE_RINGBUF is allowed in sleepable programs.
//
// WHY no two-probe pattern:
//   The LSM hook fires after the kernel has already resolved the dentry and
//   checked permissions. ENOENT files never reach this hook — no exit probe
//   or pending_opens hash map needed.
//
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "opensnoop.h"

char LICENSE[] SEC("license") = "GPL";

// 256 KB ring buffer — same size as lsm-connect.bpf.c.
// Must be a power of 2 (kernel requirement for BPF_MAP_TYPE_RINGBUF).
#define RINGBUF_SIZE (256 * 1024)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

// lsm.s/file_open — fires inside do_dentry_open() after the kernel resolves
// the file path and before returning the file descriptor to userspace.
//
// @file: kernel struct file pointer — path already resolved, dentry valid.
// @ret:  return value of any prior LSM hook in the chain. Non-zero means
//        a prior module (SELinux, AppArmor) already denied this open.
//        We pass it through unchanged — audit-only, never block.
SEC("lsm.s/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
	// Respect prior denials from other LSM hooks — do not override.
	if (ret != 0)
		return ret;

	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;

	struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	e->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	e->pid       = tgid;
	e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
	e->uid       = (u32)bpf_get_current_uid_gid();
	e->pad       = 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// bpf_d_path resolves the full absolute path (e.g. "/etc/shadow") from
	// the kernel struct path. Requires sleepable context — provided by lsm.s.
	// On error (path too long, unusual mount), discard the event rather than
	// emitting a record with a garbage or empty filename.
	e->filename[0] = '\0';
	long r = bpf_d_path(&file->f_path, e->filename, sizeof(e->filename));
	if (r < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
