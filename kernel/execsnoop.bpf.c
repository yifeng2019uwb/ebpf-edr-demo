// download from https://github.com/eunomia-bpf/bpf-developer-tutorial

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// exec_event (544 bytes) exceeds the 512-byte BPF stack limit — held here instead
// of as a stack-local variable. One slot per CPU, reused every call.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct exec_event);
} exec_scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	u64 id;
	pid_t tgid;
	struct task_struct *task;

	u32 zero = 0;
	struct exec_event *event = bpf_map_lookup_elem(&exec_scratch, &zero);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event)); // clear previous call's leftover args/tty

	uid_t uid = (u32)bpf_get_current_uid_gid();
	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;

	event->pid = tgid;
	event->uid = uid;
	// kernel monotonic timestamp — userspace converts to wall time via boot offset
	event->event_time = bpf_ktime_get_ns();
	task = (struct task_struct*)bpf_get_current_task();
	event->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// read mount namespace ID — lets userspace identify which container spawned this process
	event->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	// leaf cgroup name (v2 unified hierarchy) — replaces the resolver's /proc/<pid>/cgroup read
	const char *cgroup_name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
	bpf_probe_read_kernel_str(&event->cgroup, sizeof(event->cgroup), cgroup_name);
	// path as invoked (execve arg 0) — user-space pointer, so the _user variant
	char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
	bpf_probe_read_user_str(&event->exec_path, sizeof(event->exec_path), cmd_ptr);

	// controlling terminal attached? non-NULL tty = interactive session (kubectl exec -it,
	// an attacker's shell); NULL = no terminal (health checks, entrypoints, cron). T1059.
	event->has_tty = BPF_CORE_READ(task, signal, tty) != NULL;

	// argv[1:] into fixed-size, NUL-padded slots — ctx->args[1] is execve's argv array;
	// argv[0] is already exec_path, skip it. Slot i is at compile-time-constant offset
	// (i-1)*ARG_CHUNK — required for the verifier to prove bounds (a runtime-tracked
	// offset could not, even with masking; see git history). Not space-joined into one
	// string: harmless for the substring match this field exists for.
	const char **argv = (const char **) BPF_CORE_READ(ctx, args[1]);
	#pragma unroll
	for (int i = 1; i < MAX_ARGS; i++) {
		const char *argp = NULL;
		bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
		if (!argp)
			break;
		bpf_probe_read_user_str(&event->args[(i - 1) * ARG_CHUNK], ARG_CHUNK, argp);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";