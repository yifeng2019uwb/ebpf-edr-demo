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

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	u64 id;
	pid_t tgid;
	struct exec_event event = {0};
	struct task_struct *task;

	uid_t uid = (u32)bpf_get_current_uid_gid();
	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;

	event.pid = tgid;
	event.uid = uid;
	// kernel monotonic timestamp — userspace converts to wall time via boot offset
	event.event_time = bpf_ktime_get_ns();
	task = (struct task_struct*)bpf_get_current_task();
	event.ppid = BPF_CORE_READ(task, real_parent, tgid);
	// read mount namespace ID — lets userspace identify which container spawned this process
	event.mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	// leaf cgroup name (v2 unified hierarchy) — replaces the resolver's /proc/<pid>/cgroup read
	const char *cgroup_name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
	bpf_probe_read_kernel_str(&event.cgroup, sizeof(event.cgroup), cgroup_name);
	// path as invoked (execve arg 0) — user-space pointer, so the _user variant
	char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
	bpf_probe_read_user_str(&event.exec_path, sizeof(event.exec_path), cmd_ptr);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";