// download from https://github.com/eunomia-bpf/bpf-developer-tutorial
// Change TASK_COMM_LEN in execsnoop.h to show full path of executed binary
// Add mount namespace ID to identify which container spawned the process

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

// change TASK_COMM_LEN to show pull path, 4 + 4 + 4 + 128 = 140 bytes with in eBPF stack limit of 512 bytes
// #define TASK_COMM_LEN 16
#define TASK_COMM_LEN 128

struct event {
	int pid;
	int ppid;
	int uid;
	__u32 mnt_ns_id;         // mount namespace ID — identifies which container this process belongs to
	char comm[TASK_COMM_LEN];
};

#endif /* __EXECSNOOP_H */


