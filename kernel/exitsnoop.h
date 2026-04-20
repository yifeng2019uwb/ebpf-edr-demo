// download from https://github.com/eunomia-bpf/bpf-developer-tutorial
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 128
#define MAX_FILENAME_LEN 127

struct event {
	unsigned long long duration_ns; // offset 0  — put 8-byte field first, no implicit padding
	int pid;                        // offset 8
	int ppid;                       // offset 12
	unsigned exit_code;             // offset 16
	unsigned int pad;               // offset 20 — explicit padding, total = 152, no tail padding
	char comm[TASK_COMM_LEN];       // offset 24
};

#endif /* __BOOTSTRAP_H */
