package pkg

// eBPF buffer size constants — must match kernel/event.h exactly.
const (
	ExecPathLen    = 256 // event.h #define EXEC_PATH_LEN 256
	CgroupLen      = 128 // event.h #define CGROUP_LEN    128
	TaskCommLen    = 16  // event.h #define TASK_COMM_LEN 16 (kernel task->comm is char[16])
	MaxFilenameLen = 256 // event.h #define MAX_FILENAME_LEN 256
	ArgsLen        = 128 // event.h #define ARGS_LEN 128
)
