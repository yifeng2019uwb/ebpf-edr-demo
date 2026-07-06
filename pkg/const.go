package pkg

// eBPF buffer size constants (must match kernel header files)
const (
	TaskCommLen    = 128 // kernel/opensnoop.h: #define TASK_COMM_LEN 128
	MaxFilenameLen = 256 // kernel/opensnoop.h: #define MAX_FILENAME_LEN 256
)
