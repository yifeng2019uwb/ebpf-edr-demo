//go:build linux

package workload

import (
	"fmt"
	"strings"
	"syscall"
)

// containerIDLen is the length of a full SHA256 container ID (64 hex chars).
// All runtimes (Docker, containerd, CRI-O) use SHA256. Used to validate
// container IDs parsed from /proc/<pid>/cgroup paths.
const containerIDLen = 64

// getMntNsID returns the mount namespace inode for the given pid.
// Returns 0 if the pid no longer exists or the stat fails.
func getMntNsID(pid int) uint32 {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)

	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0
	}

	return uint32(stat.Ino)
}

// normalizeServiceName strips the project/stack prefix added by Docker Compose
// and converts underscores to dashes to match Kubernetes naming conventions.
// e.g. "order-processor-auth_service" → "auth-service"
func normalizeServiceName(raw string) string {
	if i := strings.LastIndexByte(raw, '-'); i >= 0 {
		raw = raw[i+1:]
	}
	return strings.ReplaceAll(raw, "_", "-")
}
