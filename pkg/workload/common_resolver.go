//go:build linux

package workload

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// /proc paths for namespace and process discovery
const (
	procNsMntPattern   = "/proc/[0-9]*/ns/mnt"  // Find all process mount namespaces
	procCmdlinePattern = "/proc/[0-9]*/cmdline" // Find all process command lines
	procNsMntPathFmt   = "/proc/%d/ns/mnt"      // Get namespace for specific PID (int)
	procCmdlinePathFmt = "/proc/%d/cmdline"     // Get command line for specific PID (int)
	procCgroupPathFmt  = "/proc/%s/cgroup"      // Get cgroup for process (string)
	// String-based path formats (for direct concatenation without fmt.Sprintf)
	procNsMntPathStr = "/proc/%s/ns/mnt" // Get namespace for specific PID (string pidStr)

	// containerIDLen is the length of a full SHA256 container ID (64 hex chars).
	// All runtimes (Docker, containerd, CRI-O) use SHA256.
	containerIDLen = 64
)

// getMntNsIDFromPath returns the mount namespace ID from a namespace path.
// Reads symlink target (format: "mnt:[ID]") and extracts the ID.
// Returns 0 if the path doesn't exist or parsing fails.
func getMntNsIDFromPath(nsPath string) uint32 {
	// Read symlink target from /proc/[pid]/ns/mnt
	// Symlink points to: "mnt:[4026531841]" where mnt=namespace type, 4026531841=namespace ID
	target, err := os.Readlink(nsPath)
	if err != nil {
		return 0
	}

	// Parse namespace ID from symlink target format "mnt:[4026531841]"
	// Extract the numeric ID between brackets
	start := strings.IndexByte(target, '[')
	end := strings.IndexByte(target, ']')
	if start < 0 || end < 0 || start >= end {
		return 0
	}

	nsIDStr := target[start+1 : end]
	nsID, err := strconv.ParseUint(nsIDStr, 10, 32)
	if err != nil {
		return 0
	}

	return uint32(nsID)
}

// getMntNsID returns the mount namespace ID for the given pid.
// Builds the path and calls getMntNsIDFromPath.
func getMntNsID(pid int) uint32 {
	path := fmt.Sprintf(procNsMntPathFmt, pid)
	return getMntNsIDFromPath(path)
}

// isHexID reports whether s is all hexadecimal digits (a container ID).
func isHexID(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
