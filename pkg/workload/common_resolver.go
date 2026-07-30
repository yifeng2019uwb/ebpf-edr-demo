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

// containerIDFromCgroupLeaf extracts a container ID from a cgroup v2 leaf name
// captured in-kernel by the exec sensor (see docs/EXECVE-EVENT-DESIGN.md).
// Handles the systemd driver ("docker-<64hex>.scope", "cri-containerd-<64hex>.scope",
// "crio-<64hex>.scope") and the cgroupfs driver (raw 64-hex leaf).
// Returns "" for host/system leaves (e.g. "ssh.service", "session-1.scope").
func containerIDFromCgroupLeaf(leaf string) string {
	for _, prefix := range []string{"cri-containerd-", "crio-", "docker-"} {
		if strings.HasPrefix(leaf, prefix) && strings.HasSuffix(leaf, ".scope") {
			id := strings.TrimSuffix(strings.TrimPrefix(leaf, prefix), ".scope")
			if len(id) == containerIDLen {
				return id
			}
			return ""
		}
	}
	if len(leaf) == containerIDLen && isHexID(leaf) {
		return leaf
	}
	return ""
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
