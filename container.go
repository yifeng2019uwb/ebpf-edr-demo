//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// nsCache holds the mount namespace ID → container name map
// Refreshed periodically since containers start/stop
var (
	nsCache   map[uint32]string
	nsCacheMu sync.RWMutex
)

// StartContainerResolver builds the namespace map once at startup,
// then refreshes every 30 seconds to catch new/stopped containers.
func StartContainerResolver() {
	nsCache = buildNamespaceMap()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			m := buildNamespaceMap()
			nsCacheMu.Lock()
			nsCache = m
			nsCacheMu.Unlock()
		}
	}()
}

// resolveContainer returns the container name for a given mount namespace ID.
// Returns "host" if the namespace belongs to the host, or the container name if found.
func resolveContainer(mntNsId uint32) string {
	nsCacheMu.RLock()
	defer nsCacheMu.RUnlock()
	if name, ok := nsCache[mntNsId]; ok {
		return name
	}
	return fmt.Sprintf("unknown(ns=%d)", mntNsId)
}

// buildNamespaceMap scans /proc/<pid>/ns/mnt for every running process.
// It reads the inode of the mnt namespace (= mnt_ns_id from the kernel).
// Then reads /proc/<pid>/cgroup to extract the Docker container ID,
// and uses dockerIDToName (built from `docker ps`) to get the human-readable name.
// Returns map: mnt_ns_id → container_name (or "host" for host processes).
func buildNamespaceMap() map[uint32]string {
	m := make(map[uint32]string)

	// get host mnt namespace ID from PID 1
	hostNsId := getMntNsId(1)
	if hostNsId != 0 {
		m[hostNsId] = "host"
	}

	// build container ID → name map from docker ps
	// Docker sets HOSTNAME to container ID, not name — so we need this lookup
	idToName := dockerIDToName()

	entries, err := filepath.Glob("/proc/[0-9]*/ns/mnt")
	if err != nil {
		return m
	}

	for _, nsPath := range entries {
		// extract PID from path: /proc/1234/ns/mnt → "1234"
		parts := strings.Split(nsPath, "/")
		if len(parts) < 3 {
			continue
		}
		pid := parts[2]

		// stat the ns/mnt symlink target to get the namespace inode
		var stat syscall.Stat_t
		if err := syscall.Stat(nsPath, &stat); err != nil {
			continue
		}
		nsId := uint32(stat.Ino)

		if nsId == hostNsId {
			continue // skip host processes
		}

		if _, exists := m[nsId]; exists {
			continue // already resolved this namespace
		}

		// get container ID from cgroup, then look up name
		containerID := containerIDFromCgroup(pid)
		if containerID == "" {
			continue
		}

		// look up full name from docker ps map
		if name, ok := idToName[containerID]; ok {
			m[nsId] = name
		} else {
			// docker ps didn't have it — use short ID as fallback
			if len(containerID) >= 12 {
				m[nsId] = containerID[:12]
			}
		}
	}

	return m
}

// getMntNsId returns the mount namespace inode for a given PID.
func getMntNsId(pid int) uint32 {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0
	}
	return uint32(stat.Ino)
}

// dockerIDToName calls `docker ps` to build a full container ID → name map.
// This is the reliable way to get human-readable names — HOSTNAME env var
// inside containers is set to container ID, not name.
func dockerIDToName() map[string]string {
	m := make(map[string]string)
	// --no-trunc: show full 64-char container IDs
	// --format:   output "ID NAME" per line
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}").Output()
	if err != nil {
		return m // docker not available or no containers — silent fail
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			m[fields[0]] = fields[1] // full ID → name
		}
	}
	return m
}

// containerIDFromCgroup reads /proc/<pid>/cgroup and extracts the full Docker container ID.
// Docker cgroup path example:
//
//	12:devices:/docker/a3f8c2d1b4e5f6...64chars...
func containerIDFromCgroup(pid string) string {
	path := fmt.Sprintf("/proc/%s/cgroup", pid)
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "/docker/") {
			continue
		}
		parts := strings.Split(line, "/docker/")
		if len(parts) < 2 {
			continue
		}
		id := strings.TrimSpace(parts[len(parts)-1])
		if len(id) >= 12 {
			return id // full 64-char container ID
		}
	}
	return ""
}
