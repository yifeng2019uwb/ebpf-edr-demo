//go:build linux

// Package container resolves Linux mount namespace IDs to Docker container names.
// It scans /proc and calls docker ps to build and maintain the namespace → name map.
package container

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

const nsRefreshInterval = 30 * time.Second

// nsCache holds the mount namespace ID → container name map.
// Refreshed periodically since containers start/stop.
var (
	nsCache   map[uint32]string
	nsCacheMu sync.RWMutex
)

// StartResolver builds the namespace map once at startup, then refreshes every
// nsRefreshInterval to catch new/stopped containers.
func StartResolver() {
	nsCache = buildNamespaceMap()
	go func() {
		ticker := time.NewTicker(nsRefreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			m := buildNamespaceMap()
			nsCacheMu.Lock()
			nsCache = m
			nsCacheMu.Unlock()
		}
	}()
}

// Resolve returns the container name for a given mount namespace ID.
//
// Return values:
//
//	"host"         — namespace belongs to the host (PID 1 namespace)
//	container name — known Docker container namespace
//	"unknown-ns"   — namespace is neither host nor any known container
//	               → strong indicator of container escape or rogue process
//
// On cache miss: immediately rescans /proc to handle new containers that started
// after the last 30s refresh. If still not found after rescan → "unknown-ns".
func Resolve(mntNsId uint32) string {
	nsCacheMu.RLock()
	name, ok := nsCache[mntNsId]
	nsCacheMu.RUnlock()
	if ok {
		return name
	}

	// cache miss — new container may have started since last refresh
	m := buildNamespaceMap()
	nsCacheMu.Lock()
	nsCache = m
	nsCacheMu.Unlock()

	nsCacheMu.RLock()
	name, ok = nsCache[mntNsId]
	nsCacheMu.RUnlock()
	if ok {
		return name
	}

	return "unknown-ns"
}

// buildNamespaceMap scans /proc/<pid>/ns/mnt for every running process.
// Returns map: mnt_ns_id → container_name (or "host" for host processes).
func buildNamespaceMap() map[uint32]string {
	m := make(map[uint32]string)

	hostNsId := getMntNsId(1)
	if hostNsId != 0 {
		m[hostNsId] = "host"
	}

	idToName := dockerIDToName()

	entries, err := filepath.Glob("/proc/[0-9]*/ns/mnt")
	if err != nil {
		return m
	}

	for _, nsPath := range entries {
		parts := strings.Split(nsPath, "/")
		if len(parts) < 3 {
			continue
		}
		pid := parts[2]

		var stat syscall.Stat_t
		if err := syscall.Stat(nsPath, &stat); err != nil {
			continue
		}
		nsId := uint32(stat.Ino)

		if nsId == hostNsId {
			continue
		}
		if _, exists := m[nsId]; exists {
			continue
		}

		containerID := containerIDFromCgroup(pid)
		if containerID == "" {
			continue
		}

		if name, ok := idToName[containerID]; ok {
			m[nsId] = name
		} else if len(containerID) >= 12 {
			m[nsId] = containerID[:12]
		}
	}

	return m
}

func getMntNsId(pid int) uint32 {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0
	}
	return uint32(stat.Ino)
}

func dockerIDToName() map[string]string {
	m := make(map[string]string)
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}").Output()
	if err != nil {
		return m
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			m[fields[0]] = fields[1]
		}
	}
	return m
}

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

		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			if len(parts) >= 2 {
				id := strings.TrimSpace(parts[len(parts)-1])
				if len(id) >= 12 {
					return id
				}
			}
		}

		if strings.Contains(line, "docker-") && strings.Contains(line, ".scope") {
			start := strings.Index(line, "docker-") + len("docker-")
			end := strings.LastIndex(line, ".scope")
			if end > start {
				id := line[start:end]
				if len(id) >= 12 {
					return id
				}
			}
		}
	}
	return ""
}
