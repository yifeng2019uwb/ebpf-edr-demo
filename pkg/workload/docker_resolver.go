//go:build linux

package workload

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

const dockerRefreshInterval = 30 * time.Second

type DockerResolver struct {
	mu        sync.RWMutex
	cache     map[uint32]ResolveResult
	refreshMu sync.Mutex
	node      string
	region    string
}

func (r *DockerResolver) Start() error {
	r.cache = r.buildCache()

	go func() {
		ticker := time.NewTicker(dockerRefreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			r.refresh()
		}
	}()

	return nil
}

func (r *DockerResolver) Resolve(mntNsID uint32, _ uint32) ResolveResult {
	r.mu.RLock()
	result, ok := r.cache[mntNsID]
	r.mu.RUnlock()

	if ok {
		return result
	}

	go r.refresh()

	return ResolveResult{
		Identity: WorkloadIdentity{
			Runtime: "docker",
		},
		Meta: WorkloadMeta{
			Node:   r.node,
			Region: r.region,
		},
		State: StateUnknown,
	}
}

func (r *DockerResolver) refresh() {
	if !r.refreshMu.TryLock() {
		return
	}
	defer r.refreshMu.Unlock()

	m := r.buildCache()

	r.mu.Lock()
	r.cache = m
	r.mu.Unlock()
}

func (r *DockerResolver) buildCache() map[uint32]ResolveResult {
	m := make(map[uint32]ResolveResult)

	hostNsID := getMntNsID(1)
	if hostNsID != 0 {
		m[hostNsID] = ResolveResult{
			Identity: WorkloadIdentity{Runtime: "docker"},
			Meta:     WorkloadMeta{Node: r.node, Region: r.region},
			State:    StateHost,
		}
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

		nsID := uint32(stat.Ino)

		if nsID == hostNsID {
			continue
		}
		if _, exists := m[nsID]; exists {
			continue
		}

		containerID := containerIDFromDockerCgroup(pid)
		if containerID == "" {
			continue
		}

		rawName := ""
		if name, ok := idToName[containerID]; ok {
			rawName = name
		} else if len(containerID) >= 12 {
			rawName = containerID[:12]
		}
		if rawName == "" {
			continue
		}

		service := normalizeServiceName(rawName)

		m[nsID] = ResolveResult{
			Identity: WorkloadIdentity{
				Runtime: "docker",
				Service: service,
			},
			Meta: WorkloadMeta{
				Container: rawName,
				Pod:       rawName,
				Node:      r.node,
				Region:    r.region,
			},
			State: StateResolved,
		}
	}

	return m
}

func normalizeServiceName(raw string) string {
	if i := strings.LastIndexByte(raw, '-'); i >= 0 {
		raw = raw[i+1:]
	}
	return strings.ReplaceAll(raw, "_", "-")
}

func getMntNsID(pid int) uint32 {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)

	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0
	}

	return uint32(stat.Ino)
}

func dockerIDToName() map[string]string {
	m := make(map[string]string)

	out, err := exec.Command(
		"docker",
		"ps",
		"--no-trunc",
		"--format",
		"{{.ID}} {{.Names}}",
	).Output()
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

func containerIDFromDockerCgroup(pid string) string {
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
			id := strings.TrimSpace(parts[len(parts)-1])
			if len(id) >= 12 {
				return id
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
