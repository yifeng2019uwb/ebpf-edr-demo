//go:build linux

package workload

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const k8sRefreshInterval = 5 * time.Second

type K8sResolver struct {
	mu        sync.RWMutex
	cache     map[uint32]ResolveResult
	refreshMu sync.Mutex
	selfNsID  uint32
	node      string
	region    string
}

func (r *K8sResolver) Start() error {
	r.selfNsID = getMntNsID(os.Getpid())
	r.cache = r.buildCache()

	go func() {
		ticker := time.NewTicker(k8sRefreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			r.refresh()
		}
	}()

	return nil
}

func (r *K8sResolver) Resolve(mntNsID uint32, _ uint32) ResolveResult {
	r.mu.RLock()
	result, ok := r.cache[mntNsID]
	r.mu.RUnlock()

	if ok {
		return result
	}

	go r.refresh()

	return ResolveResult{
		Identity: WorkloadIdentity{
			Runtime: "k8s",
		},
		Meta: WorkloadMeta{
			Node:   r.node,
			Region: r.region,
		},
		State: StatePending,
	}
}

func (r *K8sResolver) refresh() {
	if !r.refreshMu.TryLock() {
		return
	}
	defer r.refreshMu.Unlock()

	m := r.buildCache()

	r.mu.Lock()
	r.cache = m
	r.mu.Unlock()
}

func (r *K8sResolver) buildCache() map[uint32]ResolveResult {
	m := make(map[uint32]ResolveResult)

	if r.selfNsID != 0 {
		m[r.selfNsID] = ResolveResult{
			Identity: WorkloadIdentity{Runtime: "k8s"},
			Meta:     WorkloadMeta{Node: r.node, Region: r.region},
			State:    StateHost,
		}
	}

	if hostNsID := getMntNsID(1); hostNsID != 0 {
		m[hostNsID] = ResolveResult{
			Identity: WorkloadIdentity{Runtime: "k8s"},
			Meta:     WorkloadMeta{Node: r.node, Region: r.region},
			State:    StateHost,
		}
	}

	containerMap := crictlContainerMap(r.node, r.region)

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

		if _, exists := m[nsID]; exists {
			continue
		}

		containerID := containerIDFromK8sCgroup(pid)
		if containerID == "" {
			continue
		}

		if result, ok := containerMap[containerID]; ok {
			m[nsID] = result
		}
	}

	return m
}

func containerIDFromK8sCgroup(pid string) string {
	path := fmt.Sprintf("/proc/%s/cgroup", pid)

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.Contains(line, "/kubepods/") {
			continue
		}

		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}

		cgroupPath := line[idx+1:]
		segments := strings.Split(strings.Trim(cgroupPath, "/"), "/")
		if len(segments) < 2 {
			continue
		}

		containerID := segments[len(segments)-1]
		if len(containerID) >= 12 {
			return containerID
		}
	}

	return ""
}

type crictlOutput struct {
	Containers []struct {
		ID     string            `json:"id"`
		Labels map[string]string `json:"labels"`
	} `json:"containers"`
}

func crictlContainerMap(node, region string) map[string]ResolveResult {
	m := make(map[string]ResolveResult)

	out, err := exec.Command("crictl", "ps", "--output", "json").Output()
	if err != nil {
		return m
	}

	var result crictlOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return m
	}

	for _, c := range result.Containers {
		containerName := c.Labels["io.kubernetes.container.name"]
		podName := c.Labels["io.kubernetes.pod.name"]
		namespace := c.Labels["io.kubernetes.pod.namespace"]

		if containerName == "" || podName == "" {
			continue
		}

		service := containerName

		m[c.ID] = ResolveResult{
			Identity: WorkloadIdentity{
				Runtime: "k8s",
				Service: service,
			},
			Meta: WorkloadMeta{
				Container: containerName,
				Pod:       podName,
				Namespace: namespace,
				Node:      node,
				Region:    region,
			},
			State: StateResolved,
		}
	}

	return m
}
