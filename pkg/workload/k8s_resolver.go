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
	cluster   string
	env       string
}

func (r *K8sResolver) Start() error {
	r.selfNsID = getMntNsID(os.Getpid())
	r.cache = r.buildCache()

	// Kubernetes is dynamic:
	// pods start / stop / scale anytime
	go func() {
		ticker := time.NewTicker(k8sRefreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			r.refresh()
		}
	}()

	return nil
}

func (r *K8sResolver) bareResult(state ResolveState) ResolveResult {
	service := ""
	if state == StateHost {
		service = "host"
	}
	return ResolveResult{
		Identity: WorkloadIdentity{Runtime: "k8s", Service: service, Env: r.env},
		Meta:     WorkloadMeta{Node: r.node, Region: r.region, Cluster: r.cluster},
		State:    state,
	}
}

func (r *K8sResolver) Resolve(mntNsID uint32, _ uint32) ResolveResult {
	r.mu.RLock()
	result, ok := r.cache[mntNsID]
	r.mu.RUnlock()

	if ok {
		return result
	}

	go r.refresh()

	return r.bareResult(StatePending)
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

	ids := []uint32{
		r.selfNsID,
		getMntNsID(1),
	}

	for _, id := range ids {
		if id == 0 {
			continue
		}
		m[id] = r.bareResult(StateHost)
	}

	containerMap := crictlContainerMap(r.node, r.region, r.cluster, r.env)

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

		if !strings.Contains(line, "kubepods") {
			continue
		}

		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}

		cgroupPath := line[idx+1:]
		segments := strings.Split(strings.Trim(cgroupPath, "/"), "/")
		// cgroup path structure: /kubepods/<qos>/<pod-uid>/<container-id>
		// e.g. /kubepods/burstable/pod8e18d5ef-1234-5678-abcd-ef0123456789/a1b2c3d4e5f6...
		// a partial path like /kubepods or /kubepods/burstable gives only 1-2 segments —
		// the container ID is always the 4th component, so we need at least 2 to avoid
		// taking a QoS tier name as the "last segment".
		if len(segments) < 2 {
			continue
		}

		containerID := segments[len(segments)-1]
		// Strip runtime-specific cgroup v2 systemd scope prefixes/suffixes.
		// Different runtimes use different prefixes — all end with the 64-char SHA256 container ID.
		//   containerd (GKE, EKS, DOKS, k3s): "cri-containerd-<id>.scope"
		//   CRI-O (some EKS, OpenShift):       "crio-<id>.scope"
		//   Docker-as-CRI (K8s <1.24 legacy):  "docker-<id>.scope"
		for _, prefix := range []string{"cri-containerd-", "crio-", "docker-"} {
			if strings.HasPrefix(containerID, prefix) && strings.HasSuffix(containerID, ".scope") {
				containerID = strings.TrimSuffix(strings.TrimPrefix(containerID, prefix), ".scope")
				break
			}
		}
		// container IDs are SHA256 → exactly 64 hex chars.
		// K8s QoS tier names: burstable(9), guaranteed(10), besteffort(11).
		// pod-uid format: pod8e18d5ef-1234-5678-abcd-ef0123456789 (39 chars).
		// Both are shorter than a real container ID — 64 chars filters them out.
		if len(containerID) >= containerIDLen {
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

func crictlContainerMap(node, region, cluster, env string) map[string]ResolveResult {
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

		service := strings.ReplaceAll(containerName, "_", "-")

		m[c.ID] = ResolveResult{
			Identity: WorkloadIdentity{
				Runtime: "k8s",
				Service: service,
				Env:     env,
			},
			Meta: WorkloadMeta{
				Container: containerName,
				Pod:       podName,
				Namespace: namespace,
				Node:      node,
				Region:    region,
				Cluster:   cluster,
			},
			State: StateResolved,
		}
	}

	return m
}
