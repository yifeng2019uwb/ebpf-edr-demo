//go:build linux

package workload

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"ebpf-edr-demo/internal/processor"
)

const (
	k8sRefreshInterval   = 5 * time.Second
	k8sLookupWorkerLimit = 10 // max concurrent /proc cgroup reads per resolver instance
)

type K8sResolver struct {
	mu        sync.RWMutex
	cache     map[uint32]ResolveResult // mntNsID → pod identity
	refreshMu sync.Mutex
	selfNsID  uint32
	hostNsID  uint32 // host mount namespace (from PID 1 at startup); 0 if unknown
	// Immutable metadata set at startup (from environment)
	node    string
	region  string
	cluster string
	env     string

	// High-throughput concurrency controls (same pattern as Docker resolver)
	resolvingTasks sync.Map                 // mntNsID → bool (deduplicates concurrent hot-path requests)
	lookupSem      chan struct{}            // Semaphore (limits concurrent /proc disk scans to 10)
	containerIDMap map[string]ResolveResult // containerID → pod metadata (from crictl, separate from cache)
	containerIDMu  sync.RWMutex             // protects containerIDMap
}

func (r *K8sResolver) Start() error {
	r.selfNsID = getMntNsID(os.Getpid())
	// Host namespace ID enables the Resolve() fast path for node/host processes.
	// Works because the DaemonSet runs with hostPID and a host /proc mount, so PID 1
	// is the host init. Mirrors the Docker resolver.
	r.hostNsID = getMntNsID(1)
	log.Printf("k8s resolver: host namespace ID = %d, self namespace ID = %d (0 means detection failed, fast path disabled)", r.hostNsID, r.selfNsID)
	r.lookupSem = make(chan struct{}, k8sLookupWorkerLimit)
	r.containerIDMap = make(map[string]ResolveResult)
	r.cache = r.buildInitialCache()

	// Kubernetes is dynamic: pods start / stop / scale anytime
	// Periodic crictl sync (independent from hot-path resolution)
	go func() {
		ticker := time.NewTicker(k8sRefreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			r.refreshCrictlCache()
		}
	}()

	return nil
}

func (r *K8sResolver) bareResult(state ResolveState) ResolveResult {
	service := ""
	if state == StateResolved {
		service = "host"
	}
	return ResolveResult{
		Identity: WorkloadIdentity{Runtime: RuntimeK8s, Service: service, Env: r.env},
		Meta:     WorkloadMeta{Node: r.node, Region: r.region, Cluster: r.cluster},
		State:    state,
	}
}

func (r *K8sResolver) Resolve(event interface{}) ResolveResult {
	// Pod-focused resolution.
	// We only deal with pods and anomalous namespaces here.

	// Extract fields from event based on type
	var mntNsID uint32
	var pid uint32
	var comm string

	switch ev := event.(type) {
	case *processor.ProcessEvent:
		mntNsID = uint32(ev.MntNsId)
		pid = uint32(ev.Pid)
		comm = processor.CString(ev.Comm[:])
	case *processor.FileEvent:
		mntNsID = uint32(ev.MntNsId)
		pid = uint32(ev.Pid)
		comm = processor.CString(ev.Comm[:])
	case *processor.NetEvent:
		mntNsID = uint32(ev.MntNsId)
		pid = uint32(ev.Pid)
		comm = processor.CString(ev.Comm[:])
	default:
		return r.bareResult(StateUnknown)
	}

	// Fast path: host namespace — known at startup, resolved synchronously.
	// Transient node/host processes (kubelet-spawned probe helpers, SSH sessions on
	// the node) die before async resolution completes; without this they time out to
	// state=unknown. Mirrors the Docker resolver's host fast path.
	if r.hostNsID != 0 && mntNsID == r.hostNsID {
		return ResolveResult{
			Identity: WorkloadIdentity{Runtime: RuntimeHost, Service: HostProcessService, Env: r.env},
			Meta:     WorkloadMeta{Node: r.node, Region: r.region, Cluster: r.cluster},
			State:    StateResolved,
		}
	}

	r.mu.RLock()
	result, exists := r.cache[mntNsID]
	r.mu.RUnlock()

	if exists {
		return result
	}

	// Deduplicate: if this namespace is already being looked up, don't spawn another worker
	if _, loading := r.resolvingTasks.LoadOrStore(mntNsID, true); loading {
		return ResolveResult{State: StatePending}
	}

	// Offload heavy cgroup parsing to async worker pool
	go r.asyncResolveNamespace(mntNsID, pid, comm)

	// Return instantly (<1 microsecond execution path)
	return ResolveResult{State: StatePending}
}

func (r *K8sResolver) refreshCrictlCache() {
	if !r.refreshMu.TryLock() {
		return
	}
	defer r.refreshMu.Unlock()

	// Sync crictl output to containerIDMap (only crictl call, no /proc scan)
	newMap := crictlContainerMap(r.node, r.region, r.cluster, r.env)

	r.containerIDMu.Lock()
	r.containerIDMap = newMap
	r.containerIDMu.Unlock()
}

func (r *K8sResolver) buildInitialCache() map[uint32]ResolveResult {
	m := make(map[uint32]ResolveResult)

	// Seed the agent's own namespace as host (pid=1 host ns is handled by the
	// Resolve() fast path). Prevents the agent's own events from going through async
	// resolution.
	if r.selfNsID != 0 {
		m[r.selfNsID] = r.bareResult(StateResolved)
	}

	return m
}

func (r *K8sResolver) asyncResolveNamespace(mntNsID uint32, pid uint32, comm string) {
	defer r.resolvingTasks.Delete(mntNsID)

	// Acquire slot from semaphore pool (max 10 concurrent disk scans)
	r.lookupSem <- struct{}{}
	defer func() { <-r.lookupSem }()

	// 1. Targeted cgroup read for the event's PID (not global scan)
	containerID := containerIDFromK8sCgroup(strconv.Itoa(int(pid)))

	// Fallback: if pod vanished or cgroup parsing failed, mark as host process
	if containerID == "" {
		r.mu.Lock()
		r.cache[mntNsID] = ResolveResult{
			Identity: WorkloadIdentity{Runtime: RuntimeHost, Service: HostProcessService, Env: r.env},
			Meta:     WorkloadMeta{Node: r.node, Region: r.region, Cluster: r.cluster},
			State:    StateResolved,
		}
		r.mu.Unlock()
		return
	}

	// 2. Resolve metadata from containerIDMap (populated by periodic crictl sync)
	r.containerIDMu.RLock()
	metadata, found := r.containerIDMap[containerID]
	r.containerIDMu.RUnlock()

	r.mu.Lock()
	if found {
		// Use full metadata from crictl
		r.cache[mntNsID] = metadata
	} else {
		// Fallback: container not yet in crictl sync (pod is very new)
		// Use short container ID as placeholder until next crictl sync
		shortID := containerID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		r.cache[mntNsID] = ResolveResult{
			Identity: WorkloadIdentity{
				Runtime: RuntimeK8s,
				Service: "k8s-pod-" + shortID,
				Env:     r.env,
			},
			Meta: WorkloadMeta{
				Container: containerID,
				Node:      r.node,
				Region:    r.region,
				Cluster:   r.cluster,
			},
			State: StateResolved,
		}
	}
	r.mu.Unlock()
}

func containerIDFromK8sCgroup(pid string) string {
	path := fmt.Sprintf(procCgroupPathFmt, pid)

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineBytes := scanner.Bytes() // Zero allocation: slice into scanner buffer

		// Filter for K8s containers: cgroup v1 places K8s pods in "kubepods" hierarchy.
		if !bytes.Contains(lineBytes, []byte("kubepods")) {
			continue
		}

		idx := bytes.LastIndex(lineBytes, []byte(":"))
		if idx < 0 {
			continue
		}

		cgroupPath := bytes.Trim(lineBytes[idx+1:], "/")
		segments := bytes.Split(cgroupPath, []byte("/"))
		if len(segments) < 2 {
			continue
		}

		containerID := string(segments[len(segments)-1])
		// systemd cgroup driver: last segment is <prefix>-<id>.scope
		// (e.g. cri-containerd-<id>.scope, crio-<id>.scope, docker-<id>.scope).
		for _, prefix := range []string{"cri-containerd-", "crio-", "docker-"} {
			if strings.HasPrefix(containerID, prefix) && strings.HasSuffix(containerID, ".scope") {
				stripped := strings.TrimSuffix(strings.TrimPrefix(containerID, prefix), ".scope")
				if len(stripped) == containerIDLen {
					return stripped
				}
				break
			}
		}
		// cgroupfs cgroup driver: last segment is already the raw 64-hex container ID,
		// e.g. /kubepods/burstable/pod<uid>/<id>. Used by DO managed K8s (and any node
		// with cgroupDriver=cgroupfs). Without this the parser returned "", so every pod
		// resolved to RuntimeHost and container detection was silently disabled.
		if len(containerID) == containerIDLen && isHexID(containerID) {
			return containerID
		}
	}

	return ""
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

type crictlOutput struct {
	Containers []struct {
		ID     string            `json:"id"`
		Labels map[string]string `json:"labels"`
	} `json:"containers"`
}

func crictlContainerMap(node, region, cluster, env string) map[string]ResolveResult {
	m := make(map[string]ResolveResult)

	// Use crictl (Container Runtime Interface CLI) instead of kubectl:
	// - crictl inspects containers directly at runtime level (lower-level access)
	// - kubectl inspects pods through K8s API (higher-level, requires API availability)
	// We need container-level details (container ID, namespace mapping) for cgroup resolution.
	// Each K8s pod has multiple containers (init + app), and we need to map each one.
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

		// Normalize service name: strips Compose stack prefixes and converts underscores to dashes.
		// Ensures consistent naming across Docker Compose and K8s deployments.
		// Example: "order-processor-auth_service" → "auth-service"
		service := normalizeServiceName(containerName)

		m[c.ID] = ResolveResult{
			Identity: WorkloadIdentity{
				Runtime: RuntimeK8s,
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
