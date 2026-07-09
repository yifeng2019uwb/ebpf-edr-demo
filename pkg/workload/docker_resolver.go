//go:build linux

package workload

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"

	"ebpf-edr-demo/internal/processor"
)

const (
	// containerIDLen is the length of a full SHA256 container ID (64 hex chars).
	// All runtimes (Docker, containerd, CRI-O) use SHA256. Used to validate
	// container IDs parsed from /proc/<pid>/cgroup paths.
	// dockerShortIDLen is the conventional short ID length shown by `docker ps` (first 12 hex chars).
	// Used as a display-name fallback when a container is running but not yet in docker ps output.
	containerIDLen            = 64
	dockerShortIDLen          = 12
	dockerLookupWorkerLimit   = 10 // max concurrent /proc cgroup reads per resolver instance
	dockerComposeServiceLabel = "com.docker.compose.service"
)

var (
	// Docker cgroup patterns for both v1 and v2 formats
	dockerV1Pattern = []byte("/docker/")
	dockerV2Prefix  = []byte("docker-")
	dockerV2Suffix  = []byte(".scope")
)

type DockerResolver struct {
	mu            sync.RWMutex
	cache         map[uint32]ResolveResult // mntNsID → container identity (only containers, not system namespaces)
	containerToNs map[string]uint32        // containerID → mntNsID (O(1) reverse lookup for cleanup)
	// Immutable metadata set at startup (from environment)
	hostname string // Docker host/VM name
	region   string // Optional: cloud region
	env      string // Optional: cloud provider (gcp-vm, do-vm, local)
	hostNsID uint32 // host mount namespace ID (from PID 1 at startup); 0 if unknown
	// Docker event listener
	cli         *client.Client // Docker daemon client
	eventCtx    context.Context
	eventCancel context.CancelFunc
	// Async worker pool controls (prevent goroutine explosion, protect /proc from concurrent scans)
	resolvingTasks sync.Map      // mntNsID -> bool (deduplicates: only one lookup per namespace)
	lookupSem      chan struct{} // Semaphore: limits concurrent /proc reads to 10
	// One-time diagnostic: confirms the host-namespace fast path is live
	hostFastPathOnce sync.Once
}

func (r *DockerResolver) Start() error {
	// Initialize reverse lookup map
	r.containerToNs = make(map[string]uint32)
	// Initialize worker pool semaphore (limits concurrent /proc scans)
	r.lookupSem = make(chan struct{}, dockerLookupWorkerLimit)

	// Host namespace ID: enables the Resolve() fast path for host processes.
	// Set before the Docker client check so it works even without a daemon.
	r.hostNsID = getMntNsID(1)
	log.Printf("docker resolver: host namespace ID = %d (0 means detection failed, fast path disabled)", r.hostNsID)

	// Connect to Docker daemon early (needed for buildCache to use Docker API)
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("warning: Docker client failed: %v (will rely on on-demand lookup)", err)
		// No fallback — rely on on-demand lookupNamespace() for unknown containers
		return nil
	}
	r.cli = cli

	// Initial cache build (only container namespaces, not system namespaces)
	start := time.Now()
	r.cache = r.buildCache()
	elapsed := time.Since(start)
	log.Printf("docker resolver: initial buildCache took %v (found %d namespaces)", elapsed, len(r.cache))
	r.syncContainerToNs()

	r.eventCtx, r.eventCancel = context.WithCancel(context.Background())

	// Event listener disabled: its reconnect/recovery path had unresolved issues and is hard
	// to test without a scriptable Docker daemon. Containers are discovered on-demand via
	// asyncResolvePID instead, so detection is correct; the cache just never evicts stale entries.
	// go r.listenDockerEvents()
	log.Printf("docker resolver: started (relying on on-demand async resolution)")

	return nil
}

func (r *DockerResolver) bareResult(state ResolveState, service string) ResolveResult {
	// Container-focused result.
	return ResolveResult{
		Identity: WorkloadIdentity{Runtime: RuntimeDocker, Service: service, Env: r.env},
		Meta:     WorkloadMeta{Node: r.hostname, Region: r.region},
		State:    state,
	}
}

func (r *DockerResolver) Resolve(event interface{}) ResolveResult {
	// Container-focused resolution.
	// We only deal with containers and anomalous namespaces here.

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
		return r.bareResult(StateUnknown, "")
	}

	// Fast path 1: host namespace — known at startup, deliberately never cached.
	// Without this, transient host processes (deploy scripts, snap helpers,
	// getent) die before async resolution completes, the shared host namespace
	// never gets cached, and every one of them times out to state=unknown.
	if r.hostNsID != 0 && mntNsID == r.hostNsID {
		r.hostFastPathOnce.Do(func() {
			log.Printf("DEBUG: docker resolver: host-namespace fast path active (first hit: pid %d comm %s ns %d)", pid, comm, mntNsID)
		})
		return ResolveResult{
			Identity: WorkloadIdentity{Runtime: RuntimeHost, Service: "host-process", Env: r.env},
			Meta:     WorkloadMeta{Node: r.hostname, Region: r.region},
			State:    StateResolved,
		}
	}

	r.mu.RLock()
	result, ok := r.cache[mntNsID]
	r.mu.RUnlock()

	// Fast path 2: Cache hit (container already resolved)
	if ok {
		return result
	}

	// Dedup: Only one async worker per namespace (sync.Map LoadOrStore).
	// If already resolving this namespace, skip (prevents goroutine explosion).
	if _, loading := r.resolvingTasks.LoadOrStore(mntNsID, true); !loading {
		// New namespace: spin up worker to resolve it asynchronously.
		// Pass pid and comm so we can check whitelist without reading /proc.
		go r.asyncResolvePID(mntNsID, pid, comm)
	}

	// Return immediately (< 1 microsecond, RAM-only path).
	return r.bareResult(StatePending, "")
}

// asyncResolvePID resolves a container from a specific PID's cgroup (targeted, fast).
// Reads /proc/[pid]/cgroup directly instead of scanning all of /proc/*/ns/mnt.
// This is atomic and captures container metadata before process is completely reaped (handles docker destroy).
// Runs with semaphore to limit concurrent disk I/O (max 10 workers).
// Guarantees cache entry is set to prevent memory leaks and infinite pending retries.
// comm is passed from eBPF event to avoid procfs race when checking whitelists.
func (r *DockerResolver) asyncResolvePID(mntNsID uint32, pid uint32, comm string) {
	log.Printf("DEBUG: asyncResolvePID called for ns=%d pid=%d comm=%s", mntNsID, pid, comm)
	var cgroupTime, inspectTime time.Duration

	// Always clean up the task tracking to allow future retries if needed
	defer r.resolvingTasks.Delete(mntNsID)

	// Acquire worker slot (semaphore limits to 10 concurrent /proc readers)
	r.lookupSem <- struct{}{}
	defer func() { <-r.lookupSem }()

	// Read container ID from target PID's cgroup (direct, atomic, no glob scan)
	cgroupStart := time.Now()
	containerID := containerIDFromDockerCgroup(strconv.Itoa(int(pid)))
	cgroupTime = time.Since(cgroupStart)

	if cgroupTime > 2*time.Millisecond {
		log.Printf("DEBUG: cgroup parse took %v for pid %d", cgroupTime, pid)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Prevent race: another goroutine may have resolved this namespace already
	if _, exists := r.cache[mntNsID]; exists {
		return
	}

	if containerID == "" {
		// PROCFS RACE PROTECTION:
		// Check if the process directory is completely missing.
		// If it's gone, it was an ephemeral task (like a health-check curl).
		// Drop it without updating the cache, keeping the namespace clean.
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			log.Printf("DEBUG: docker resolver: skipping cache write for transient dead process %s (pid %d)", comm, pid)
			return
		}

		// DECOUPLED HOST WORKLOAD FALLBACK:
		// The process is still fully active in the system, but it has no container tracking context.
		// This happens on native host processes (e.g. sshd sessions or local shells).
		// Cache this explicitly as a non-container host result to stop lookup thrashing.
		log.Printf("DEBUG: docker resolver: process %s (pid %d, ns %d) verified host environment -> cached as host-process", comm, pid, mntNsID)
		r.cache[mntNsID] = ResolveResult{
			Identity: WorkloadIdentity{Runtime: RuntimeHost, Service: "host-process", Env: r.env},
			Meta:     WorkloadMeta{Node: r.hostname, Region: r.region},
			State:    StateResolved,
		}
		return
	}

	// Extract service name from container ID
	// Use docker ps if available for full name, fallback to short ID
	rawName := containerID
	service := containerID
	if len(containerID) >= dockerShortIDLen {
		rawName = containerID[:dockerShortIDLen]
		service = rawName
	}

	// Optimization: Use Docker API directly instead of fork+exec (docker ps)
	// ContainerInspect via unix socket is microseconds, not milliseconds
	if r.cli != nil {
		inspectStart := time.Now()
		inspect, err := r.cli.ContainerInspect(r.eventCtx, containerID)
		inspectTime := time.Since(inspectStart)

		if inspectTime > 10*time.Millisecond {
			log.Printf("DEBUG: ContainerInspect took %v for %s", inspectTime, containerID[:12])
		}

		if err == nil {
			// Use container name from API (trim leading "/" added by Docker)
			rawName = strings.TrimPrefix(inspect.Name, "/")
			service = rawName
			// Check for docker-compose service label (in-memory, no external call)
			if svcLabel, ok := inspect.Config.Labels["com.docker.compose.service"]; ok {
				service = svcLabel
			}
		}
	}

	// Atomically update cache with resolved identity
	r.cache[mntNsID] = ResolveResult{
		Identity: WorkloadIdentity{
			Runtime: RuntimeDocker,
			Service: service,
			Env:     r.env,
		},
		Meta: WorkloadMeta{
			Container: rawName,
			Pod:       rawName,
			Node:      r.hostname,
			Region:    r.region,
		},
		State: StateResolved,
	}
	r.containerToNs[containerID] = mntNsID

	if cgroupTime+inspectTime > 50*time.Millisecond {
		log.Printf("DEBUG: asyncResolvePID latency (cgroup %v, inspect %v) for ns %d", cgroupTime, inspectTime, mntNsID)
	}

	log.Printf("docker resolver: discovered container %s (ns %d)", containerID[:12], mntNsID)
}

// syncContainerToNs rebuilds the containerID→mntNsID reverse lookup map from cache.
// Must be called with mu locked.
func (r *DockerResolver) syncContainerToNs() {
	r.containerToNs = make(map[string]uint32)
	for nsID, result := range r.cache {
		if result.Meta.Container != "" {
			r.containerToNs[result.Meta.Container] = nsID
		}
	}
}

// listenDockerEvents subscribes to Docker events and detects daemon availability via liveness probing.
// Uses Ping() to verify daemon is alive before calling Events() to avoid blocking/hanging.
// Handles recovery when Docker is absent at startup or stops/restarts after startup.
func (r *DockerResolver) listenDockerEvents() {
	for {
		select {
		case <-r.eventCtx.Done():
			return
		default:
		}

		// RECOVERY: Acquire lock to safely create client if absent (Fix #2: data race protection)
		r.mu.Lock()
		if r.cli == nil {
			newCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			if err != nil {
				r.mu.Unlock()
				time.Sleep(10 * time.Second)
				continue
			}
			r.cli = newCli
		}
		cli := r.cli // Snapshot reference to avoid multi-thread pointer swapping
		r.mu.Unlock()

		// LIVENESS CHECK: Verify daemon is alive before calling Events()
		_, err := cli.Ping(r.eventCtx)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		opts := events.ListOptions{}
		eventsChan, errChan := cli.Events(r.eventCtx, opts)

		// Catch up on containers safely
		r.lightweightRefresh()

	eventLoop: // Fix #1: Labeled loop to allow true breakout from errChan select
		for {
			select {
			case <-r.eventCtx.Done():
				return

			case event := <-eventsChan:
				if event.Action == "start" || event.Action == "stop" || event.Action == "die" {
					go r.lightweightRefresh()
				}

				if event.Action == "stop" || event.Action == "die" || event.Action == "remove" {
					r.mu.RLock()
					nsID, explicitMatch := r.containerToNs[event.ID]
					r.mu.RUnlock()

					if explicitMatch {
						go func(containerID string, ns uint32) {
							time.Sleep(5 * time.Second)
							r.mu.Lock()
							if current, exists := r.containerToNs[containerID]; exists && current == ns {
								delete(r.cache, ns)
								delete(r.containerToNs, containerID)
								log.Printf("docker resolver: cleaned up container %s (ns %d)", containerID[:12], ns)
							}
							r.mu.Unlock()
						}(event.ID, nsID)
					}
				}

			case err := <-errChan:
				log.Printf("docker resolver: event stream disconnected: %v (entering probe mode)", err)
				time.Sleep(2 * time.Second)
				break eventLoop // Fix #1: Exits the internal loop entirely, not just the select block
			}
		}
	}
}

// lightweightRefresh verifies cache consistency after Docker events.
// Triggered on container lifecycle events (start/stop/die), not on a timer.
// Uses only docker ps output to catch containers missed by Docker events.
func (r *DockerResolver) lightweightRefresh() {
	// Check Docker daemon availability without holding lock
	if r.cli == nil {
		return
	}

	start := time.Now()
	idToInfo := make(map[string]containerIDInfo)
	containers, err := r.cli.ContainerList(context.Background(), container.ListOptions{})
	elapsed := time.Since(start)

	if err != nil {
		// Docker daemon unavailable, connection will be reset by event listener
		return
	}

	// Build containerID → info map from Docker API response
	for _, c := range containers {
		if len(c.ID) != containerIDLen || len(c.Names) == 0 {
			continue
		}

		name := strings.TrimPrefix(c.Names[0], "/")
		service := name

		if label, ok := c.Labels[dockerComposeServiceLabel]; ok && label != "" {
			service = label
		}
		idToInfo[c.ID] = containerIDInfo{name: name, service: service}
	}

	if elapsed > 5*time.Second {
		log.Printf("docker resolver: refresh took %v (slow docker API)", elapsed)
	}

	// Fix 3: Minimize critical zone lock footprint
	r.mu.RLock()
	existingNames := make(map[string]struct{}, len(r.cache))
	for _, res := range r.cache {
		if res.Meta.Container != "" {
			existingNames[res.Meta.Container] = struct{}{}
		}
	}
	r.mu.RUnlock() // Lock released before entering slow log I/O loops

	for containerID, info := range idToInfo {
		if _, found := existingNames[info.name]; !found {
			log.Printf("docker resolver: cache miss detected for container %s (will discover on next process event)", containerID[:12])
		}
	}
}

func (r *DockerResolver) buildCache() map[uint32]ResolveResult {
	// Build cache for running containers (system namespaces checked directly in Resolve())
	m := make(map[uint32]ResolveResult)

	hostNsID := getMntNsID(1)

	idToInfo := make(map[string]containerIDInfo)
	containers, err := r.cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return m
	}

	for _, c := range containers {
		if len(c.ID) != containerIDLen || len(c.Names) == 0 {
			continue
		}

		name := strings.TrimPrefix(c.Names[0], "/")
		service := name

		if label, ok := c.Labels[dockerComposeServiceLabel]; ok && label != "" {
			service = label
		}
		idToInfo[c.ID] = containerIDInfo{name: name, service: service}
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}

	// Keep track of namespaces we already resolved during this boot scan
	// to prevent redundant cgroup filesystem parsing while keying results by PID
	resolvedNamespaces := make(map[uint32]ResolveResult)

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		// Validate PID format without parsing (we key by namespace ID, not PID)
		if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		nsPath := fmt.Sprintf(procNsMntPathStr, pidStr)
		nsID := getMntNsIDFromPath(nsPath)

		if nsID == hostNsID {
			continue
		}

		// If we already know the metadata for this namespace, reuse the cached result
		if _, exists := resolvedNamespaces[uint32(nsID)]; exists {
			continue
		}

		containerID := containerIDFromDockerCgroup(pidStr)
		if containerID == "" {
			continue
		}

		rawName := containerID
		service := rawName

		if info, ok := idToInfo[containerID]; ok {
			rawName = info.name
			service = info.service
		}

		res := ResolveResult{
			Identity: WorkloadIdentity{
				Runtime: RuntimeDocker,
				Service: service,
				Env:     r.env,
			},
			Meta: WorkloadMeta{
				Container: rawName,
				Pod:       rawName,
				Node:      r.hostname,
				Region:    r.region,
			},
			State: StateResolved,
		}

		// Cache the result for this namespace keyed by mntNsID (not PID)
		resolvedNamespaces[uint32(nsID)] = res
		m[uint32(nsID)] = res
	}

	return m
}

// containerIDInfo holds the Docker container name and its resolved service name.
type containerIDInfo struct {
	name    string // full container name, e.g. "sensor-env-sensor-1"
	service string // service name for policy matching, e.g. "env-sensor"
}

func containerIDFromDockerCgroup(pid string) string {
	path := fmt.Sprintf(procCgroupPathFmt, pid)

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// bufio.Scanner wraps the file reader and doesn't require explicit Close().
	// File close via defer f.Close() above is sufficient for cleanup.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineBytes := scanner.Bytes()

		// cgroup v1 format: /docker/<container-id>/cpuset/...
		if idx := bytes.Index(lineBytes, dockerV1Pattern); idx != -1 {
			idPart := bytes.TrimSpace(lineBytes[idx+len(dockerV1Pattern):])
			// Split on "/" to extract just the container ID (before the cgroup subsystem)
			if slashIdx := bytes.IndexByte(idPart, '/'); slashIdx != -1 {
				idPart = idPart[:slashIdx]
			}
			if len(idPart) == containerIDLen {
				return string(idPart)
			}
		}

		// cgroup v2 systemd format: .../docker-<container-id>.scope
		if idx := bytes.Index(lineBytes, dockerV2Prefix); idx != -1 {
			start := idx + len(dockerV2Prefix)
			// Search for .scope strictly *after* the docker- token
			if endOffset := bytes.Index(lineBytes[start:], dockerV2Suffix); endOffset != -1 {
				end := start + endOffset
				id := lineBytes[start:end]
				if len(id) == containerIDLen {
					return string(id)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Layer 2: cgroup scanner error for PID %s: %v", pid, err)
	}

	return ""
}
