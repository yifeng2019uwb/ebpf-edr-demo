//go:build linux

package workload

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
)

const (
	// dockerShortIDLen is the conventional short ID length shown by `docker ps` (first 12 hex chars).
	// Used as a display-name fallback when a container is running but not yet in docker ps output.
	dockerShortIDLen      = 12
	dockerLookupWorkerLimit = 10 // max concurrent /proc cgroup reads per resolver instance
)

type DockerResolver struct {
	mu            sync.RWMutex
	cache         map[uint32]ResolveResult  // mntNsID → container identity (only containers, not system namespaces)
	containerToNs map[string]uint32         // containerID → mntNsID (O(1) reverse lookup for cleanup)
	// System namespace ID (snap docker, if found; host=1 is checked directly without caching)
	dockerdNsID   uint32 // Docker daemon namespace (snap docker), 0 if not found
	// Immutable metadata set at startup (from environment)
	hostname      string // Docker host/VM name
	region        string // Optional: cloud region
	env           string // Optional: cloud provider (gcp-vm, do-vm, local)
	// Docker event listener
	cli           *client.Client // Docker daemon client
	eventCtx      context.Context
	eventCancel   context.CancelFunc
	// Async worker pool controls (prevent goroutine explosion, protect /proc from concurrent scans)
	resolvingTasks sync.Map     // mntNsID -> bool (deduplicates: only one lookup per namespace)
	lookupSem      chan struct{} // Semaphore: limits concurrent /proc reads to 10
}

func (r *DockerResolver) Start() error {
	// Initialize reverse lookup map
	r.containerToNs = make(map[string]uint32)
	// Initialize worker pool semaphore (limits concurrent /proc scans)
	r.lookupSem = make(chan struct{}, dockerLookupWorkerLimit)
	// Cache snap docker namespace for O(1) checks in hot path
	r.dockerdNsID = findDockerDaemonNamespace()

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

	// Start Docker event listener (primary mechanism for real-time container lifecycle detection)
	r.eventCtx, r.eventCancel = context.WithCancel(context.Background())
	go r.listenDockerEvents()

	log.Printf("docker resolver: started (listening to Docker events)")

	return nil
}

func (r *DockerResolver) bareResult(state ResolveState, service string) ResolveResult {
	// Default: StateHost without explicit service uses "host"
	if service == "" && state == StateHost {
		service = "host"
	}
	return ResolveResult{
		Identity: WorkloadIdentity{Runtime: RuntimeDocker, Service: service, Env: r.env},
		Meta:     WorkloadMeta{Node: r.hostname, Region: r.region},
		State:    state,
	}
}

func (r *DockerResolver) Resolve(mntNsID uint32, pid uint32) ResolveResult {
	// Fast path: check if this is a system namespace (O(1) comparisons, no syscalls)
	// Host process always has pid=1
	if pid == 1 {
		return r.bareResult(StateHost, "host")
	}

	r.mu.RLock()
	dockerdNs := r.dockerdNsID
	result, ok := r.cache[mntNsID]
	r.mu.RUnlock()

	// Docker daemon namespace (snap docker) if found; cached at startup
	if dockerdNs != 0 && mntNsID == dockerdNs {
		return r.bareResult(StateHost, "docker-daemon")
	}

	if ok {
		return result
	}

	// CRITICAL: If pid == 0 (from main.go retry loop), do not spawn async worker.
	// /proc/0/cgroup is invalid and will fail, poisoning cache with StateUnknown
	// and short-circuiting the 60-second grace period for slow-starting containers.
	if pid == 0 {
		return r.bareResult(StatePending, "")
	}

	// Dedup: Only one async worker per namespace (sync.Map LoadOrStore).
	// If already resolving this namespace, skip (prevents goroutine explosion).
	if _, loading := r.resolvingTasks.LoadOrStore(mntNsID, true); !loading {
		// New namespace: spin up worker to resolve it asynchronously.
		// Pass pid so we can read /proc/[pid]/cgroup directly (fast + atomic).
		go r.asyncResolvePID(mntNsID, pid)
	}

	// Return immediately (< 1 microsecond, RAM-only path).
	return r.bareResult(StatePending, "")
}

// asyncResolvePID resolves a container from a specific PID's cgroup (targeted, fast).
// Reads /proc/[pid]/cgroup directly instead of scanning all of /proc/*/ns/mnt.
// This is atomic and captures container metadata before process is completely reaped (handles docker destroy).
// Runs with semaphore to limit concurrent disk I/O (max 10 workers).
// Guarantees cache entry is set to prevent memory leaks and infinite pending retries.
func (r *DockerResolver) asyncResolvePID(mntNsID uint32, pid uint32) {
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

	if cgroupTime > 5*time.Millisecond {
		log.Printf("DEBUG: cgroup parse took %v for pid %d", cgroupTime, pid)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Prevent race: another goroutine may have resolved this namespace already
	if _, exists := r.cache[mntNsID]; exists {
		return
	}

	if containerID == "" {
		// Process already cleaned up (docker destroy in progress).
		// Set fallback state to prevent infinite retry loops in pending buffer.
		// Mark as Unknown so pending events transition out cleanly.
		r.cache[mntNsID] = ResolveResult{State: StateUnknown}
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
	if r.dockerdNsID != 0 && r.cli != nil {
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
		} else {
			// Docker daemon unavailable
			r.dockerdNsID = 0
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

		// RECOVERY: If client is nil (Docker was down at boot), try to recreate it
		if r.cli == nil {
			newCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			if err != nil {
				time.Sleep(10 * time.Second) // Slow backoff if docker completely missing
				continue
			}
			r.cli = newCli
		}

		// LIVENESS CHECK: Verify daemon is alive before calling Events() (avoids blocking/hanging)
		// Ping() is lightweight and fails instantly if dockerd is stopped
		_, err := r.cli.Ping(r.eventCtx)
		if err != nil {
			// Docker daemon is down, mark as unavailable and probe again
			if r.dockerdNsID != 0 {
				log.Printf("docker resolver: docker daemon unavailable, disabling container tracking")
				r.mu.Lock()
				r.dockerdNsID = 0
				r.mu.Unlock()
			}
			time.Sleep(5 * time.Second) // Backoff before next probe
			continue
		}

		// Connection successful: Docker daemon is alive and responding
		opts := events.ListOptions{}
		eventsChan, errChan := r.cli.Events(r.eventCtx, opts)

		// Find/update dockerd namespace (may have changed if docker restarted)
		newDockerdNsID := findDockerDaemonNamespace()
		r.mu.Lock()
		r.dockerdNsID = newDockerdNsID
		r.mu.Unlock()

		if newDockerdNsID != 0 {
			log.Printf("docker resolver: docker daemon connected (ns %d)", newDockerdNsID)
		}

		// Catch up on containers that may have started while disconnected
		go r.lightweightRefresh()

		// Inner event processing loop
		for {
			select {
			case <-r.eventCtx.Done():
				return

			case event := <-eventsChan:
				// Trigger lightweight refresh on container lifecycle events
				if event.Action == "start" || event.Action == "stop" || event.Action == "die" {
					go r.lightweightRefresh()
				}

				if event.Action == "stop" || event.Action == "die" || event.Action == "remove" {
					// FIX: Wrap containerToNs lookup in RLock to eliminate race with lightweightRefresh
					r.mu.RLock()
					nsID, explicitMatch := r.containerToNs[event.ID]
					r.mu.RUnlock()

					if explicitMatch {
						// Grace period before cleanup: Docker sends stop/die event immediately, but eBPF
						// is still seeing processes from that container (in-flight syscalls). Keeping
						// the namespace in cache for 5s allows in-flight events to resolve correctly.
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
				// Event stream disconnected (e.g., systemctl stop docker)
				r.mu.Lock()
				if r.dockerdNsID != 0 {
					log.Printf("docker resolver: event stream disconnected: %v (entering probe mode)", err)
					r.dockerdNsID = 0
				}
				r.mu.Unlock()

				time.Sleep(2 * time.Second)
				break // Break inner loop to resume Ping probing
			}
		}
	}
}

// lightweightRefresh verifies cache consistency after Docker events.
// Triggered on container lifecycle events (start/stop/die), not on a timer.
// Uses only docker ps output to catch containers missed by Docker events.
func (r *DockerResolver) lightweightRefresh() {
	// Check availability without holding lock
	r.mu.RLock()
	avail := r.dockerdNsID
	r.mu.RUnlock()

	if avail == 0 {
		return
	}

	start := time.Now()
	idToInfo := make(map[string]containerIDInfo)
	containers, err := r.cli.ContainerList(context.Background(), container.ListOptions{})
	elapsed := time.Since(start)

	if err != nil {
		// Docker daemon unavailable, reset cached ID
		r.mu.Lock()
		r.dockerdNsID = 0
		r.mu.Unlock()
		return
	}

	// Build containerID → info map from Docker API response
	for _, c := range containers {
		if len(c.ID) < containerIDLen {
			continue
		}
		id := c.ID[:containerIDLen]
		name := c.Names[0]
		if len(name) > 0 && name[0] == '/' {
			name = name[1:]
		}
		service := normalizeServiceName(name)
		if label, ok := c.Labels["com.docker.compose.service"]; ok && label != "" {
			service = normalizeServiceName(label)
		}
		idToInfo[id] = containerIDInfo{name: name, service: service}
	}

	if elapsed > 5*time.Second {
		log.Printf("docker resolver: refresh took %v (slow docker API)", elapsed)
	}

	// Verify cache consistency: check if any running containers are missing from cache
	// FIX: Build O(1) inverted map instead of O(N×M) nested loop
	r.mu.RLock()
	defer r.mu.RUnlock()

	existingNames := make(map[string]struct{}, len(r.cache))
	for _, res := range r.cache {
		if res.Meta.Container != "" {
			existingNames[res.Meta.Container] = struct{}{}
		}
	}

	for containerID, info := range idToInfo {
		if _, found := existingNames[info.name]; !found {
			log.Printf("docker resolver: cache miss detected for container %s (will discover on next process event)", containerID[:12])
		}
	}
}

func (r *DockerResolver) buildCache() map[uint32]ResolveResult {
	// Build cache for running containers only (system namespaces checked directly in Resolve())
	m := make(map[uint32]ResolveResult)

	// Get host namespace ID to skip it during container discovery
	hostNsID := getMntNsID(1)

	// Discover all running containers and their namespaces via Docker API (not subprocess)
	idToInfo := make(map[string]containerIDInfo)
	containers, err := r.cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		// Docker unavailable at startup, reset cached ID to avoid retrying stale daemon
		r.dockerdNsID = 0
		// Return empty cache and continue with async resolution
		return m
	}

	// Build containerID → info map from Docker API response
	for _, c := range containers {
		if len(c.ID) < containerIDLen {
			continue
		}
		id := c.ID[:containerIDLen]
		name := c.Names[0]
		if len(name) > 0 && name[0] == '/' {
			name = name[1:] // Strip leading slash from Docker container name
		}
		service := normalizeServiceName(name)
		if label, ok := c.Labels["com.docker.compose.service"]; ok && label != "" {
			service = normalizeServiceName(label)
		}
		idToInfo[id] = containerIDInfo{name: name, service: service}
	}

	// Scan /proc directly (more efficient than Glob for high process counts)
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}

	for _, entry := range procEntries {
		// Short-circuit: skip non-directories
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		// Short-circuit: skip non-numeric names (like /proc/sys, /proc/net)
		// Fast check: just verify first byte is a digit
		if pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		// Guaranteed PID directory; read namespace directly
		nsPath := fmt.Sprintf(procNsMntPathStr, pidStr)
		nsID := getMntNsIDFromPath(nsPath)

		// Skip host namespace (handled separately in Resolve())
		if nsID == hostNsID {
			continue
		}
		if _, exists := m[nsID]; exists {
			continue
		}

		containerID := containerIDFromDockerCgroup(pidStr)
		if containerID == "" {
			continue
		}

		// Initialize with fallback: use short ID (first 12 chars) for container display name.
		// This handles containers that are transitioning: cgroup exists but docker ps hasn't caught up yet,
		// or container is stopping and docker ps no longer shows it but cgroup lingers.
		rawName := containerID[:dockerShortIDLen]
		service := rawName

		// Override fallback if docker ps has this container (idToInfo populated by dockerIDToInfo()).
		// This gives us the full container name and resolved service name (from Docker Compose labels).
		if info, ok := idToInfo[containerID]; ok {
			rawName = info.name
			service = info.service
		}

		m[nsID] = ResolveResult{
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
	}

	return m
}

// findDockerDaemonNamespace finds the mount namespace of the snap Docker daemon.
// Only returns snap docker namespace (known to be isolated and infrastructure).
// System docker may or may not have its own namespace, so we don't guess.
// Uses pgrep to efficiently locate dockerd process.
// Returns 0 if snap docker not found.
func findDockerDaemonNamespace() uint32 {
	// Use pgrep to find all PIDs matching 'dockerd' (equivalent to: ps aux | grep dockerd).
	// pgrep -f checks full command line, catching /snap/docker/... paths.
	// Much faster and cleaner than scanning all /proc files.
	out, err := exec.Command("pgrep", "-f", "dockerd").Output()
	if err != nil {
		return 0
	}

	pids := strings.Fields(string(out))

	for _, pidStr := range pids {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// Re-verify the cmdline to check for snap docker
		cmdlineBytes, err := os.ReadFile(fmt.Sprintf(procCmdlinePathFmt, pid))
		if err != nil {
			continue
		}
		cmdline := string(cmdlineBytes)

		// Only return snap docker (we know it's isolated infrastructure namespace)
		if strings.Contains(cmdline, "/snap/docker") || strings.Contains(cmdline, "/run/snap.docker") {
			nsID := getMntNsID(pid)
			if nsID != 0 {
				return nsID
			}
		}
	}

	return 0 // No snap docker found
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

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineBytes := scanner.Bytes() // Zero allocation: slice into scanner buffer

		// cgroup v1 format: /docker/<container-id>
		if idx := strings.Index(string(lineBytes), "/docker/"); idx != -1 {
			idPart := bytes.TrimSpace(lineBytes[idx+len("/docker/"):])
			// Docker uses SHA256 → exactly 64 hex chars
			if len(idPart) >= containerIDLen {
				return string(idPart[:containerIDLen])
			}
		}

		// cgroup v2 systemd format: docker-<container-id>.scope
		if bytes.Contains(lineBytes, []byte("docker-")) && bytes.Contains(lineBytes, []byte(".scope")) {
			start := bytes.Index(lineBytes, []byte("docker-")) + len("docker-")
			end := bytes.LastIndex(lineBytes, []byte(".scope"))
			if end > start {
				id := lineBytes[start:end]
				if len(id) == containerIDLen {
					return string(id)
				}
			}
		}
	}

	return ""
}
