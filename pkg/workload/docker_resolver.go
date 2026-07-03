//go:build linux

package workload

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
)

// dockerShortIDLen is the conventional short ID length shown by `docker ps` (first 12 hex chars).
// Used as a display-name fallback when a container is running but not yet in docker ps output.
const dockerShortIDLen = 12

type DockerResolver struct {
	mu            sync.RWMutex
	cache         map[uint32]ResolveResult  // mntNsID → container identity
	containerToNs map[string]uint32         // containerID → mntNsID (O(1) reverse lookup for cleanup)
	refreshMu     sync.Mutex
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
	// Initialize worker pool semaphore (limits concurrent /proc scans to 10)
	r.lookupSem = make(chan struct{}, 10)
	// Initial cache build
	start := time.Now()
	r.cache = r.buildCache()
	elapsed := time.Since(start)
	log.Printf("docker resolver: initial buildCache took %v (found %d namespaces)", elapsed, len(r.cache))
	r.syncContainerToNs()

	// Connect to Docker daemon for event-driven refresh
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("warning: Docker client failed: %v (will rely on on-demand lookup)", err)
		// No fallback — rely on on-demand lookupNamespace() for unknown containers
		return nil
	}
	r.cli = cli

	// Start Docker event listener (primary mechanism for real-time container lifecycle detection)
	r.eventCtx, r.eventCancel = context.WithCancel(context.Background())
	go r.listenDockerEvents()

	log.Printf("docker resolver: started (listening to Docker events)")

	return nil
}

func (r *DockerResolver) bareResult(state ResolveState) ResolveResult {
	service := ""
	if state == StateHost {
		service = "host"
	}
	return ResolveResult{
		Identity: WorkloadIdentity{Runtime: RuntimeDocker, Service: service, Env: r.env},
		Meta:     WorkloadMeta{Node: r.hostname, Region: r.region},
		State:    state,
	}
}

func (r *DockerResolver) Resolve(mntNsID uint32, pid uint32) ResolveResult {
	r.mu.RLock()
	result, ok := r.cache[mntNsID]
	r.mu.RUnlock()

	if ok {
		return result
	}

	// Dedup: Only one async worker per namespace (sync.Map LoadOrStore).
	// If already resolving this namespace, skip (prevents goroutine explosion).
	if _, loading := r.resolvingTasks.LoadOrStore(mntNsID, true); !loading {
		// New namespace: spin up worker to resolve it asynchronously.
		// Pass pid so we can read /proc/[pid]/cgroup directly (fast + atomic).
		go r.asyncResolvePID(mntNsID, pid)
	}

	// Return immediately (< 1 microsecond, RAM-only path).
	return r.bareResult(StatePending)
}

// asyncResolvePID resolves a container from a specific PID's cgroup (targeted, fast).
// Reads /proc/[pid]/cgroup directly instead of scanning all of /proc/*/ns/mnt.
// This is atomic and captures container metadata before process is completely reaped (handles docker destroy).
// Runs with semaphore to limit concurrent disk I/O (max 10 workers).
// Guarantees cache entry is set to prevent memory leaks and infinite pending retries.
func (r *DockerResolver) asyncResolvePID(mntNsID uint32, pid uint32) {
	// Always clean up the task tracking to allow future retries if needed
	defer r.resolvingTasks.Delete(mntNsID)

	// Acquire worker slot (semaphore limits to 10 concurrent /proc readers)
	r.lookupSem <- struct{}{}
	defer func() { <-r.lookupSem }()

	// Read container ID from target PID's cgroup (direct, atomic, no glob scan)
	containerID := containerIDFromDockerCgroup(strconv.Itoa(int(pid)))

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

	// Try to get full name from docker ps (async, so delay doesn't block main pipeline)
	idToInfo := dockerIDToInfo()
	if info, ok := idToInfo[containerID]; ok {
		rawName = info.name
		service = info.service
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
	log.Printf("docker resolver: discovered container %s (ns %d)", containerID[:12], mntNsID)
}

func (r *DockerResolver) refresh() {
	if !r.refreshMu.TryLock() {
		return
	}
	defer r.refreshMu.Unlock()

	start := time.Now()
	m := r.buildCache()
	elapsed := time.Since(start)

	r.mu.Lock()
	r.cache = m
	r.syncContainerToNs()
	r.mu.Unlock()

	log.Printf("docker resolver: buildCache took %v (found %d namespaces)", elapsed, len(m))
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

// listenDockerEvents subscribes to Docker events and refreshes cache on container lifecycle changes.
// This is the primary mechanism for detecting new/removed containers in real-time.
func (r *DockerResolver) listenDockerEvents() {
	if r.cli == nil {
		return
	}

	for {
		select {
		case <-r.eventCtx.Done():
			return
		default:
		}

		// Subscribe to container lifecycle events
		opts := events.ListOptions{}
		eventsChan, errChan := r.cli.Events(r.eventCtx, opts)

		for {
			select {
			case <-r.eventCtx.Done():
				return
			case event := <-eventsChan:
				// Trigger lightweight refresh on container lifecycle events
				// This verifies cache consistency (catches event ordering issues, missed events)
				if event.Action == "start" || event.Action == "stop" || event.Action == "die" {
					go r.lightweightRefresh()
				}

				if event.Action == "stop" || event.Action == "die" || event.Action == "remove" {
					// Grace period before cleanup (TEMPORARY: 5s hardcoded):
					// Race condition: Docker sends stop/die event immediately, but eBPF is still seeing
					// processes from that container spawning/exiting (in-flight syscalls). If we delete
					// from cache immediately, those processes become "unknown namespace" → false T1611
					// container escape alerts. By keeping the namespace in cache for 5s, in-flight
					// events resolve correctly against cached metadata.
					// TODO: Replace with activity-based cleanup (track last event time per namespace,
					// clean up only after 2+ seconds of inactivity + minimum grace time). This avoids
					// time-guessing and handles both quick shutdowns and graceful shutdowns elegantly.
					nsID := r.containerToNs[event.ID]
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
			case err := <-errChan:
				// Event stream disconnected, reconnect with backoff
				if err != nil {
					log.Printf("docker resolver: events error: %v (reconnecting...)", err)
				}
				time.Sleep(1 * time.Second) // Backoff to avoid busy loop
				break // Break inner loop to reconnect
			}
		}
	}
}

// lightweightRefresh verifies cache consistency after Docker events.
// Triggered on container lifecycle events (start/stop/die), not on a timer.
// Uses only docker ps output to catch containers missed by Docker events.
func (r *DockerResolver) lightweightRefresh() {
	start := time.Now()
	idToInfo := dockerIDToInfo()
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		log.Printf("docker resolver: refresh took %v (slow docker ps)", elapsed)
	}

	// Verify cache consistency: check if any running containers are missing from cache
	r.mu.RLock()
	defer r.mu.RUnlock()

	for containerID, info := range idToInfo {
		// Check if this container is in cache
		found := false
		for _, result := range r.cache {
			if result.Meta.Container == info.name {
				found = true
				break
			}
		}
		if !found {
			// Container in docker ps but not in cache — missed by events
			log.Printf("docker resolver: cache miss detected for container %s (will discover on next event)", containerID[:12])
			// No action needed here — on-demand lookupNamespace will find it when events arrive
		}
	}
}

func (r *DockerResolver) buildCache() map[uint32]ResolveResult {
	m := make(map[uint32]ResolveResult)

	hostNsID := getMntNsID(1)
	if hostNsID != 0 {
		m[hostNsID] = r.bareResult(StateHost)
	}

	// Find Docker daemon namespace (snap docker or system docker)
	// Snap docker typically runs as PID 1534 or similar; also check /var/run/docker.sock
	dockerdNsID := findDockerDaemonNamespace()
	if dockerdNsID != 0 && dockerdNsID != hostNsID {
		// Docker daemon infrastructure namespace — treat as system
		m[dockerdNsID] = r.bareResult(StateHost)
	}

	idToInfo := dockerIDToInfo()

	entries, err := filepath.Glob(procNsMntPattern)
	if err != nil {
		return m
	}

	for _, nsPath := range entries {
		parts := strings.Split(nsPath, "/")
		pidStr := parts[2]

		nsID := getMntNsIDFromPath(nsPath)

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

// findDockerDaemonNamespace finds the mount namespace of the Docker daemon.
// Prioritizes snap docker over system docker to find the isolated namespace.
// Returns 0 if not found.
func findDockerDaemonNamespace() uint32 {
	// Try to find dockerd process by searching /proc
	entries, err := filepath.Glob(procCmdlinePattern)
	if err != nil {
		return 0
	}

	var snapDockerNsID uint32

	for _, cmdlinePath := range entries {
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		cmdline := string(data)

		// Look for dockerd processes
		if !strings.Contains(cmdline, "dockerd") {
			continue
		}

		// Extract PID from path: /proc/1234/cmdline → 1234
		parts := strings.Split(cmdlinePath, "/")
		if len(parts) < 3 {
			continue
		}

		pid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		nsID := getMntNsID(pid)
		if nsID == 0 {
			continue
		}

		// Prioritize snap docker (contains /snap/docker or /run/snap.docker)
		if strings.Contains(cmdline, "/snap/docker") || strings.Contains(cmdline, "/run/snap.docker") {
			snapDockerNsID = nsID
			break // Found snap docker, use it
		}
	}

	if snapDockerNsID != 0 {
		return snapDockerNsID
	}

	return 0
}

// containerIDInfo holds the Docker container name and its resolved service name.
type containerIDInfo struct {
	name    string // full container name, e.g. "sensor-env-sensor-1"
	service string // service name for policy matching, e.g. "env-sensor"
}

// dockerIDToInfo returns a map from full container ID to containerIDInfo.
// Runs `docker ps` to get running containers only (stopped containers excluded).
// Maps each container ID to its full name and service name for detection rules.
//
// Service name priority:
// 1. Docker Compose label (com.docker.compose.service) — most reliable for Compose services
// 2. Full container name normalized — fallback for non-Compose containers
//
// Note: This snapshot is taken once per refresh (every 10s). Containers starting/stopping
// between refreshes may not be in this map. Use short ID fallback if container not found.
func dockerIDToInfo() map[string]containerIDInfo {
	m := make(map[string]containerIDInfo)

	out, err := exec.Command(
		"docker",
		"ps",
		"--no-trunc",
		"--format",
		`{{.ID}} {{.Names}} {{.Label "com.docker.compose.service"}}`,
	).Output()
	if err != nil {
		return m
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		id, name := fields[0], fields[1]
		service := name // use full container name; overridden by Compose label if present
		if len(fields) >= 3 && fields[2] != "" {
			service = fields[2]
		}
		m[id] = containerIDInfo{name: name, service: service}
	}

	return m
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
		line := scanner.Text()

		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			id := strings.TrimSpace(parts[len(parts)-1])
			// cgroup v1 format: /docker/<container-id>
			// e.g. /docker/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 (64 chars)
			// Docker uses SHA256 → exactly 64 hex chars
			if len(id) == containerIDLen {
				return id
			}
		}

		if strings.Contains(line, "docker-") && strings.Contains(line, ".scope") {
			start := strings.Index(line, "docker-") + len("docker-")
			end := strings.LastIndex(line, ".scope")
			if end > start {
				id := line[start:end]
				// cgroup v2 systemd format: docker-<container-id>.scope
				// e.g. docker-a1b2c3d4e5f6...64chars.scope → extract between "docker-" and ".scope"
				// Docker uses SHA256 → exactly 64 hex chars.
				if len(id) == containerIDLen {
					return id
				}
			}
		}
	}

	return ""
}
