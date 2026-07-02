//go:build linux

package workload

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const dockerRefreshInterval = 10 * time.Second

// dockerShortIDLen is the conventional short ID length shown by `docker ps` (first 12 hex chars).
// Used as a display-name fallback when a container is running but not yet in docker ps output.
const dockerShortIDLen = 12

type DockerResolver struct {
	mu        sync.RWMutex
	cache     map[uint32]ResolveResult // containerID → container identity; refreshed periodically (containers start/stop)
	refreshMu sync.Mutex
	// Immutable metadata set at startup (from environment)
	hostname string // Docker host/VM name
	region   string // Optional: cloud region
	env      string // Optional: cloud provider (gcp-vm, do-vm, local)
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

func (r *DockerResolver) Resolve(mntNsID uint32, _ uint32) ResolveResult {
	r.mu.RLock()
	result, ok := r.cache[mntNsID]
	r.mu.RUnlock()

	if ok {
		return result
	}

	go r.refresh()

	return r.bareResult(StatePending)
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
