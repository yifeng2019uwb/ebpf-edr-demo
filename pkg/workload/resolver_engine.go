//go:build linux

// resolver_engine.go — the runtime-agnostic workload resolver (new design).
//
// This file is self-contained and does NOT touch the existing DockerResolver /
// K8sResolver; main.go will switch to the Engine later. The Engine owns everything
// runtime-agnostic (the cache, in-flight dedup, host fast path, cgroup→(id,runtime)
// dispatch); per-runtime metadata lookup is delegated to a RuntimeClient.
//
// Layering: pipeline Enricher → WorkloadResolver (interface) → Engine (this) →
// RuntimeClient (docker / cri). See the design discussion in HANDOFF.
package workload

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	engineLookupWorkers = 10 // max concurrent metadata lookups
	shortIDLen          = 12 // human-readable container short id (first 12 hex)
)

// cgroupPrefixRuntime maps a systemd-driver cgroup leaf prefix to the runtime that
// owns it. The leaf both yields the container ID and names the runtime, so this map
// is the dispatch key. Add a runtime = one entry here.
var cgroupPrefixRuntime = map[string]Runtime{
	"docker-":         RuntimeDocker,
	"cri-containerd-": RuntimeK8s,
	"crio-":           RuntimeK8s,
}

// containerIDFromCgroupLeaf extracts (containerID, runtime) from a cgroup v2 leaf:
//   - systemd driver "<prefix><64hex>.scope" → (id, runtime)
//   - cgroupfs driver raw "<64hex>"          → (id, RuntimeUnknown) — runtime not in the leaf
//   - host/system leaf (e.g. "init.scope")   → ("", RuntimeUnknown)
//   - prefix matches but id malformed        → ("", RuntimeUnknown)
//
// Kept separate from the existing containerIDFromCgroupLeaf so the current resolvers
// are untouched; this variant additionally reports the runtime for dispatch.
func containerIDFromCgroupLeaf(leaf string) (string, Runtime) {
	for prefix, rt := range cgroupPrefixRuntime {
		if strings.HasPrefix(leaf, prefix) && strings.HasSuffix(leaf, ".scope") {
			id := strings.TrimSuffix(strings.TrimPrefix(leaf, prefix), ".scope")
			if len(id) == containerIDLen {
				return id, rt
			}
			return "", RuntimeUnknown
		}
	}
	if len(leaf) == containerIDLen && isHexID(leaf) {
		return leaf, RuntimeUnknown
	}
	return "", RuntimeUnknown
}

// RuntimeClient looks up container metadata from ONE container runtime's API. It owns
// only its connection; it never sees a mount namespace, cgroup, or the cache. Its whole
// surface is "container ID → runtime-specific identity + metadata."
type RuntimeClient interface {
	Runtime() Runtime
	// Enrich returns the container-specific identity (Runtime, Service) and metadata
	// (Container, Pod, Namespace). ok=false if the container is unknown to this runtime
	// or the runtime is currently unreachable. The engine overlays static env/node fields.
	Enrich(ctx context.Context, containerID string) (WorkloadIdentity, WorkloadMeta, bool)
	Close() error
}

// Engine is the runtime-agnostic resolver. Implements WorkloadResolver.
type Engine struct {
	env  string       // static WorkloadIdentity.Env (cloud provider), overlaid on every result
	meta WorkloadMeta // static Node/Region/Cluster, overlaid on every result

	mu        sync.RWMutex
	cache     map[uint32]ResolveResult // mnt_ns_id → resolved workload (the cache map)
	resolving sync.Map                 // mnt_ns_id → in-flight marker (the pending map, dedup)
	hostNsID  uint32                   // host mount namespace (host fast path)
	lookupSem chan struct{}            // caps concurrent metadata lookups

	clientsMu sync.Mutex
	clients   map[Runtime]RuntimeClient // metadata clients, created on first sight of a runtime
}

var _ WorkloadResolver = (*Engine)(nil)

// NewEngine builds an engine with the static environment metadata. Runtime clients are
// created lazily on first sight of a runtime's cgroup.
func NewEngine(env string, meta WorkloadMeta) *Engine {

	return &Engine{
		env:       env,
		meta:      meta,
		cache:     make(map[uint32]ResolveResult),
		lookupSem: make(chan struct{}, engineLookupWorkers),
		clients:   make(map[Runtime]RuntimeClient),
	}
}

// Start records the host mount namespace, then pre-warms the cache from /proc — same
// approach as the previous DockerResolver.buildCache/K8sResolver.buildInitialCache:
// scan every running process, read its cgroup, and resolve container namespaces before
// any event arrives. This is required because a container's *first* event can race an
// in-flight cgroup migration (e.g. a health-check exec: namespace-join is synchronous,
// but systemd cgroup-driver migration is an async D-Bus call) — an already-running
// process's cgroup has long since settled, so prewarm sidesteps that race entirely for
// anything running when the agent starts.
func (e *Engine) Start() error {
	if err := checkCgroupV2(); err != nil {
		return err
	}
	log.Printf("resolver engine: cgroup v2 (unified hierarchy) confirmed on /sys/fs/cgroup")
	e.hostNsID = getMntNsID(1)
	log.Printf("resolver engine: host namespace ID = %d (0 = detection failed, host fast path disabled)", e.hostNsID)
	e.seedSelfAsHost()
	e.prewarmFromProc()
	return nil
}

// cgroup2SuperMagic is CGROUP2_SUPER_MAGIC (linux/magic.h) — the f_type statfs(2)
// reports for the cgroup v2 unified hierarchy. To check by hand on a host:
//
//	$ stat -f -c "Type: %T, Magic: %t" /sys/fs/cgroup
//	Type: cgroup2fs, Magic: 63677270
const cgroup2SuperMagic = 0x63677270

// checkCgroupV2 verifies the host uses the cgroup v2 unified hierarchy, which every
// cgroup leaf this engine parses assumes (see docs/EXECVE-EVENT-DESIGN.md "Startup
// guard"). Fail fast, never remediate: a security agent must not modify host boot
// config (e.g. rewrite /etc/default/grub) — that's the operator's call, not ours.
func checkCgroupV2() error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &stat); err != nil {
		return fmt.Errorf("resolver engine: cannot stat /sys/fs/cgroup: %w", err)
	}
	if int64(stat.Type) != cgroup2SuperMagic {
		return fmt.Errorf("resolver engine: host is not running cgroup v2 (unified hierarchy) — " +
			"boot with systemd.unified_cgroup_hierarchy=1 and reboot, then restart the agent")
	}
	return nil
}

// seedSelfAsHost caches the agent's own mount namespace as RuntimeHost before any event
// arrives. Prevents the agent's own on-demand runtime-client subprocess calls (e.g.
// crictl, forked per newly-seen container) from resolving as a K8s/Docker container and
// self-triggering a container-management-tool detection (T1613) on itself. Mirrors the
// previous K8sResolver.buildInitialCache's selfNsID seeding.
func (e *Engine) seedSelfAsHost() {
	selfNsID := getMntNsID(os.Getpid())
	if selfNsID == 0 || selfNsID == e.hostNsID {
		return // already covered by the host fast path, or couldn't determine
	}
	e.store(selfNsID, e.result(StateResolved, WorkloadIdentity{Runtime: RuntimeHost, Service: HostProcessService}))
	log.Printf("resolver engine: seeded own namespace (%d) as host to prevent self-triggered alerts", selfNsID)
}

// prewarmFromProc scans /proc once and resolves every already-running container's
// namespace synchronously. Ambiguous or unreadable entries are left alone — prewarm
// only fills in cases it can already answer for sure; anything else falls through to
// the normal event-driven path.
func (e *Engine) prewarmFromProc() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("resolver engine: prewarm /proc scan failed: %v", err)
		return
	}

	seeded := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidStr := entry.Name()
		if pidStr[0] < '0' || pidStr[0] > '9' {
			continue // not a pid directory
		}
		pid64, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)

		nsID := getMntNsID(int(pid))
		if nsID == 0 || nsID == e.hostNsID {
			continue
		}
		e.mu.RLock()
		_, exists := e.cache[nsID]
		e.mu.RUnlock()
		if exists {
			continue // another pid in this namespace already resolved it this scan
		}

		leaf, ok := leafFromProcCgroup(pid)
		if !ok || leaf == "" {
			continue // can't tell; leave for the event-driven path to decide later
		}
		containerID, _ := containerIDFromCgroupLeaf(leaf)
		if containerID == "" {
			continue // not a container, or ambiguous — never seed Unknown from prewarm
		}

		if id, meta, ok := e.enrich(containerID); ok {
			id.Env = e.env
			meta.Node, meta.Region, meta.Cluster = e.meta.Node, e.meta.Region, e.meta.Cluster
			e.store(nsID, ResolveResult{Identity: id, Meta: meta, State: StateResolved})
			seeded++
		}
	}
	log.Printf("resolver engine: prewarm resolved %d container namespaces from /proc", seeded)
}

// EvictStale removes cache entries for namespaces that no longer have any live process
// — i.e. every process that was in them has exited (the container was destroyed).
// Neither previous resolver actually did this in practice (the old Docker resolver's
// eviction was written but never started; the K8s resolver had none at all), so a
// destroyed container's identity stuck around forever and could be handed to a later,
// unrelated namespace that reused the same ID. Call periodically; reuses the same
// /proc scan as prewarmFromProc so it works identically for docker and k8s.
func (e *Engine) EvictStale() {
	live := make(map[uint32]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("resolver engine: evictStale /proc scan failed: %v", err)
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidStr := entry.Name()
		if pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}
		pid64, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			continue
		}
		if nsID := getMntNsID(int(pid64)); nsID != 0 {
			live[nsID] = true
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	evicted := 0
	for ns := range e.cache {
		if !live[ns] {
			delete(e.cache, ns)
			evicted++
		}
	}
	if evicted > 0 {
		log.Printf("resolver engine: evicted %d stale cache entries (namespace no longer has a live process)", evicted)
	}
}

// resolvableEvent is the minimal surface the engine needs from any sensor event —
// implemented by every processor event (see processor.ResolveInfo). A new event type
// works with the engine by implementing this; the engine has no per-type switch.
type resolvableEvent interface {
	ResolveInfo() (mntNsID, pid uint32, cgroupLeaf string, hasCgroup bool)
}

// Resolve implements WorkloadResolver: pull the join key (mnt_ns_id) and dispatch hint
// (cgroup leaf) from the event via the interface, then resolve against the shared state.
func (e *Engine) Resolve(event interface{}) ResolveResult {
	ev, ok := event.(resolvableEvent)
	if !ok {
		return e.result(StateUnknown, WorkloadIdentity{Runtime: RuntimeUnknown})
	}
	mntNsID, pid, cgroupLeaf, hasCgroup := ev.ResolveInfo()

	// Host fast path — runtime-agnostic; catches direct-to-node processes (incl. SSH).
	if e.hostNsID != 0 && mntNsID == e.hostNsID {
		return e.result(StateResolved, WorkloadIdentity{Runtime: RuntimeHost, Service: HostProcessService})
	}

	// Cache — keyed by mnt_ns_id, present on every event.
	e.mu.RLock()
	cached, hit := e.cache[mntNsID]
	e.mu.RUnlock()
	if hit {
		return cached
	}

	// Events without a cgroup (net) resolve from the cache only — they never drive
	// resolution. Cache miss → pending; a later exec/file event resolves the namespace.
	if !hasCgroup {
		return e.result(StatePending, WorkloadIdentity{Runtime: RuntimeUnknown})
	}

	// One in-flight resolution per namespace (dedup).
	log.Printf("DEBUG: uncached event ns=%d ", mntNsID)

	if _, inflight := e.resolving.LoadOrStore(mntNsID, true); inflight {
		return e.result(StatePending, WorkloadIdentity{Runtime: RuntimeUnknown})
	}
	go e.asyncResolve(mntNsID, pid, cgroupLeaf)
	return e.result(StatePending, WorkloadIdentity{Runtime: RuntimeUnknown})
}

func (e *Engine) asyncResolve(mntNsID, pid uint32, cgroupLeaf string) {
	defer e.resolving.Delete(mntNsID)
	e.lookupSem <- struct{}{}
	defer func() { <-e.lookupSem }()
	log.Printf("DEBUG: asyncResolve ns=%d pid=%d cgroupLeaf=%s ", mntNsID, pid, cgroupLeaf)

	// Container ID + runtime: prefer the kernel-captured leaf (race-free, valid even
	// after the process exits); fall back to a procfs read only when the leaf is absent.
	containerID, rt := containerIDFromCgroupLeaf(cgroupLeaf)
	if containerID == "" && cgroupLeaf == "" {
		// BPF capture failed; try procfs once. Any failure — process exited, permission,
		// or anything else; we don't distinguish why — means nothing more can be learned
		// here. Bail without caching so a later event gets a fresh attempt.
		leaf, ok := leafFromProcCgroup(pid)
		if !ok || leaf == "" {
			return
		}
		cgroupLeaf = leaf // treat a successful procfs read identically to a kernel-captured leaf
		containerID, rt = containerIDFromCgroupLeaf(leaf)
	}

	if containerID == "" {
		// cgroupLeaf is guaranteed non-empty here (the only empty case already returned
		// above), so this is always "non-empty cgroup that didn't parse as a container."
		// Resolve() only calls asyncResolve after its host-fast-path check (mntNsID ==
		// hostNsID) has already failed, so this namespace is confirmed NOT the host —
		// yet its cgroup isn't a recognized container leaf either (e.g. a snap-confined
		// dockerd's own systemd unit). Cache it so repeated activity in this namespace
		// doesn't re-trigger resolution on every event. RuntimeUnknown, not Host: this
		// namespace is confirmed non-host, we just don't know what it is.
		log.Printf("DEBUG: asyncResolve ns=%d pid=%d cgroupLeaf=%q -> unparseable, caching Unknown", mntNsID, pid, cgroupLeaf)
		e.store(mntNsID, e.result(StateResolved, WorkloadIdentity{Runtime: RuntimeUnknown}))
		return
	}

	// Container → metadata via the runtime's client (lazy-connected). On success the
	// client fills container-specific fields; the engine overlays static env/node.
	if id, meta, ok := e.enrich(containerID); ok {
		id.Env = e.env
		meta.Node, meta.Region, meta.Cluster = e.meta.Node, e.meta.Region, e.meta.Cluster
		e.store(mntNsID, ResolveResult{Identity: id, Meta: meta, State: StateResolved})
		return
	}

	// No client yet, or lookup failed → keep the container visible with a short-ID name.
	// Detection still works (gating keys on mnt_ns_id + container id); only the name is
	// degraded until the runtime client connects.
	log.Printf("DEBUG: asyncResolve ns=%d containerID=%s ENRICH FAILED, falling back to short-id runtime=%s",
		mntNsID, containerID, rt)
	e.store(mntNsID, e.shortIDResult(rt, containerID))
}

// enrich tries every runtime's client until one recognizes the container. A container
// ID is unique to whichever runtime minted it, so querying the wrong client is a
// harmless miss — no need to gate on the cgroup leaf's guessed runtime (which is often
// unavailable anyway: the cgroupfs driver's raw-hex leaf carries no runtime prefix).
func (e *Engine) enrich(containerID string) (WorkloadIdentity, WorkloadMeta, bool) {
	for _, rt := range []Runtime{RuntimeDocker, RuntimeK8s} {
		c := e.clientFor(rt)
		if c == nil {
			continue
		}
		if id, meta, ok := c.Enrich(context.Background(), containerID); ok {
			return id, meta, true
		}
	}
	return WorkloadIdentity{}, WorkloadMeta{}, false
}

// clientFor returns the metadata client for a runtime, creating it on first use. Returns
// nil if the runtime has no client or is unreachable; the caller then uses a short-id
// label, and a later event retries the creation.
func (e *Engine) clientFor(rt Runtime) RuntimeClient {
	e.clientsMu.Lock()
	defer e.clientsMu.Unlock()
	if c, ok := e.clients[rt]; ok {
		return c
	}
	if c := newRuntimeClient(rt); c != nil {
		e.clients[rt] = c
		return c
	}
	return nil
}

// newRuntimeClient creates the metadata client for a runtime, or nil if it is unsupported
// or unreachable. A connect failure is not fatal: it logs and returns nil so the caller
// falls back to a short-id label, and a later event retries the creation.
func newRuntimeClient(rt Runtime) RuntimeClient {
	switch rt {
	case RuntimeDocker:
		c, err := newDockerClient()
		if err != nil {
			log.Printf("resolver engine: docker client unavailable: %v", err)
			return nil
		}
		return c
	case RuntimeK8s:
		c, err := newCriClient()
		if err != nil {
			log.Printf("resolver engine: cri client unavailable: %v", err)
			return nil
		}
		return c
	}
	return nil
}

func (e *Engine) store(mntNsID uint32, r ResolveResult) {
	e.mu.Lock()
	e.cache[mntNsID] = r
	e.mu.Unlock()
}

// result builds a ResolveResult from a container-agnostic identity, overlaying the
// static env + node/region/cluster metadata the engine holds.
func (e *Engine) result(state ResolveState, id WorkloadIdentity) ResolveResult {
	id.Env = e.env
	return ResolveResult{Identity: id, Meta: e.meta, State: state}
}

// shortIDResult labels an identified-but-unenriched container (no client yet, or lookup
// failed) with a short-id service name so it stays visible to detection. Runtime is
// passed through as-is, including RuntimeUnknown — we don't guess it. Meta.Container/Pod
// are populated with the short ID too, matching the old resolvers' fallback behavior.
func (e *Engine) shortIDResult(rt Runtime, containerID string) ResolveResult {
	short := containerID
	if len(short) > shortIDLen {
		short = short[:shortIDLen]
	}
	res := e.result(StateResolved, WorkloadIdentity{Runtime: rt, Service: "container-" + short})
	res.Meta.Container = short
	res.Meta.Pod = short
	return res
}

// leafFromProcCgroup reads the cgroup v2 leaf from /proc/<pid>/cgroup — the procfs
// fallback used only when the in-kernel leaf is absent (a rare BPF read failure). On v2
// the file is a single "0::/path" line; the leaf is its last path segment.
// leafFromProcCgroup reads the cgroup v2 leaf from /proc/<pid>/cgroup — the procfs
// fallback used only when the in-kernel leaf is absent (a rare BPF read failure). On v2
// the file is a single "0::/path" line; the leaf is its last path segment. ok is false
// on any read failure (process exited, permission, or anything else) — we don't
// distinguish why; there's nothing more to learn either way.
func leafFromProcCgroup(pid uint32) (leaf string, ok bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
	if err != nil {
		return "", false
	}
	line := strings.TrimSpace(string(data))
	if i := strings.LastIndexByte(line, ':'); i >= 0 {
		line = line[i+1:]
	}
	line = strings.Trim(line, "/")
	if i := strings.LastIndexByte(line, '/'); i >= 0 {
		return line[i+1:], true
	}
	return line, true
}

// Close releases all connected runtime clients.
func (e *Engine) Close() error {
	e.clientsMu.Lock()
	defer e.clientsMu.Unlock()
	for _, c := range e.clients {
		_ = c.Close()
	}
	return nil
}
