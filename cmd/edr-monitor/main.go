//go:build linux

package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/config"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg"
	"ebpf-edr-demo/pkg/alertsink"
	"ebpf-edr-demo/pkg/bpf"
	"ebpf-edr-demo/pkg/detector"
	"ebpf-edr-demo/pkg/pipeline"
	"ebpf-edr-demo/pkg/rules"
	"ebpf-edr-demo/pkg/workload"
)

const (
	pendingRetryInterval = 3 * time.Second
	pendingMaxRetries    = 20               // 20 × 3s = 60s max — covers K8s slow starts (image pull + init containers)
	pendingMaxAge        = 60 * time.Second // primary limiter; K8s pods can take 30–60s to appear in crictl

	rawChCap      = 65536 // kernel event burst buffer — absorbs deployment spikes (10,000-50,000 events/sec)
	enrichedChCap = 32768 // post-enrichment buffer
	alertChCap    = 8096  // alerts are rare, but may have many Low/Info telemetry

	// fileDedupWindow deduplicates file events from the same process within this window.
	// Why: multi-threaded processes trigger lsm/file_open once per thread (N threads = N syscalls).
	// But from detection perspective: file open happened once; threads share file descriptor & RAM.
	// Solution: keep only first occurrence within window; discard thread duplicates as noise.
	fileDedupWindow = time.Second

	cacheCleanUpWorkerInterval     = 5 * time.Minute
	debugResolveDetecCheckInterval = 100 * time.Microsecond

	// Graceful shutdown timings
	shutdownWaitInterval = 100 * time.Millisecond // time for goroutines to finish between channel closes
)

type fileDedupKey struct {
	Pid      uint32
	Comm     [pkg.TaskCommLen]byte    // matches kernel/opensnoop.h
	Filename [pkg.MaxFilenameLen]byte // matches kernel/opensnoop.h
}

const fileDedupShards = 32 // shard count: distributes lock contention across cores

type fileDedupShard struct {
	mu   sync.Mutex
	seen map[fileDedupKey]time.Time
}

var fileDedupShards_array [fileDedupShards]fileDedupShard

func init() {
	for i := range fileDedupShards_array {
		fileDedupShards_array[i].seen = make(map[fileDedupKey]time.Time)
	}
}

type pendingEntry struct {
	ev        pipeline.EnrichedEvent
	mntNsID   uint32
	firstSeen time.Time
	retries   int
}

func main() {
	// --runtime selects the workload resolver.
	// "k8s"    → K8sResolver (uses crictl, works with Docker/containerd/cri-o in K8s)
	// "docker" → DockerResolver (Docker daemon, standalone VMs or Compose)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	runtime := flag.String("runtime", defaultRuntime, validRuntimes)
	flag.Parse()

	// Load configuration from environment
	cfg := config.Load()

	// Alert Sink Initialization
	handler := initAlertHandler(cfg)
	defer handler.Close()

	loader, err := bpf.Load()
	if err != nil {
		log.Fatalf("loading eBPF programs: %v", err)
	}
	defer loader.Close()

	// Create runtime-specific resolver
	rt := workload.RuntimeDocker
	if *runtime == string(workload.RuntimeK8s) {
		rt = workload.RuntimeK8s
	}

	rulesDB, err := rules.LoadRulesForEnvironment(rulesFilePath)
	if err != nil {
		log.Fatalf("loading rules from YAML: %v", err)
	}

	// Layer 1: Scan /proc to discover safe infrastructure PIDs in this environment
	safeInfraPIDs := buildSafeInfraPIDs(rulesDB.InfrastructureFilters)
	log.Printf("Layer 1: Discovered %d safe infrastructure PIDs for fast-path filtering:", len(safeInfraPIDs))
	for pid, comm := range safeInfraPIDs {
		log.Printf("  PID %d: %s", pid, comm)
	}

	resolver := workload.NewResolver(rt)

	if err := resolver.Start(); err != nil {
		log.Fatalf("starting resolver: %v", err)
	}
	log.Printf("INFO: Resolver started with runtime=%s", rt)

	rawCh := make(chan pipeline.RawEvent, rawChCap)
	enrichedCh := make(chan pipeline.EnrichedEvent, enrichedChCap)
	alertCh := make(chan alert.Alert, alertChCap)

	var rawDropped atomic.Int64      // kernel events lost before enrichment
	var enrichedDropped atomic.Int64 // enriched events lost before detection
	var alertDropped atomic.Int64    // alerts lost before handler
	var unknownNs atomic.Int64       // pending events that expired without resolving
	var resolvedEvents atomic.Int64  // events successfully processed from rawCh → enrichedCh (temp debug)

	var pendingMu sync.Mutex
	pendingBuf := make(map[uint32][]pendingEntry)

	det := detector.NewYAMLDetectorWithRuntime(rulesDB, rt)
	det.SetInfrastructurePIDs(safeInfraPIDs) // Pass Layer 1 infrastructure PIDs for Layer 2 pre-filter
	responder := detector.NewResponder(nil)

	// Live process ancestry cache: pid → (ppid, execPath) captured from every exec
	// event, so parent identity stays readable after the parent exits.
	// The detector uses it for trusted-parent verification (isParentTrusted).
	// Design: docs/DESIGN-PROCESS-ANCESTRY-CACHE.md
	ancestry := detector.NewAncestryCache()
	ancestry.Bootstrap()
	det.SetAncestryCache(ancestry)

	// Load GKE-specific service CIDRs only if detected in GKE environment.
	// Avoids unnecessary metadata server calls on Docker/bare-metal.
	if string(rulesDB.Env) == envGCP {
		detector.AddGKEServiceCIDR()
	}

	// Start Readers
	startEBPFReaders(loader, rawCh, &rawDropped, &resolvedEvents)

	// 3. Enricher Loop
	startEnricherWorker(
		rawCh,
		enrichedCh,
		resolver,
		ancestry,
		safeInfraPIDs,
		&pendingMu,
		pendingBuf,
		&enrichedDropped,
		&resolvedEvents,
	)

	// 4. Retry Pending Events
	startPendingRetryWorker(
		resolver,
		enrichedCh,
		&pendingMu,
		pendingBuf,
		&enrichedDropped,
		&unknownNs,
	)

	// 5. Cache Cleanup
	startCacheCleanupWorker(ancestry)

	// 6 Detector & Responder Routing
	startDetectorAndResponder(enrichedCh, alertCh, det, responder, &alertDropped)

	// 7. Alert Handler Dispatcher
	startAlertHandlerWorker(alertCh, handler)

	// signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutdown: resolved=%d (dropped: raw=%d enriched=%d alert=%d unknown=%d)",
		resolvedEvents.Load(), rawDropped.Load(), enrichedDropped.Load(), alertDropped.Load(), unknownNs.Load())

	// Graceful shutdown: close channels in order (stops goroutines from top to bottom)
	close(rawCh)                     // Stop event readers → enricher stops receiving
	time.Sleep(shutdownWaitInterval) // Let enricher finish processing
	close(enrichedCh)                // Stop enricher → detector stops receiving
	time.Sleep(shutdownWaitInterval) // Let detector finish processing
	close(alertCh)                   // Stop handler

	// Close resources
	handler.Close()
	loader.Close()
}

// initAlertHandler: initializes and builds the complete slice of alert sinks
// based on the provided configuration topology.
func initAlertHandler(cfg *config.Config) *alert.Handler {
	var sinks []alert.Sink

	// File sink (always enabled)
	fileSink, err := alertsink.NewFileSink(cfg.AlertLogPath)
	if err != nil {
		log.Fatalf("opening alert log: %v", err)
	}
	sinks = append(sinks, fileSink)

	// Pub/Sub sink (if configured)
	if cfg.PubSubAddr != "" {
		pubsubSink, err := alertsink.NewRedisSink(cfg.PubSubAddr)
		if err != nil {
			log.Printf("pub/sub sink disabled: %v", err)
		} else {
			sinks = append(sinks, pubsubSink)
		}
	}

	// Database sink (if configured)
	if cfg.DatabaseURL != "" && cfg.DatabaseKey != "" {
		dbSink, err := alertsink.NewSupabaseSink(cfg.DatabaseURL, cfg.DatabaseKey)
		if err != nil {
			log.Printf("database sink disabled: %v", err)
		} else {
			sinks = append(sinks, dbSink)
		}
	}

	return alert.NewHandler(sinks)
}

type eventReader struct {
	source  pipeline.Source
	logName string
	read    func() ([]byte, error)
}

// startEBPFReaders orchestrates the initialization and background worker loops
// for reading raw samples from the eBPF ring buffers.
func startEBPFReaders(loader *bpf.Loader, rawCh chan<- pipeline.RawEvent, rawDropped *atomic.Int64, resolvedEvents *atomic.Int64) {
	readers := []eventReader{
		{pipeline.SourceExecsnoop, logNameProcess, func() ([]byte, error) {
			rec, err := loader.ProcessRd.Read()
			if err != nil {
				return nil, err
			}
			return rec.RawSample, nil
		}},
		{pipeline.SourceOpensnoop, logNameFile, func() ([]byte, error) {
			rec, err := loader.FileRd.Read()
			if err != nil {
				return nil, err
			}
			return rec.RawSample, nil
		}},
		{pipeline.SourceNetConnect, logNameNet, func() ([]byte, error) {
			rec, err := loader.NetRd.Read()
			if err != nil {
				return nil, err
			}
			return rec.RawSample, nil
		}},
	}

	for _, cfg := range readers {
		go startEventReader(cfg, rawCh, rawDropped, resolvedEvents)
	}
}

// startEnricherWorker runs the pipeline worker responsible for intercepting raw eBPF events,
// updating the ancestry cache, filtering out infrastructure spikes, deduping file access,
// and executing asynchronous workload metadata enrichment.
func startEnricherWorker(
	rawCh <-chan pipeline.RawEvent,
	enrichedCh chan<- pipeline.EnrichedEvent,
	resolver workload.WorkloadResolver,
	ancestry *detector.AncestryCache,
	safeInfraPIDs map[uint32]string,
	pendingMu *sync.Mutex,
	pendingBuf map[uint32][]pendingEntry,
	enrichedDropped *atomic.Int64,
	resolvedEvents *atomic.Int64,
) {
	go func() {
		for raw := range rawCh {
			// Record every exec into the ancestry cache BEFORE the Layer 1 skip,
			// so children of skipped infrastructure processes can still resolve
			// their parent identity later.
			if raw.Source == pipeline.SourceExecsnoop {
				pe := (*processor.ProcessEvent)(unsafe.Pointer(&raw.Data[0]))
				ancestry.Record(uint32(pe.Pid), uint32(pe.Ppid), processor.CString(pe.Comm[:]))
			}

			// Layer 1: Fast-path filtering (before enrichment/resolver)
			if shouldSkipLayer1(raw, safeInfraPIDs) {
				continue
			}

			ev := enrich(raw, resolver)
			if ev == nil {
				continue
			}

			if ev.Type == pipeline.FileEventType {
				// Dedup file events: multi-threaded processes trigger lsm/file_open once per thread.
				// Optimization: Use sharded locks (32 shards indexed by PID) to reduce contention on multi-core systems.
				key := fileDedupKey{
					Pid:      uint32(ev.File.Pid),
					Comm:     ev.File.Comm,
					Filename: ev.File.Filename,
				}
				shardIdx := uint32(ev.File.Pid) % fileDedupShards
				shard := &fileDedupShards_array[shardIdx]
				shard.mu.Lock()
				last, seen := shard.seen[key]
				if seen && time.Since(last) < fileDedupWindow {
					shard.mu.Unlock()
					continue
				}
				shard.seen[key] = time.Now()
				shard.mu.Unlock()
			}

			// Pending workload: resolver couldn't identify container yet (State=Pending).
			// Buffer event and retry later when resolver catches up (K8s pod startup lag).
			if ev.Workload.State == workload.StatePending {
				nsID := mntNsIDOf(*ev)
				pendingMu.Lock()
				pendingBuf[nsID] = append(pendingBuf[nsID], pendingEntry{
					ev: *ev, mntNsID: nsID, firstSeen: time.Now(),
				})
				pendingMu.Unlock()
				continue
			}

			select {
			case enrichedCh <- *ev:
				resolvedEvents.Add(1)
			default:
				n := enrichedDropped.Add(1)
				if n == 1 || n%100 == 0 {
					log.Printf("warning: enrichedCh full, %d enriched events dropped", n)
				}
			}
		}
	}()
}

// startPendingRetryWorker runs the background routine that retries namespace/workload
// resolution for buffered events whose state was initially Pending.
func startPendingRetryWorker(
	resolver workload.WorkloadResolver,
	enrichedCh chan<- pipeline.EnrichedEvent,
	pendingMu *sync.Mutex,
	pendingBuf map[uint32][]pendingEntry,
	enrichedDropped *atomic.Int64,
	unknownNs *atomic.Int64,
) {
	go func() {
		ticker := time.NewTicker(pendingRetryInterval)
		defer ticker.Stop()

		for range ticker.C {
			pendingMu.Lock()

			for nsID, entries := range pendingBuf {
				if len(entries) == 0 {
					delete(pendingBuf, nsID)
					continue
				}

				// Resolve using first event: all events in this nsID group share a namespace.
				// Pass the underlying *processor event — Resolve type-switches on those,
				// not on EnrichedEvent (the workload pkg can't import pipeline).
				res := resolver.Resolve(underlyingEvent(entries[0].ev))

				// Success: namespace resolved — apply resolution to all events in this group
				if res.State == workload.StateResolved {
					for _, e := range entries {
						ev := e.ev
						ev.Workload = res
						select {
						case enrichedCh <- ev:
						default:
							if n := enrichedDropped.Add(1); n == 1 || n%100 == 0 {
								log.Printf("warning: enrichedCh full, %d enriched events dropped", n)
							}
						}
					}
					delete(pendingBuf, nsID)
					continue
				}

				// Still unresolved: check if any entries have exceeded timeout/retry limits
				var remain []pendingEntry
				for _, e := range entries {
					ev := e.ev
					var pid int32
					switch ev.Type {
					case pipeline.ProcessEventType:
						pid = ev.Process.Pid
					case pipeline.FileEventType:
						pid = ev.File.Pid
					case pipeline.NetEventType:
						pid = ev.Net.Pid
					}

					if pid > 0 {
						// Check if process exists without sending signal
						if err := syscall.Kill(int(pid), 0); err != nil {
							// Process is dead: mark as unknown and send immediately
							ev.Workload.State = workload.StateUnknown
							unknownNs.Add(1)
							select {
							case enrichedCh <- ev:
							default:
								if n := enrichedDropped.Add(1); n == 1 || n%100 == 0 {
									log.Printf("warning: enrichedCh full, %d enriched events dropped", n)
								}
							}
							continue
						}
					}

					// Check absolute timeout (pendingMaxAge = 60s)
					expired := time.Since(e.firstSeen) > pendingMaxAge
					if !expired {
						e.retries++
						expired = e.retries >= pendingMaxRetries
					}

					if expired {
						ev.Workload.State = workload.StateUnknown
						unknownNs.Add(1)
						select {
						case enrichedCh <- ev:
						default:
							if n := enrichedDropped.Add(1); n == 1 || n%100 == 0 {
								log.Printf("warning: enrichedCh full, %d enriched events dropped", n)
							}
						}
					} else {
						remain = append(remain, e)
					}
				}

				if len(remain) == 0 {
					delete(pendingBuf, nsID)
				} else {
					pendingBuf[nsID] = remain
				}
			}

			pendingMu.Unlock()
		}
	}()
}

// startCacheCleanupWorker runs a background routine that periodically evicts
// dead or expired entries from the process ancestry cache.
func startCacheCleanupWorker(ancestry *detector.AncestryCache) {
	go func() {
		ticker := time.NewTicker(cacheCleanUpWorkerInterval)
		defer ticker.Stop()

		for range ticker.C {
			ancestry.Sweep()
		}
	}()
}

// startDetectorAndResponder runs the core pipeline processor that evaluates enriched events,
// tracks detection latency, applies inline mitigation responses, and handles alert signaling.
func startDetectorAndResponder(
	enrichedCh <-chan pipeline.EnrichedEvent,
	alertCh chan<- alert.Alert,
	det *detector.YAMLDetector,
	responder *detector.Responder,
	alertDropped *atomic.Int64,
) {
	go func() {
		for ev := range enrichedCh {
			detectStart := time.Now()
			a := det.Detect(ev)
			detectTime := time.Since(detectStart)
			if detectTime > debugResolveDetecCheckInterval {
				log.Printf("DEBUG: det.Detect took %v (slow detection)", detectTime)
			}

			if a == nil {
				continue
			}

			// Compute response BEFORE sending alert to avoid data race:
			// If we send alert first, then modify a.ResponseAction, handler goroutine
			// may read partial/stale data. Compute response action first, then send complete alert.
			action := detector.ResponseFor(a.Rule, a.Level)
			if action != alert.ActionNone {
				action = responder.Respond(a, action)
			}
			a.ResponseAction = action

			select {
			case alertCh <- *a:
			default:
				alertDropped.Add(1)
				log.Printf("ERROR: alertCh full, alert dropped: rule=%s level=%s comm=%s", a.Rule, a.Level, a.Comm)
			}
		}
	}()
}

// startAlertHandlerWorker consumes generated security alerts from the pipeline
// and dispatches them to all active logging and database sinks.
func startAlertHandlerWorker(alertCh <-chan alert.Alert, handler *alert.Handler) {
	go func() {
		for a := range alertCh {
			handler.Send(a)
		}
	}()
}

func enrich(raw pipeline.RawEvent, r workload.WorkloadResolver) *pipeline.EnrichedEvent {
	switch raw.Source {

	case pipeline.SourceExecsnoop:
		if len(raw.Data) < int(unsafe.Sizeof(processor.ProcessEvent{})) {
			log.Printf("enrich: execsnoop event too small: %d bytes", len(raw.Data))
			return nil
		}
		ev := (*processor.ProcessEvent)(unsafe.Pointer(&raw.Data[0]))
		enriched := &pipeline.EnrichedEvent{
			Type:      pipeline.ProcessEventType,
			Process:   ev,
			Timestamp: time.Now(),
		}
		start := time.Now()
		enriched.Workload = r.Resolve(ev)
		resolveTime := time.Since(start)
		if resolveTime > debugResolveDetecCheckInterval {
			log.Printf("DEBUG: resolve process took %v", resolveTime)
		}

		return enriched

	case pipeline.SourceOpensnoop:
		if len(raw.Data) < int(unsafe.Sizeof(processor.FileEvent{})) {
			log.Printf("enrich: opensnoop event too small: %d bytes", len(raw.Data))
			return nil
		}
		ev := (*processor.FileEvent)(unsafe.Pointer(&raw.Data[0]))
		enriched := &pipeline.EnrichedEvent{
			Type:      pipeline.FileEventType,
			File:      ev,
			Timestamp: time.Now(),
		}
		start := time.Now()
		enriched.Workload = r.Resolve(ev)
		resolveTime := time.Since(start)
		if resolveTime > debugResolveDetecCheckInterval {
			log.Printf("DEBUG: resolve file took %v", resolveTime)
		}
		return enriched

	case pipeline.SourceNetConnect:
		if len(raw.Data) < int(unsafe.Sizeof(processor.NetEvent{})) {
			log.Printf("enrich: lsm-connect event too small: %d bytes", len(raw.Data))
			return nil
		}
		ev := (*processor.NetEvent)(unsafe.Pointer(&raw.Data[0]))
		enriched := &pipeline.EnrichedEvent{
			Type:      pipeline.NetEventType,
			Net:       ev,
			Timestamp: time.Now(),
		}
		start := time.Now()
		enriched.Workload = r.Resolve(ev)
		resolveTime := time.Since(start)
		if resolveTime > debugResolveDetecCheckInterval {
			log.Printf("DEBUG: resolve net took %v", resolveTime)
		}

		return enriched
	}

	return nil
}

// buildSafeInfraPIDs scans /proc at startup to find actual infrastructure process PIDs
// Returns map[pid]comm of all safe infrastructure processes in this environment
func buildSafeInfraPIDs(infraFilters rules.InfrastructureFilters) map[uint32]string {
	safeProcs := make(map[uint32]string)

	// Pre-process categories into dedicated lookup maps to preserve boundaries
	type processedCategory struct {
		allowedComms map[string]bool
		prefixes     []string
		isContainer  bool // Flag to toggle cgroup namespace checking
	}

	// Helper to build truncated maps
	buildCat := func(comms []string, prefixes []string, isContainer bool) processedCategory {
		m := make(map[string]bool)
		for _, c := range comms {
			if len(c) > 15 {
				c = c[:15]
			}
			m[c] = true
		}
		return processedCategory{allowedComms: m, prefixes: prefixes, isContainer: isContainer}
	}

	pcats := []processedCategory{
		buildCat(infraFilters.HostSystem.AllowedComms, infraFilters.HostSystem.TrustedPrefixes, false),
		buildCat(infraFilters.DockerRuntime.AllowedComms, infraFilters.DockerRuntime.TrustedPrefixes, true),
		buildCat(infraFilters.Kubernetes.AllowedComms, infraFilters.Kubernetes.TrustedPrefixes, true),
		buildCat(infraFilters.Agent.AllowedComms, infraFilters.Agent.TrustedPrefixes, false),
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("Layer 1: failed to scan /proc: %v", err)
		return safeProcs
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			continue
		}

		commData, err := os.ReadFile(filepath.Join("/proc", pidStr, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commData))

		realPath, err := os.Readlink(filepath.Join("/proc", pidStr, "exe"))
		if err != nil {
			continue
		}

		// Validate strictly within category bounds
		for _, pcat := range pcats {
			if !pcat.allowedComms[comm] {
				continue
			}

			// Path validation: directory prefixes (ending /) use HasPrefix; exact binaries use exact match
			if !pathAllowed(realPath, pcat.prefixes) {
				continue
			}

			// Apply complex validation contextually for container/k8s daemons
			if pcat.isContainer && isIsolatedWorkload(pidStr) {
				continue // Reject if it belongs to a tenant cgroup/namespace
			}

			safeProcs[uint32(pid)] = comm
			break // Handled by this category, move to next PID
		}
	}

	return safeProcs
}

func pathAllowed(realPath string, patterns []string) bool {
	for _, pattern := range patterns {
		if realPath == pattern {
			return true
		} else if strings.HasSuffix(pattern, "/") {
			if strings.HasPrefix(realPath, pattern) {
				return true
			}
		}
	}
	return false
}

// isIsolatedWorkload checks if a process belongs to a container/pod namespace
// Returns true if process is isolated (inside a container), false if it's host infrastructure
func isIsolatedWorkload(pidStr string) bool {
	data, err := os.ReadFile(filepath.Join("/proc", pidStr, "cgroup"))
	if err != nil {
		return true // Treat errors as untrusted
	}
	content := string(data)
	return strings.Contains(content, "docker-") || strings.Contains(content, "kubepods")
}

// extractPPidFromStatus parses ppid from /proc/[pid]/status content
func extractPPidFromStatus(status string) uint32 {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ppid, _ := strconv.ParseUint(parts[1], 10, 32)
				return uint32(ppid)
			}
		}
	}
	return 0
}

// shouldSkipLayer1 checks if event should be skipped by Layer 1 fast-path filter
// eBPF kernel code already validates data size, so no length checks needed
// Returns true if event matches Layer 1 filters (ppid==0 or pid in safe list)
// Returns false if event should be processed (enrich and detect)
func shouldSkipLayer1(raw pipeline.RawEvent, safeInfraPIDs map[uint32]string) bool {
	var pid, ppid uint32

	switch raw.Source {
	case pipeline.SourceExecsnoop:
		ev := (*processor.ProcessEvent)(unsafe.Pointer(&raw.Data[0]))
		pid = uint32(ev.Pid)
		ppid = uint32(ev.Ppid)

	case pipeline.SourceOpensnoop:
		ev := (*processor.FileEvent)(unsafe.Pointer(&raw.Data[0]))
		pid = uint32(ev.Pid)
		ppid = uint32(ev.Ppid)

	case pipeline.SourceNetConnect:
		ev := (*processor.NetEvent)(unsafe.Pointer(&raw.Data[0]))
		pid = uint32(ev.Pid)
		ppid = uint32(ev.Ppid)

	default:
		return false
	}

	// Layer 1 filters
	if ppid == 0 {
		return true // Kernel thread
	}

	if _, isSafe := safeInfraPIDs[pid]; isSafe {
		return true // Known safe infrastructure process
	}

	return false // Process normally (fall through to Layer 2)
}

func startEventReader(cfg struct {
	source  pipeline.Source
	logName string
	read    func() ([]byte, error)
}, rawCh chan<- pipeline.RawEvent, rawDropped *atomic.Int64, resolvedEvents *atomic.Int64) {
	var eventCount atomic.Int64
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// log the number of events and resolved events in last 10s for debugging
	var prevResolvedEvents int64
	go func() {
		for range ticker.C {
			count := eventCount.Load()
			currentResolved := resolvedEvents.Load()
			resolvedDelta := currentResolved - prevResolvedEvents
			prevResolvedEvents = currentResolved
			log.Printf("DEBUG: %s produced %d events, resolved=%d in last 10s", cfg.logName, count, resolvedDelta)
			eventCount.Store(0)
		}
	}()

	for {
		data, err := cfg.read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Printf("%s reader error (restarting): %v", cfg.logName, err)
			time.Sleep(time.Second)
			continue
		}
		eventCount.Add(1)

		select {
		case rawCh <- pipeline.RawEvent{Source: cfg.source, Data: append([]byte(nil), data...)}:
		default:
			if n := rawDropped.Add(1); n == 1 || n%100 == 0 {
				log.Printf("warning: rawCh full, %d kernel events dropped", n)
			}
		}
	}
}

// underlyingEvent returns the raw *processor event carried by an EnrichedEvent.
// WorkloadResolver.Resolve type-switches on the processor structs (the workload
// package cannot import pipeline — EnrichedEvent.Workload would be a circular import),
// so callers must hand it the underlying event, not the EnrichedEvent wrapper.
func underlyingEvent(ev pipeline.EnrichedEvent) interface{} {
	switch ev.Type {
	case pipeline.ProcessEventType:
		return ev.Process
	case pipeline.FileEventType:
		return ev.File
	case pipeline.NetEventType:
		return ev.Net
	}
	return nil
}

func mntNsIDOf(ev pipeline.EnrichedEvent) uint32 {
	switch ev.Type {
	case pipeline.ProcessEventType:
		return ev.Process.MntNsId
	case pipeline.FileEventType:
		return uint32(ev.File.MntNsId)
	case pipeline.NetEventType:
		return uint32(ev.Net.MntNsId)
	}
	return 0
}
