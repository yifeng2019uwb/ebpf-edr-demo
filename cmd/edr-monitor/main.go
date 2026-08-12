//go:build linux

package main

import (
	"errors"
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
	"ebpf-edr-demo/internal/dedup"
	"ebpf-edr-demo/internal/processor"
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

	// fileDedupWindow collapses repeated opens of the same file by the same process
	// within this window (internal/dedup explains why).
	fileDedupWindow = time.Second

	// fileDedupSweepInterval evicts expired dedup entries. Kept near fileDedupWindow:
	// entries older than the window can never suppress anything again, so a longer
	// interval only raises how many dead entries are held at once.
	fileDedupSweepInterval = 10 * time.Second

	cacheCleanUpWorkerInterval = 5 * time.Minute

	// Graceful shutdown timings
	shutdownWaitInterval = 100 * time.Millisecond // drain time between pipeline stages
)

type pendingEntry struct {
	ev        pipeline.EnrichedEvent
	mntNsID   uint32
	firstSeen time.Time
	retries   int
}

func main() {
	// Load configuration from environment
	cfg := config.Load()

	// Alert Sink Initialization. Both the handler and the loader are closed explicitly
	// in the shutdown sequence at the end of main, which has to order them against the
	// pipeline goroutines — so no defer here (a defer would close them a second time,
	// and log.Fatalf below skips defers anyway).
	handler := initAlertHandler(cfg)

	loader, err := bpf.Load()
	if err != nil {
		log.Fatalf("loading eBPF programs: %v", err)
	}

	// Create the runtime-agnostic resolver engine (multi-runtime: docker + k8s/cri,
	// clients created lazily on first sight of a runtime's cgroup).
	env := rules.DetectEnvironment()
	node, err := os.Hostname()
	if err != nil {
		log.Printf("workload: os.Hostname() failed: %v — node field will be empty in alerts", err)
	}
	meta := workload.WorkloadMeta{
		Node:    node,
		Region:  os.Getenv(config.EnvRegion),
		Cluster: os.Getenv(config.EnvClusterName),
	}
	engine := workload.NewEngine(string(env), meta)
	if err := engine.Start(); err != nil {
		log.Fatalf("starting resolver engine: %v", err)
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

	rawCh := make(chan pipeline.RawEvent, rawChCap)
	enrichedCh := make(chan pipeline.EnrichedEvent, enrichedChCap)
	alertCh := make(chan alert.Alert, alertChCap)

	var rawDropped atomic.Int64      // kernel events lost before enrichment
	var enrichedDropped atomic.Int64 // enriched events lost before detection
	var alertDropped atomic.Int64    // alerts lost before handler
	var unknownNs atomic.Int64       // debug - pending events that expired without resolving
	var resolvedEvents atomic.Int64  // debug - events successfully processed from rawCh → enrichedCh (temp debug)

	var pendingMu sync.Mutex
	pendingBuf := make(map[uint32][]pendingEntry)

	// d.runtime is currently unused inside the detector (no rule reads it); with the
	// multi-runtime engine there is no single runtime to report, so pass Unknown.
	det := detector.NewYAMLDetectorWithRuntime(rulesDB, workload.RuntimeUnknown)
	det.SetInfrastructurePIDs(safeInfraPIDs) // Pass Layer 1 infrastructure PIDs for Layer 2 pre-filter
	responder := detector.NewResponder(nil)

	// Live process ancestry cache: pid → (ppid, execPath) captured from every exec
	// event, so parent identity stays readable after the parent exits.
	// The detector uses it for trusted-parent verification (isParentTrusted).
	// Design: docs/DESIGN-PROCESS-ANCESTRY-CACHE.md
	ancestry := detector.NewAncestryCache()
	ancestry.Bootstrap()
	det.SetAncestryCache(ancestry)

	fileDedup := dedup.New(fileDedupWindow)

	// Start Readers
	readersDone := startEBPFReaders(loader, rawCh, &rawDropped)

	// 3. Enricher Loop
	startEnricherWorker(
		rawCh,
		enrichedCh,
		engine,
		ancestry,
		safeInfraPIDs,
		&pendingMu,
		pendingBuf,
		&enrichedDropped,
		&resolvedEvents,
		fileDedup,
	)

	// 4. Retry Pending Events
	startPendingRetryWorker(
		engine,
		enrichedCh,
		&pendingMu,
		pendingBuf,
		&enrichedDropped,
		&unknownNs,
	)

	// 5. Cache Cleanup
	startCacheCleanupWorker(ancestry, engine)
	startFileDedupSweeper(fileDedup)

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

	// Graceful shutdown, in dependency order. Closing a channel while a producer is
	// still sending panics, so each stage stops its producers before closing:
	//
	//  1. Close the loader — the ring-buffer reads fail with os.ErrClosed and every
	//     reader goroutine returns. Without this, readers keep sending into rawCh.
	//  2. Wait for the readers to actually exit, then close rawCh. The enricher drains
	//     what is buffered and leaves its range loop.
	//  3. Give the enricher → detector → handler stages time to drain.
	//
	// enrichedCh and alertCh are deliberately left open: their producers are still
	// running during the drain, so closing them would reintroduce the same panic, and
	// nothing waits on them — the process is exiting. This makes the drain best-effort;
	// events still in flight past the drain window are lost rather than flushed.
	loader.Close()
	readersDone.Wait()
	close(rawCh)
	time.Sleep(shutdownWaitInterval) // enricher → detector
	time.Sleep(shutdownWaitInterval) // detector → alert handler

	handler.Close()
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
// for reading raw samples from the eBPF ring buffers. The returned WaitGroup
// completes once every reader has stopped, which shutdown waits on before closing
// rawCh — closing it while a reader is still sending would panic.
func startEBPFReaders(loader *bpf.Loader, rawCh chan<- pipeline.RawEvent, rawDropped *atomic.Int64) *sync.WaitGroup {
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

	var wg sync.WaitGroup
	for _, cfg := range readers {
		wg.Add(1)
		go func(cfg eventReader) {
			defer wg.Done()
			startEventReader(cfg, rawCh, rawDropped)
		}(cfg)
	}
	return &wg
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
	fileDedup *dedup.Cache,
) {
	go func() {
		for raw := range rawCh {
			// Record every exec into the ancestry cache BEFORE the Layer 1 skip,
			// so children of skipped infrastructure processes can still resolve
			// their parent identity later.
			if raw.Source == pipeline.SourceExecsnoop {
				pe := (*processor.ProcessEvent)(unsafe.Pointer(&raw.Data[0]))
				ancestry.Record(uint32(pe.Pid), uint32(pe.Ppid), processor.CString(pe.ExecPath[:]))
			}

			// Layer 1: Fast-path filtering (before enrichment/resolver)
			if shouldSkipLayer1(raw, safeInfraPIDs) {
				continue
			}

			ev := enrich(raw, resolver)
			if ev == nil {
				continue
			}

			// runc:[…] container-init events skip dedup: runc reads /etc/passwd +
			// /etc/group for user lookup and then execs into the target binary under the
			// SAME pid, so recording them would dedup-shadow the target's own first read
			// of those files (T1082 would miss `cat /etc/passwd`). They are
			// detector-whitelisted anyway (whitelisted_file_access_procs), so skipping
			// dedup for them costs nothing.
			if ev.Type == pipeline.FileEventType &&
				!strings.HasPrefix(processor.CString(ev.File.Comm[:]), "runc:[") {
				if fileDedup.Seen(uint32(ev.File.Pid), processor.CString(ev.File.Filename[:]), time.Now()) {
					continue
				}
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

// startFileDedupSweeper evicts expired entries from the file-dedup cache. Kept on its
// own short ticker rather than folded into startCacheCleanupWorker: dedup entries stop
// being useful after fileDedupWindow (1s), so sweeping them on the 5-minute cache
// interval would retain five minutes of dead keys — millions of them under load.
func startFileDedupSweeper(fileDedup *dedup.Cache) {
	go func() {
		ticker := time.NewTicker(fileDedupSweepInterval)
		defer ticker.Stop()

		for range ticker.C {
			fileDedup.Sweep(time.Now())
		}
	}()
}

// startCacheCleanupWorker runs a background routine that periodically evicts
// dead or expired entries from the process ancestry cache and the resolver's
// workload cache (destroyed containers whose namespace no longer has a live process).
func startCacheCleanupWorker(ancestry *detector.AncestryCache, engine *workload.Engine) {
	go func() {
		ticker := time.NewTicker(cacheCleanUpWorkerInterval)
		defer ticker.Stop()

		for range ticker.C {
			ancestry.Sweep()
			engine.EvictStale()
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
			a := det.Detect(ev)
			if a == nil {
				continue
			}
			// Fired alerts are logged by the file sink (pkg/alertsink/file_sink.go),
			// which writes the same line to stdout and to the alert log.

			// Execute response BEFORE sending alert to avoid data race:
			// If we send alert first, then modify a.ResponseAction, handler goroutine
			// may read partial/stale data. The detector set a.ResponseAction to the
			// fired rule's response: (rules/*.yaml); replace it with the action the
			// responder actually executed, then send the complete alert.
			if a.ResponseAction != alert.ActionNone {
				a.ResponseAction = responder.Respond(a, a.ResponseAction)
			}

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

// enrich maps a raw record onto its event struct and resolves its workload.
// No length check: each sensor reserves exactly sizeof(struct) and the ringbuf returns
// a sample of exactly that length, so the only way it could be short is a drift between
// kernel/event.h and internal/processor — a build problem, not a runtime one.
func enrich(raw pipeline.RawEvent, r workload.WorkloadResolver) *pipeline.EnrichedEvent {
	switch raw.Source {

	case pipeline.SourceExecsnoop:
		ev := (*processor.ProcessEvent)(unsafe.Pointer(&raw.Data[0]))
		enriched := &pipeline.EnrichedEvent{
			Type:      pipeline.ProcessEventType,
			Process:   ev,
			Timestamp: time.Now(),
		}
		enriched.Workload = r.Resolve(ev)
		return enriched

	case pipeline.SourceOpensnoop:
		ev := (*processor.FileEvent)(unsafe.Pointer(&raw.Data[0]))
		enriched := &pipeline.EnrichedEvent{
			Type:      pipeline.FileEventType,
			File:      ev,
			Timestamp: time.Now(),
		}
		enriched.Workload = r.Resolve(ev)
		return enriched

	case pipeline.SourceNetConnect:
		ev := (*processor.NetEvent)(unsafe.Pointer(&raw.Data[0]))
		enriched := &pipeline.EnrichedEvent{
			Type:      pipeline.NetEventType,
			Net:       ev,
			Timestamp: time.Now(),
		}
		enriched.Workload = r.Resolve(ev)
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

func startEventReader(cfg eventReader, rawCh chan<- pipeline.RawEvent, rawDropped *atomic.Int64) {
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
