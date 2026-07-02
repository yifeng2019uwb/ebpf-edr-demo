//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/config"
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

	rawChCap      = 4096 // kernel event burst buffer
	enrichedChCap = 4096 // post-enrichment buffer
	alertChCap    = 64   // alerts are rare; small buffer is fine

	// fileDedupWindow deduplicates file events from the same process within this window.
	// Why: multi-threaded processes trigger lsm/file_open once per thread (N threads = N syscalls).
	// But from detection perspective: file open happened once; threads share file descriptor & RAM.
	// Solution: keep only first occurrence within window; discard thread duplicates as noise.
	fileDedupWindow = time.Second

	// Graceful shutdown timings
	shutdownWaitInterval = 100 * time.Millisecond // time for goroutines to finish between channel closes
)

var (
	fileDedupMu   sync.Mutex
	fileDedupSeen = map[string]time.Time{}
)

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

	// Create alert sinks based on configuration
	var sinks []alert.Sink

	// File sink (always enabled)
	fileSink, err := alertsink.NewFileSink(cfg.AlertLogPath)
	if err != nil {
		log.Fatalf("opening alert log: %v", err)
	}
	sinks = append(sinks, fileSink)

	// Pub/Sub sink (if configured)
	// Currently supports Redis, extensible to other pub/sub systems
	if cfg.PubSubAddr != "" {
		pubsubSink, err := alertsink.NewRedisSink(cfg.PubSubAddr)
		if err != nil {
			log.Printf("pub/sub sink disabled: %v", err)
		} else {
			sinks = append(sinks, pubsubSink)
		}
	}

	// Database sink (if configured)
	// Currently supports Supabase, extensible to other databases
	if cfg.DatabaseURL != "" && cfg.DatabaseKey != "" {
		dbSink, err := alertsink.NewSupabaseSink(cfg.DatabaseURL, cfg.DatabaseKey)
		if err != nil {
			log.Printf("database sink disabled: %v", err)
		} else {
			sinks = append(sinks, dbSink)
		}
	}

	handler := alert.NewHandler(sinks)
	defer handler.Close()

	rt := workload.RuntimeDocker
	if *runtime == string(workload.RuntimeK8s) {
		rt = workload.RuntimeK8s
	}
	resolver := workload.NewResolver(rt)
	if err := resolver.Start(); err != nil {
		log.Fatalf("starting resolver: %v", err)
	}

	loader, err := bpf.Load()
	if err != nil {
		log.Fatalf("loading eBPF programs: %v", err)
	}
	defer loader.Close()

	rulesDB, err := rules.LoadRulesForEnvironment(rulesFilePath)
	if err != nil {
		log.Fatalf("loading rules from YAML: %v", err)
	}

	rawCh := make(chan pipeline.RawEvent, rawChCap)
	enrichedCh := make(chan pipeline.EnrichedEvent, enrichedChCap)
	alertCh := make(chan alert.Alert, alertChCap)

	var rawDropped atomic.Int64      // kernel events lost before enrichment
	var enrichedDropped atomic.Int64 // enriched events lost before detection
	var alertDropped atomic.Int64    // alerts lost before handler
	var unknownNs atomic.Int64       // pending events that expired without resolving

	var pendingMu sync.Mutex
	pendingBuf := make(map[uint32][]pendingEntry)

	det := detector.NewYAMLDetectorWithEnv(rulesDB, string(rulesDB.Env))
	responder := detector.NewResponder(nil)

	// Load GKE-specific service CIDRs only if detected in GKE environment.
	// Avoids unnecessary metadata server calls on Docker/bare-metal.
	if string(rulesDB.Env) == envGCP {
		detector.AddGKEServiceCIDR()
	}

	// Producers: start readers for each eBPF event source
	type eventReader struct {
		source  pipeline.Source
		logName string
		read    func() ([]byte, error)
	}

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
		go startEventReader(cfg, rawCh, &rawDropped)
	}

	// Enricher
	go func() {
		for raw := range rawCh {
			ev := enrich(raw, resolver)
			if ev == nil {
				continue
			}

			if ev.Type == pipeline.ProcessEventType {
				if processor.CString(ev.Process.Comm[:]) == "pause" {
					continue
				}
			}

			if ev.Type == pipeline.FileEventType {
				// Dedup file events: multi-threaded processes trigger lsm/file_open once per thread.
				// From kernel's perspective: N threads = N syscalls = N hook firings.
				// From detection's perspective: file open happened once; N threads share FD and RAM.
				// Keep only first within fileDedupWindow (1s); rest are noise.
				key := fmt.Sprintf("%s:%d:%s", processor.CString(ev.File.Comm[:]), ev.File.Pid, processor.CString(ev.File.Filename[:]))
				fileDedupMu.Lock()
				last, seen := fileDedupSeen[key]
				if seen && time.Since(last) < fileDedupWindow {
					fileDedupMu.Unlock()
					continue
				}
				fileDedupSeen[key] = time.Now()
				fileDedupMu.Unlock()
			}

			// Pending workload: resolver couldn't identify container yet (State=Pending).
			// Buffer event and retry later when resolver catches up (K8s pod startup lag).
			// Note: Dedup applied to file events only (multi-thread noise).
			// Pending events (any type) skip dedup for now — if duplicates matter in production,
			// create shared dedup func and apply to all pending types.
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
			default:
				n := enrichedDropped.Add(1)
				if n == 1 || n%100 == 0 {
					log.Printf("warning: enrichedCh full, %d enriched events dropped", n)
				}
			}
		}
	}()

	// Retry pending
	go func() {
		ticker := time.NewTicker(pendingRetryInterval)
		defer ticker.Stop()

		for range ticker.C {
			pendingMu.Lock()

			for nsID, entries := range pendingBuf {
				// pid=0: original PID is gone by retry time; resolve by namespace only.
				res := resolver.Resolve(nsID, 0)

				// resolved
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

				// still pending
				var remain []pendingEntry
				for _, e := range entries {
					expired := time.Since(e.firstSeen) > pendingMaxAge
					if !expired {
						e.retries++
						expired = e.retries >= pendingMaxRetries
					}
					if expired {
						ev := e.ev
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

	// File dedup cache cleanup — evict entries older than 2× the dedup window
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-fileDedupWindow * 2)
			fileDedupMu.Lock()
			for k, t := range fileDedupSeen {
				if t.Before(cutoff) {
					delete(fileDedupSeen, k)
				}
			}
			fileDedupMu.Unlock()
		}
	}()

	// Detector
	go func() {
		for ev := range enrichedCh {
			a := det.Detect(ev)
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

	// Handler
	go func() {
		for a := range alertCh {
			handler.Send(a)
		}
	}()

	// signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutdown: rawDropped=%d enrichedDropped=%d alertDropped=%d unknownNs=%d",
		rawDropped.Load(), enrichedDropped.Load(), alertDropped.Load(), unknownNs.Load())

	// Graceful shutdown: close channels in order (stops goroutines from top to bottom)
	close(rawCh)       // Stop event readers → enricher stops receiving
	time.Sleep(shutdownWaitInterval)  // Let enricher finish processing
	close(enrichedCh)  // Stop enricher → detector stops receiving
	time.Sleep(shutdownWaitInterval)  // Let detector finish processing
	close(alertCh)     // Stop handler

	// Close resources
	handler.Close()
	loader.Close()
}

func enrich(raw pipeline.RawEvent, r workload.WorkloadResolver) *pipeline.EnrichedEvent {
	switch raw.Source {

	case pipeline.SourceExecsnoop:
		var ev processor.ProcessEvent
		// go standard library using binary.LittleEndian in encoding/binary
		if err := binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev); err != nil {
			log.Printf("enrich: bad execsnoop event: %v", err)
			return nil
		}
		res := r.Resolve(ev.MntNsId, uint32(ev.Pid))

		return &pipeline.EnrichedEvent{
			Type:      pipeline.ProcessEventType,
			Process:   &ev,
			Workload:  res,
			Timestamp: time.Now(),
		}

	case pipeline.SourceOpensnoop:
		var ev processor.FileEvent
		if err := binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev); err != nil {
			log.Printf("enrich: bad opensnoop event: %v", err)
			return nil
		}
		res := r.Resolve(uint32(ev.MntNsId), uint32(ev.Pid))
		return &pipeline.EnrichedEvent{
			Type:      pipeline.FileEventType,
			File:      &ev,
			Workload:  res,
			Timestamp: time.Now(),
		}

	case pipeline.SourceNetConnect:
		var ev processor.NetEvent
		if err := binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev); err != nil {
			log.Printf("enrich: bad lsm-connect event: %v", err)
			return nil
		}
		res := r.Resolve(uint32(ev.MntNsId), uint32(ev.Pid))

		return &pipeline.EnrichedEvent{
			Type:      pipeline.NetEventType,
			Net:       &ev,
			Workload:  res,
			Timestamp: time.Now(),
		}
	}

	return nil
}

func startEventReader(cfg struct {
	source  pipeline.Source
	logName string
	read    func() ([]byte, error)
}, rawCh chan<- pipeline.RawEvent, rawDropped *atomic.Int64) {
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
