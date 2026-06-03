package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/bpf"
	"ebpf-edr-demo/pkg/detector"
	"ebpf-edr-demo/pkg/pipeline"
	"ebpf-edr-demo/pkg/workload"
)

const (
	pendingRetryInterval = 3 * time.Second
	pendingMaxRetries    = 20              // 20 × 3s = 60s max — covers K8s slow starts (image pull + init containers)
	pendingMaxAge        = 60 * time.Second // primary limiter; K8s pods can take 30–60s to appear in crictl

	rawChCap      = 4096 // kernel event burst buffer
	enrichedChCap = 4096 // post-enrichment buffer
	alertChCap    = 64   // alerts are rare; small buffer is fine
)

type pendingEntry struct {
	ev        pipeline.EnrichedEvent
	mntNsID   uint32
	firstSeen time.Time
	retries   int
}

func main() {
	// --runtime selects the workload resolver.
	// "k8s"    → K8sResolver (uses crictl, reads kubepods cgroup paths)
	// "docker" → DockerResolver (uses docker ps, reads /docker/ cgroup paths)
	// "auto"   → currently falls through to DockerResolver (default case in NewResolver).
	// TODO: implement auto-detection — check if crictl or kubepods cgroup exists,
	//       pick k8s or docker accordingly. Any unrecognized value also falls to docker.
	runtime := flag.String("runtime", "auto", "docker | k8s")
	flag.Parse()

	handler, err := alert.NewHandler()
	if err != nil {
		log.Fatalf("opening alert log: %v", err)
	}
	defer handler.Close()

	resolver := workload.NewResolver(*runtime)
	if err := resolver.Start(); err != nil {
		log.Fatalf("starting resolver: %v", err)
	}

	loader, err := bpf.Load()
	if err != nil {
		log.Fatalf("loading eBPF programs: %v", err)
	}
	defer loader.Close()

	rawCh := make(chan pipeline.RawEvent, rawChCap)
	enrichedCh := make(chan pipeline.EnrichedEvent, enrichedChCap)
	alertCh := make(chan alert.Alert, alertChCap)

	var rawDropped atomic.Int64      // kernel events lost before enrichment
	var enrichedDropped atomic.Int64 // enriched events lost before detection
	var alertDropped atomic.Int64    // alerts lost before handler
	var unknownNs atomic.Int64       // pending events that expired without resolving

	var pendingMu sync.Mutex
	pendingBuf := make(map[uint32][]pendingEntry)

	det := detector.NewRuleDetector()

	// Producers
	go func() {
		for {
			rec, err := loader.ProcessRd.Read()
			if err != nil {
				return
			}
			select {
			case rawCh <- pipeline.RawEvent{Source: "execsnoop", Data: append([]byte(nil), rec.RawSample...)}:
			default:
				if n := rawDropped.Add(1); n == 1 || n%100 == 0 {
					log.Printf("warning: rawCh full, %d kernel events dropped", n)
				}
			}
		}
	}()
	go func() {
		for {
			rec, err := loader.FileRd.Read()
			if err != nil {
				return
			}
			select {
			case rawCh <- pipeline.RawEvent{Source: "opensnoop", Data: append([]byte(nil), rec.RawSample...)}:
			default:
				if n := rawDropped.Add(1); n == 1 || n%100 == 0 {
					log.Printf("warning: rawCh full, %d kernel events dropped", n)
				}
			}
		}
	}()
	go func() {
		for {
			rec, err := loader.NetRd.Read()
			if err != nil {
				return
			}
			select {
			case rawCh <- pipeline.RawEvent{Source: "lsm-connect", Data: append([]byte(nil), rec.RawSample...)}:
			default:
				if n := rawDropped.Add(1); n == 1 || n%100 == 0 {
					log.Printf("warning: rawCh full, %d kernel events dropped", n)
				}
			}
		}
	}()

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

			// pending-ns logic → NOW uses State
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

	// Detector
	go func() {
		for ev := range enrichedCh {
			for _, a := range det.Detect(ev) {
				action := detector.ResponseFor(a.Rule, a.Level)
				if action != detector.ActionNone {
					detector.Respond(&a, action)
				}
				a.ResponseAction = string(action)
				select {
				case alertCh <- a:
				default:
					alertDropped.Add(1)
					log.Printf("ERROR: alertCh full, alert dropped: rule=%s level=%s comm=%s", a.Rule, a.Level, a.Comm)
				}
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
}

func enrich(raw pipeline.RawEvent, r workload.WorkloadResolver) *pipeline.EnrichedEvent {
	switch raw.Source {

	case "execsnoop":
		var ev processor.ProcessEvent
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

	case "opensnoop":
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

	case "lsm-connect":
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
