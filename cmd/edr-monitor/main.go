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
	pendingMaxRetries    = 3
	pendingMaxAge        = 10 * time.Second
)

type pendingEntry struct {
	ev        pipeline.EnrichedEvent
	mntNsID   uint32
	firstSeen time.Time
	retries   int
}

func main() {
	runtime := flag.String("runtime", "auto", "docker | k8s")
	flag.Parse()

	handler, err := alert.NewHandler("alerts/alert.log")
	if err != nil {
		log.Fatalf("opening alert log: %v", err)
	}
	defer handler.Close()

	resolver := workload.NewResolver(*runtime)
	resolver.Start()

	loader, err := bpf.Load()
	if err != nil {
		log.Fatalf("loading eBPF programs: %v", err)
	}
	defer loader.Close()

	rawCh := make(chan pipeline.RawEvent, 4096)
	enrichedCh := make(chan pipeline.EnrichedEvent, 1024)
	alertCh := make(chan alert.Alert, 64)

	var dropped atomic.Int64
	var unknownNs atomic.Int64

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
			rawCh <- pipeline.RawEvent{Source: "execsnoop", Data: append([]byte(nil), rec.RawSample...)}
		}
	}()
	go func() {
		for {
			rec, err := loader.FileRd.Read()
			if err != nil {
				return
			}
			rawCh <- pipeline.RawEvent{Source: "opensnoop", Data: append([]byte(nil), rec.RawSample...)}
		}
	}()
	go func() {
		for {
			rec, err := loader.NetRd.Read()
			if err != nil {
				return
			}
			rawCh <- pipeline.RawEvent{Source: "lsm-connect", Data: append([]byte(nil), rec.RawSample...)}
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

			enrichedCh <- *ev
		}
	}()

	// Retry pending
	go func() {
		ticker := time.NewTicker(pendingRetryInterval)
		defer ticker.Stop()

		for range ticker.C {
			pendingMu.Lock()

			for nsID, entries := range pendingBuf {
				res := resolver.Resolve(nsID, 0)

				// resolved
				if res.State == workload.StateResolved {
					for _, e := range entries {
						ev := e.ev
						ev.Workload = res
						enrichedCh <- ev
					}
					delete(pendingBuf, nsID)
					continue
				}

				// still pending
				var remain []pendingEntry
				for _, e := range entries {
					if e.retries >= pendingMaxRetries || time.Since(e.firstSeen) > pendingMaxAge {
						ev := e.ev
						ev.Workload.State = workload.StateUnknown
						unknownNs.Add(1)
						enrichedCh <- ev
					} else {
						e.retries++
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
				select {
				case alertCh <- a:
				default:
					dropped.Add(1)
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
	signal.Notify(sig, syscall.SIGINT)
	<-sig
}

func enrich(raw pipeline.RawEvent, r workload.WorkloadResolver) *pipeline.EnrichedEvent {
	switch raw.Source {

	case "execsnoop":
		var ev processor.ProcessEvent
		binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev)
		res := r.Resolve(ev.MntNsId, uint32(ev.Pid))

		return &pipeline.EnrichedEvent{
			Type:      pipeline.ProcessEventType,
			Process:   &ev,
			Workload:  res,
			Timestamp: time.Now(),
		}

	case "opensnoop":
		var ev processor.FileEvent
		binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev)
		res := r.Resolve(uint32(ev.MntNsId), uint32(ev.Pid))

		return &pipeline.EnrichedEvent{
			Type:      pipeline.FileEventType,
			File:      &ev,
			Workload:  res,
			Timestamp: time.Now(),
		}

	case "lsm-connect":
		var ev processor.NetEvent
		binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev)
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
