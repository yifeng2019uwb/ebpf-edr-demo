//go:build linux

// edr-monitor — EDR agent entry point.
// Loads eBPF programs, wires the buffered pipeline, and emits structured alerts.
// All detection logic lives in pkg/detector; workload resolution in pkg/workload.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"
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

func main() {
	runtime := flag.String("runtime", "auto", "workload runtime: docker | k8s | auto")
	flag.Parse()

	handler, err := alert.NewHandler("alerts/alert.log")
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

	rawCh := make(chan pipeline.RawEvent, 4096)
	enrichedCh := make(chan pipeline.EnrichedEvent, 1024)
	alertCh := make(chan alert.Alert, 64)

	var dropped atomic.Int64
	var alertCount atomic.Int64

	log.Println("EDR Monitor started — watching process execution, file access, and network connections")
	log.Printf("Runtime: %s | Press Ctrl+C to stop", *runtime)

	// Metrics: log pipeline health every 10s
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("[METRICS] raw_pending=%d enr_pending=%d alert_pending=%d dropped=%d alerts=%d",
				len(rawCh), len(enrichedCh), len(alertCh),
				dropped.Load(), alertCount.Load())
		}
	}()

	// Producers: one goroutine per probe → rawCh
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

	// Enricher: rawCh → enrichedCh
	go func() {
		for raw := range rawCh {
			ev := enrich(raw, resolver)
			if ev == nil {
				continue
			}
			if ev.Type == pipeline.ProcessEventType {
				comm := processor.CString(ev.Process.Comm[:])
				log.Printf("[PROCESS] pid=%-6d ppid=%-6d uid=%-6d mnt_ns=%-10d service=%-30s path=%s",
					ev.Process.Pid, ev.Process.Ppid, ev.Process.Uid, ev.Process.MntNsId, ev.Workload.Service, comm)
			}
			enrichedCh <- *ev
		}
	}()

	// Detector: enrichedCh → alertCh (non-blocking drop on full)
	det := detector.NewRuleDetector()
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

	// Handler: alertCh → output
	go func() {
		for a := range alertCh {
			handler.Send(a)
			alertCount.Add(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Stopping EDR monitor...")
}

func enrich(raw pipeline.RawEvent, r workload.WorkloadResolver) *pipeline.EnrichedEvent {
	switch raw.Source {
	case "execsnoop":
		var ev processor.ProcessEvent
		if err := binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing process event: %v", err)
			return nil
		}
		id := r.Resolve(ev.MntNsId, uint32(ev.Pid))
		return &pipeline.EnrichedEvent{
			Type: pipeline.ProcessEventType, Process: &ev,
			Workload: id, Timestamp: time.Now(),
		}
	case "opensnoop":
		var ev processor.FileEvent
		if err := binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing file event: %v", err)
			return nil
		}
		id := r.Resolve(uint32(ev.MntNsId), uint32(ev.Pid))
		return &pipeline.EnrichedEvent{
			Type: pipeline.FileEventType, File: &ev,
			Workload: id, Timestamp: time.Now(),
		}
	case "lsm-connect":
		var ev processor.NetEvent
		if err := binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing net event: %v", err)
			return nil
		}
		id := r.Resolve(uint32(ev.MntNsId), uint32(ev.Pid))
		return &pipeline.EnrichedEvent{
			Type: pipeline.NetEventType, Net: &ev,
			Workload: id, Timestamp: time.Now(),
		}
	}
	return nil
}
