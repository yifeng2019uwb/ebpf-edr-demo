//go:build linux

// edr-monitor — EDR agent entry point.
// Loads eBPF programs, starts event-reading goroutines, applies detection rules,
// and emits structured alerts. All detection logic lives in pkg/detector.
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/bpf"
	"ebpf-edr-demo/pkg/container"
	"ebpf-edr-demo/pkg/detector"
)

func main() {
	// Open alert handler — writes to stdout and alerts/alert.log
	handler, err := alert.NewHandler("alerts/alert.log")
	if err != nil {
		log.Fatalf("opening alert log: %v", err)
	}
	defer handler.Close()

	// Start container namespace resolver — scans /proc every 30s
	container.StartResolver()

	// Load all eBPF programs and attach kernel hooks
	loader, err := bpf.Load()
	if err != nil {
		log.Fatalf("loading eBPF programs: %v", err)
	}
	defer loader.Close()

	log.Println("EDR Monitor started — watching process execution, file access, and network connections")
	log.Println("Press Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine 1: process execution events (execsnoop → perf buffer)
	go func() {
		for {
			record, err := loader.ProcessRd.Read()
			if err != nil {
				return
			}
			var event processor.ProcessEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing process event: %v", err)
				continue
			}

			comm := processor.CString(event.Comm[:])
			containerName := container.Resolve(event.MntNsId)

			log.Printf("[PROCESS] pid=%-6d ppid=%-6d uid=%-6d mnt_ns=%-10d container=%-40s path=%s",
				event.Pid, event.Ppid, event.Uid, event.MntNsId, containerName, comm)

			if a := detector.CheckProcessRules(event, containerName); a != nil {
				handler.Send(*a)
			}
		}
	}()

	// Goroutine 2: file access events (opensnoop → ring buffer)
	go func() {
		for {
			record, err := loader.FileRd.Read()
			if err != nil {
				return
			}
			var event processor.FileEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing file event: %v", err)
				continue
			}

			comm := processor.CString(event.Comm[:])
			filename := processor.CString(event.Filename[:])
			containerName := container.Resolve(uint32(event.MntNsId))

			if a := detector.CheckFileRules(event, containerName); a != nil {
				log.Printf("[FILE]    pid=%-6d ppid=%-6d uid=%-6d container=%-40s comm=%-20s file=%s",
					event.Pid, event.Ppid, event.Uid, containerName, comm, filename)
				handler.Send(*a)
			}
		}
	}()

	// Goroutine 3: network connection events (lsm-connect → ring buffer)
	go func() {
		for {
			record, err := loader.NetRd.Read()
			if err != nil {
				return
			}
			var event processor.NetEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing net event: %v", err)
				continue
			}

			ip := processor.NetIP(event.DstIp)
			port := processor.NetPort(event.DstPort)
			comm := processor.CString(event.Comm[:])
			containerName := container.Resolve(uint32(event.MntNsId))

			if a := detector.CheckNetworkRules(event, containerName, ip, port); a != nil {
				log.Printf("[NET]     pid=%-6d ppid=%-6d uid=%-6d container=%-40s comm=%-20s dst=%s:%d",
					event.Pid, event.Ppid, event.Uid, containerName, comm, ip, port)
				handler.Send(*a)
			}
		}
	}()

	<-sig
	log.Println("Stopping EDR monitor...")
}
