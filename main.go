//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const TaskCommLen = 128

// Must match execsnoop.h struct event
type Event struct {
	Pid  int32
	Ppid int32
	Uid  int32
	Comm [TaskCommLen]byte
}

func main() {
	// Remove memory limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load eBPF objects
	objs := processObjects{}
	if err := loadProcessObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve",
		objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	// Open perf reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("opening perf reader: %v", err)
	}
	defer rd.Close()

	log.Println("Monitoring process execution... Press Ctrl+C to stop")

	// Handle Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				return
			}

			var event Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing event: %v", err)
				continue
			}

			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
			log.Printf("pid=%-6d ppid=%-6d uid=%-6d comm=%s",
				event.Pid, event.Ppid, event.Uid, comm)
		}
	}()

	<-sig
	log.Println("Stopping...")
}
