// Package pipeline defines the core event types and interfaces for the EDR pipeline.
//
//	execsnoop ──┐
//	opensnoop ──┼──▶ rawCh ──▶ Enricher ──▶ enrichedCh ──▶ Detector ──▶ alertCh ──▶ AlertHandler
//	lsm-connect ┘                                     └──▶ EventForwarder → [central stream]
package pipeline

import (
	"time"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/workload"
)

// EventType identifies which BPF probe produced an event.
type EventType string

const (
	ProcessEventType EventType = "process"
	FileEventType    EventType = "file"
	NetEventType     EventType = "network"
)

// RawEvent is the unparsed bytes from a BPF ring/perf buffer,
// tagged with the probe that produced it.
type RawEvent struct {
	Source string // "execsnoop" | "opensnoop" | "lsm-connect"
	Data   []byte // raw sample — parsed by the Enricher
}

// EnrichedEvent is a parsed kernel event with workload identity attached.
// Exactly one of Process/File/Net is non-nil, matching the Type field.
type EnrichedEvent struct {
	Type      EventType
	Process   *processor.ProcessEvent // non-nil when Type == ProcessEventType
	File      *processor.FileEvent    // non-nil when Type == FileEventType
	Net       *processor.NetEvent     // non-nil when Type == NetEventType
	Workload  workload.WorkloadIdentity
	Timestamp time.Time // userspace receipt time; see design doc for known limitation
}

// EventSource reads raw events from a single BPF probe.
type EventSource interface {
	Name()   string
	Start()  error
	Events() <-chan RawEvent
	Close()
}

// Detector applies detection rules to enriched events.
type Detector interface {
	Detect(event EnrichedEvent) []alert.Alert
}

// AlertHandler writes alerts to an output destination.
type AlertHandler interface {
	Send(a alert.Alert)
}

// EventForwarder forwards enriched events to a central correlation stream.
// Branches off enrichedCh — all enriched events are forwarded, not just alerts.
// Not used in Phase 1; reserved for Section 5 cross-node correlation.
type EventForwarder interface {
	Forward(event EnrichedEvent)
}
