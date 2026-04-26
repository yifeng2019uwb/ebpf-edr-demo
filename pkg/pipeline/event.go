package pipeline

import (
	"time"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/workload"
)

type EventType string

const (
	ProcessEventType EventType = "process"
	FileEventType    EventType = "file"
	NetEventType     EventType = "network"
)

type RawEvent struct {
	Source string
	Data   []byte
}

type EnrichedEvent struct {
	Type      EventType
	Process   *processor.ProcessEvent
	File      *processor.FileEvent
	Net       *processor.NetEvent
	Workload  workload.ResolveResult
	Timestamp time.Time
}

type EventSource interface {
	Name() string
	Start() error
	Events() <-chan RawEvent
	Close()
}

type Detector interface {
	Detect(event EnrichedEvent) []alert.Alert
}

type AlertHandler interface {
	Send(a alert.Alert)
}

type EventForwarder interface {
	Forward(event EnrichedEvent)
}
