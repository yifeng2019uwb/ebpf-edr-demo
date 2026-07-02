package pipeline

import (
	"time"

	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/workload"
)

type EventType string

const (
	ProcessEventType EventType = "process"
	FileEventType    EventType = "file"
	NetEventType     EventType = "network"
)

type Source string

const (
	SourceExecsnoop  Source = "execsnoop"
	SourceOpensnoop  Source = "opensnoop"
	SourceNetConnect Source = "lsm-connect"
)

type RawEvent struct {
	Source Source
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
