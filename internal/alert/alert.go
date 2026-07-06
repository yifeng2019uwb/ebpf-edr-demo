package alert

import (
	"context"
	"log"

	"ebpf-edr-demo/pkg/workload"
)

// Level represents the severity of an alert.
type Level string

const (
	Critical Level = "CRITICAL"
	High     Level = "HIGH"
	Medium   Level = "MEDIUM"
	Low      Level = "LOW"
)

// Action represents the response action taken by the responder.
type Action string

const (
	ActionNone        Action = "none"
	ActionKillProcess Action = "kill_process"
	ActionBlockIP     Action = "block_ip"
)

// Alert represents a security detection event emitted by a detection rule.
type Alert struct {
	Level   Level
	Rule    string
	Message string

	Pid  int32
	Ppid int32
	Uid  int32
	Comm string

	Workload workload.ResolveResult

	// event-specific fields
	Filename string
	DstIP    string
	DstPort  uint16

	ResponseAction Action // set by responder after detection; ActionNone means no action taken
}

// Sink writes alerts to a destination (Redis, Supabase, file, etc.).
type Sink interface {
	Write(ctx context.Context, a Alert) error
	Close() error
}

// Handler manages alert sinks.
type Handler struct {
	sinks []Sink
}

// NewHandler creates a handler with the given sinks.
func NewHandler(sinks []Sink) *Handler {
	return &Handler{sinks: sinks}
}

// Send writes the alert to all configured sinks.
func (h *Handler) Send(a Alert) {
	ctx := context.Background()
	for _, sink := range h.sinks {
		if err := sink.Write(ctx, a); err != nil {
			log.Printf("sink write error: %v", err)
		}
	}
}

// Close closes all sinks.
func (h *Handler) Close() {
	for _, sink := range h.sinks {
		if err := sink.Close(); err != nil {
			log.Printf("sink close error: %v", err)
		}
	}
}
