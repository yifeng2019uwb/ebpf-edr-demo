package alert

import (
	"context"
	"log"

	"ebpf-edr-demo/pkg/workload"
)

// Level represents the severity of an alert.
type Level string

const (
	Critical Level = "CRITICAL" // P1 (Critical) Immediate threats to infrastructure (e.g., container escapes, privilege escalations, or unauthorized eBPF program loads).
	High     Level = "HIGH"     // P2 (High): Serious violations requiring prompt review (e.g., access to sensitive/restricted files like /etc/shadow).
	Medium   Level = "MEDIUM"   // P3 (Medium/Warning): Behavioral anomalies, unusual outbound connections, or performance deviations.
	Low      Level = "LOW"      // P4 (Low/Info): Routine audit trails, policy check events, or basic statistical thresholds.
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

	ResponseAction Action // requested by the fired rule (rules/*.yaml response:), replaced with the action actually executed before the alert is sent; ActionNone = no action
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
