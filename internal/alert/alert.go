// Package alert defines the Alert struct and handles writing structured
// security events to stdout and the persistent alert log file.
package alert

import (
	"fmt"
	"log"
	"os"
	"time"

	"ebpf-edr-demo/pkg/workload"
)

// Alert represents a security detection event emitted by a detection rule.
type Alert struct {
	Level   string
	Rule    string
	Message string
	Pid     int32
	Ppid    int32
	Uid     int32
	Comm    string
	Workload workload.WorkloadIdentity
	// event-specific fields
	Filename string // populated for file events
	DstIP    string // populated for network events
	DstPort  uint16 // populated for network events
}

// Handler manages where alerts are written.
type Handler struct {
	file *os.File
}

// NewHandler opens the alert log file (creates if not exists, appends if exists).
func NewHandler(path string) (*Handler, error) {
	if err := os.MkdirAll("alerts", 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Handler{file: f}, nil
}

// Send writes the alert to stdout and the log file.
func (h *Handler) Send(a Alert) {
	extra := ""
	if a.Filename != "" {
		extra = " filename=" + a.Filename
	} else if a.DstIP != "" {
		extra = fmt.Sprintf(" dst=%s:%d", a.DstIP, a.DstPort)
	}

	line := fmt.Sprintf("[%s] ALERT level=%s rule=%s runtime=%s service=%s pod=%s namespace=%s pid=%d ppid=%d uid=%d comm=%s%s msg=%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		a.Level, a.Rule,
		a.Workload.Runtime, a.Workload.Service, a.Workload.Pod, a.Workload.Namespace,
		a.Pid, a.Ppid, a.Uid, a.Comm, extra, a.Message)

	log.Print(line)
	if _, err := h.file.WriteString(line); err != nil {
		log.Printf("failed to write alert: %v", err)
	}
}

// Close closes the alert log file.
func (h *Handler) Close() {
	h.file.Close()
}
