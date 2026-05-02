package alert

import (
	"fmt"
	"log"
	"os"
	"time"

	"ebpf-edr-demo/pkg/workload"
)

// alertDir is the directory where all alert logs are written.
const alertDir = "alerts"

// alertPath is the single alert log file used at runtime.
// TODO: support time-windowed rotation — create alerts/alert_<timestamp>.log
//       every 10 or 30 minutes so each file covers a bounded time range.
//       Makes it easier to correlate alerts with incidents and limit file size.
const alertPath = alertDir + "/alert.log"

// Level represents the severity of an alert.
type Level string

const (
	Critical Level = "CRITICAL"
	High     Level = "HIGH"
	Medium   Level = "MEDIUM"
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

	// NEW: use ResolveResult instead of WorkloadIdentity
	Workload workload.ResolveResult

	// event-specific fields
	Filename string
	DstIP    string
	DstPort  uint16
}

// Handler manages where alerts are written.
type Handler struct {
	file *os.File
}

// NewHandler opens the alert log file, creating the alerts directory if needed.
func NewHandler() (*Handler, error) {
	if err := os.MkdirAll(alertDir, 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(alertPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Handler{file: f}, nil
}

// Send writes the alert to stdout and the log file.
func (h *Handler) Send(a Alert) {

	// extra info (file / network)
	extra := ""
	if a.Filename != "" {
		extra = " filename=" + a.Filename
	} else if a.DstIP != "" {
		extra = fmt.Sprintf(" dst=%s:%d", a.DstIP, a.DstPort)
	}

	id := a.Workload.Identity
	meta := a.Workload.Meta
	state := a.Workload.State

	line := fmt.Sprintf(
		"[%s] ALERT level=%s rule=%s runtime=%s service=%s state=%s pod=%s namespace=%s pid=%d ppid=%d uid=%d comm=%s%s msg=%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		a.Level,
		a.Rule,
		id.Runtime,
		id.Service,
		state,
		meta.Pod,
		meta.Namespace,
		a.Pid,
		a.Ppid,
		a.Uid,
		a.Comm,
		extra,
		a.Message,
	)

	log.Print(line)

	if _, err := h.file.WriteString(line); err != nil {
		log.Printf("failed to write alert: %v", err)
	}
}

// Close closes the alert log file.
func (h *Handler) Close() {
	h.file.Close()
}
