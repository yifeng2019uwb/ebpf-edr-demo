package alertsink

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"ebpf-edr-demo/internal/alert"
)

// FileSink writes alerts to a local file.
type FileSink struct {
	mu   sync.Mutex
	file *os.File
}

func NewFileSink(path string) (*FileSink, error) {
	// Create the log's parent directory (matches the actual path, which may be an
	// absolute hostPath mount like /alerts on K8s — not the relative default).
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &FileSink{file: f}, nil
}

func (s *FileSink) Write(ctx context.Context, a alert.Alert) error {
	now := eventWallTime(a.EventTime) // kernel event time, not detect time
	ts := now.Format("2006-01-02 15:04:05.000000")

	extra := ""
	if a.Filename != "" {
		extra = " filename=" + a.Filename
		extra += fmt.Sprintf(" fmode=0x%x ret=%d", a.Fmode, a.Ret)
	} else if a.DstIP != "" {
		extra = fmt.Sprintf(" dst=%s:%d", a.DstIP, a.DstPort)
	}
	if a.Cgroup != "" {
		extra += " cgroup=" + a.Cgroup
	}
	if a.EventTime != 0 {
		extra += fmt.Sprintf(" event_time=%d", a.EventTime)
	}
	if a.ResponseAction != alert.ActionNone {
		extra += " action=" + string(a.ResponseAction)
	}

	id := a.Workload.Identity
	meta := a.Workload.Meta
	state := a.Workload.State

	line := fmt.Sprintf(
		"[%s] ALERT level=%s rule=%s runtime=%s service=%s env=%s state=%s pod=%s k8s_namespace=%s pid=%d ppid=%d uid=%d comm=%s%s msg=%s\n",
		ts,
		a.Level,
		a.Rule,
		id.Runtime,
		id.Service,
		id.Env,
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

	s.mu.Lock()
	_, err := s.file.WriteString(line)
	s.mu.Unlock()

	if err != nil {
		log.Printf("file sink write error: %v", err)
		return err
	}

	return nil
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
