package alertsink

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"ebpf-edr-demo/internal/alert"
)

// FileSink writes alerts to a local file.
type FileSink struct {
	mu   sync.Mutex
	file *os.File
}

func NewFileSink(path string) (*FileSink, error) {
	if err := os.MkdirAll("alerts", 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &FileSink{file: f}, nil
}

func (s *FileSink) Write(ctx context.Context, a alert.Alert) error {
	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000000")

	extra := ""
	if a.Filename != "" {
		extra = " filename=" + a.Filename
	} else if a.DstIP != "" {
		extra = fmt.Sprintf(" dst=%s:%d", a.DstIP, a.DstPort)
	}
	if a.ResponseAction != alert.ActionNone {
		extra += " action=" + string(a.ResponseAction)
	}

	id := a.Workload.Identity
	meta := a.Workload.Meta
	state := a.Workload.State

	line := fmt.Sprintf(
		"[%s] ALERT level=%s rule=%s runtime=%s service=%s env=%s state=%s pod=%s namespace=%s pid=%d ppid=%d uid=%d comm=%s%s msg=%s\n",
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
