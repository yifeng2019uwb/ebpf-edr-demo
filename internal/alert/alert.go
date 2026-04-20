// Package alert defines the Alert struct and handles writing structured
// security events to stdout and the persistent alert log file.
package alert

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Alert represents a security detection event emitted by a detection rule.
type Alert struct {
	Level     string
	Rule      string
	Message   string
	Pid       int32
	Ppid      int32
	Uid       int32
	Comm      string
	Container string // container name or "host"
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
	line := fmt.Sprintf("[%s] ALERT level=%s rule=%s container=%s pid=%d ppid=%d uid=%d comm=%s msg=%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		a.Level, a.Rule, a.Container,
		a.Pid, a.Ppid, a.Uid,
		a.Comm, a.Message)

	log.Print(line)
	if _, err := h.file.WriteString(line); err != nil {
		log.Printf("failed to write alert: %v", err)
	}
}

// Close closes the alert log file.
func (h *Handler) Close() {
	h.file.Close()
}
