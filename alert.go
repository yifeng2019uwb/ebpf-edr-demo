//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Alert represents a security detection event
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

// AlertHandler manages where alerts are sent
type AlertHandler struct {
	file *os.File
}

// NewAlertHandler opens the alert log file (creates if not exists, appends if exists)
func NewAlertHandler(path string) (*AlertHandler, error) {
	if err := os.MkdirAll("alerts", 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &AlertHandler{file: f}, nil
}

// Send writes the alert to stdout and the log file
// TODO: add Slack webhook notification
// TODO: add email via SMTP
func (h *AlertHandler) Send(alert Alert) {
	line := fmt.Sprintf("[%s] ALERT level=%s rule=%s container=%s pid=%d ppid=%d uid=%d comm=%s msg=%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		alert.Level, alert.Rule, alert.Container,
		alert.Pid, alert.Ppid, alert.Uid,
		alert.Comm, alert.Message)

	log.Print(line)
	if _, err := h.file.WriteString(line); err != nil {
    	log.Printf("failed to write alert: %v", err)
	}
}

// Close closes the alert log file
func (h *AlertHandler) Close() {
	h.file.Close()
}
