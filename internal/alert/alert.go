package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	cloudlogging "cloud.google.com/go/logging"
	"cloud.google.com/go/pubsub/v2"
	"ebpf-edr-demo/pkg/workload"
)

const alertDir = "alerts"
const alertPath = alertDir + "/alert.log"
const logName = "ebpf-edr-alerts"

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

	Workload workload.ResolveResult

	// event-specific fields
	Filename string
	DstIP    string
	DstPort  uint16

	ResponseAction string // set by responder after detection; empty means no action taken
}

// alertPayload is the structured JSON written to Cloud Logging.
type alertPayload struct {
	SchemaVersion int    `json:"schema_version"`
	Ts            string `json:"ts"`
	Level         string `json:"level"`
	Rule          string `json:"rule"`
	Message       string `json:"message"`
	Pid           int32  `json:"pid"`
	Ppid          int32  `json:"ppid"`
	Uid           int32  `json:"uid"`
	Comm          string `json:"comm"`
	Runtime       string `json:"runtime"`
	Service       string `json:"service"`
	Env           string `json:"env,omitempty"`
	State         string `json:"state"`
	Cluster       string `json:"cluster"`
	Pod           string `json:"pod"`
	Namespace     string `json:"namespace"`
	Node          string `json:"node"`
	Region        string `json:"region"`
	Filename       string `json:"filename,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	DstPort        uint16 `json:"dst_port,omitempty"`
	ResponseAction string `json:"response_action,omitempty"`
}

const pubsubTopicID = "edr-alerts"

// Handler manages where alerts are written.
type Handler struct {
	file        *os.File
	cloudLogger *cloudlogging.Logger
	cloudClient *cloudlogging.Client
	pubsubPublisher *pubsub.Publisher
}

// NewHandler opens the alert log file and initialises Cloud Logging if
// GOOGLE_CLOUD_PROJECT is set.
func NewHandler() (*Handler, error) {
	if err := os.MkdirAll(alertDir, 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(alertPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	h := &Handler{file: f}

	if project := os.Getenv("GOOGLE_CLOUD_PROJECT"); project != "" {
		client, err := cloudlogging.NewClient(context.Background(), project)
		if err != nil {
			log.Printf("Cloud Logging disabled — client init failed: %v", err)
		} else {
			h.cloudLogger = client.Logger(logName)
			h.cloudClient = client
			log.Printf("Cloud Logging enabled: project=%s", project)
		}

		psClient, err := pubsub.NewClient(context.Background(), project)
		if err != nil {
			log.Printf("Pub/Sub disabled — client init failed: %v", err)
		} else {
			h.pubsubPublisher = psClient.Publisher(pubsubTopicID)
			log.Printf("Pub/Sub enabled: topic=%s", pubsubTopicID)
		}
	} else {
		log.Printf("Cloud Logging disabled — GOOGLE_CLOUD_PROJECT not set")
	}

	return h, nil
}

// Send writes the alert to stdout, the local log file, and Cloud Logging (if enabled).
func (h *Handler) Send(a Alert) {
	now := time.Now()

	extra := ""
	if a.Filename != "" {
		extra = " filename=" + a.Filename
	} else if a.DstIP != "" {
		extra = fmt.Sprintf(" dst=%s:%d", a.DstIP, a.DstPort)
	}
	if a.ResponseAction != "" && a.ResponseAction != "none" {
		extra += " action=" + a.ResponseAction
	}

	id := a.Workload.Identity
	meta := a.Workload.Meta
	state := a.Workload.State

	line := fmt.Sprintf(
		"[%s] ALERT level=%s rule=%s runtime=%s service=%s env=%s state=%s pod=%s namespace=%s pid=%d ppid=%d uid=%d comm=%s%s msg=%s\n",
		now.Format("2006-01-02 15:04:05"),
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

	if _, err := h.file.WriteString(line); err != nil {
		log.Printf("failed to write alert: %v", err)
	}

	payload := alertPayload{
		SchemaVersion: 1,
		Ts:            now.UTC().Format(time.RFC3339),
		Level:         string(a.Level),
		Rule:          a.Rule,
		Message:       a.Message,
		Pid:           a.Pid,
		Ppid:          a.Ppid,
		Uid:           a.Uid,
		Comm:          a.Comm,
		Runtime:       id.Runtime,
		Service:       id.Service,
		Env:           id.Env,
		State:         string(state),
		Cluster:       meta.Cluster,
		Pod:           meta.Pod,
		Namespace:     meta.Namespace,
		Node:          meta.Node,
		Region:        meta.Region,
		Filename:       a.Filename,
		DstIP:          a.DstIP,
		DstPort:        a.DstPort,
		ResponseAction: a.ResponseAction,
	}

	if h.cloudLogger != nil {
		h.cloudLogger.Log(cloudlogging.Entry{
			Severity: severityFor(a.Level),
			Payload:  payload,
		})
	}

	if h.pubsubPublisher != nil {
		if data, err := json.Marshal(payload); err == nil {
			result := h.pubsubPublisher.Publish(context.Background(), &pubsub.Message{Data: data})
			go func() {
				if _, err := result.Get(context.Background()); err != nil {
					log.Printf("Pub/Sub publish error: %v", err)
				}
			}()
		}
	}
}

// Close flushes Cloud Logging, stops the Pub/Sub publisher, and closes the log file.
func (h *Handler) Close() {
	h.file.Close()
	if h.cloudClient != nil {
		if err := h.cloudClient.Close(); err != nil {
			log.Printf("Cloud Logging flush error: %v", err)
		}
	}
	if h.pubsubPublisher != nil {
		h.pubsubPublisher.Stop()
	}
}

func severityFor(level Level) cloudlogging.Severity {
	switch level {
	case Critical:
		return cloudlogging.Critical
	case High:
		return cloudlogging.Error
	case Medium:
		return cloudlogging.Warning
	default:
		return cloudlogging.Info
	}
}
