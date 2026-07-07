package alertsink

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/redis/go-redis/v9"

	"ebpf-edr-demo/internal/alert"
)

const (
	redisChannel     = "edr-alerts"
	redisConnTimeout = 2 * time.Second
)

// RedisSink publishes alerts to a Redis channel for real-time monitoring.
type RedisSink struct {
	client  *redis.Client
	channel string
}

func NewRedisSink(addr string) (*RedisSink, error) {
	// Parse Redis URL (format: redis://user:pass@host:port)
	opts, err := redis.ParseURL(addr)
	if err != nil {
		log.Printf("redis sink parse url failed: url=%s err=%v", addr, err)
		return nil, err
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), redisConnTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("redis sink connection failed: %v", err)
		return nil, err
	}

	log.Printf("redis sink connected: %s", addr)
	return &RedisSink{
		client:  client,
		channel: redisChannel,
	}, nil
}

func (s *RedisSink) Write(ctx context.Context, a alert.Alert) error {
	// LOW alerts are informational telemetry (e.g. unresolved-namespace visibility
	// gaps). Keep them off the live dashboard to avoid alert fatigue; they still
	// persist via the file + Supabase sinks for the anomaly service to analyze.
	if a.Level == alert.Low {
		return nil
	}

	payload := map[string]interface{}{
		"ts":              time.Now().UTC().Format(time.RFC3339),
		"level":           string(a.Level),
		"rule":            a.Rule,
		"message":         a.Message,
		"pid":             a.Pid,
		"ppid":            a.Ppid,
		"uid":             a.Uid,
		"comm":            a.Comm,
		"runtime":         a.Workload.Identity.Runtime,
		"service":         a.Workload.Identity.Service,
		"env":             a.Workload.Identity.Env,
		"state":           string(a.Workload.State),
		"cluster":         a.Workload.Meta.Cluster,
		"pod":             a.Workload.Meta.Pod,
		"namespace":       a.Workload.Meta.Namespace,
		"node":            a.Workload.Meta.Node,
		"region":          a.Workload.Meta.Region,
		"filename":        a.Filename,
		"dst_ip":          a.DstIP,
		"dst_port":        a.DstPort,
		"response_action": a.ResponseAction,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("redis sink marshal error: %v", err)
		return err
	}

	if err := s.client.Publish(ctx, s.channel, data).Err(); err != nil {
		log.Printf("redis sink publish error: %v", err)
		return err
	}

	return nil
}

func (s *RedisSink) Close() error {
	return s.client.Close()
}
