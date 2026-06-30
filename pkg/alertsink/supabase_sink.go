package alertsink

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"

	"ebpf-edr-demo/internal/alert"
)

// SupabaseSink writes alerts to Supabase PostgreSQL database for persistent storage.
type SupabaseSink struct {
	db *sql.DB
}

func NewSupabaseSink(url, key string) (*SupabaseSink, error) {
	// Convert Supabase URL to PostgreSQL connection string
	// url format: https://project.supabase.co
	// Convert to: postgres://postgres:key@project.supabase.co:5432/postgres
	connStr := fmt.Sprintf("postgres://postgres:%s@%s:5432/postgres?sslmode=require",
		url, key)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("supabase sink init failed: %v", err)
		return nil, err
	}

	// Test connection
	if err := db.PingContext(context.Background()); err != nil {
		log.Printf("supabase sink connection test failed: %v", err)
		return nil, err
	}

	log.Printf("supabase sink connected")
	return &SupabaseSink{db: db}, nil
}

// alertRow represents a row in the alerts table.
type alertRow struct {
	Timestamp      time.Time `json:"timestamp"`
	Level          string    `json:"level"`
	Rule           string    `json:"rule"`
	Message        string    `json:"message"`
	Pid            int32     `json:"pid"`
	Ppid           int32     `json:"ppid"`
	Uid            int32     `json:"uid"`
	Comm           string    `json:"comm"`
	Runtime        string    `json:"runtime"`
	Service        string    `json:"service"`
	Env            string    `json:"env"`
	State          string    `json:"state"`
	Cluster        string    `json:"cluster"`
	Pod            string    `json:"pod"`
	Namespace      string    `json:"namespace"`
	Node           string    `json:"node"`
	Region         string    `json:"region"`
	Filename       string    `json:"filename"`
	DstIP          string    `json:"dst_ip"`
	DstPort        int       `json:"dst_port"`
	ResponseAction string    `json:"response_action"`
}

func (s *SupabaseSink) Write(ctx context.Context, a alert.Alert) error {
	query := `
		INSERT INTO alerts (
			timestamp, level, rule, message, pid, ppid, uid, comm,
			runtime, service, env, state, cluster, pod, namespace, node, region,
			filename, dst_ip, dst_port, response_action
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16, $17,
			$18, $19, $20, $21
		)
	`

	_, err := s.db.ExecContext(ctx, query,
		time.Now().UTC(),
		string(a.Level),
		a.Rule,
		a.Message,
		a.Pid,
		a.Ppid,
		a.Uid,
		a.Comm,
		a.Workload.Identity.Runtime,
		a.Workload.Identity.Service,
		a.Workload.Identity.Env,
		string(a.Workload.State),
		a.Workload.Meta.Cluster,
		a.Workload.Meta.Pod,
		a.Workload.Meta.Namespace,
		a.Workload.Meta.Node,
		a.Workload.Meta.Region,
		a.Filename,
		a.DstIP,
		a.DstPort,
		a.ResponseAction,
	)

	if err != nil {
		log.Printf("supabase sink insert error: %v", err)
		return fmt.Errorf("supabase insert: %w", err)
	}

	return nil
}

func (s *SupabaseSink) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
