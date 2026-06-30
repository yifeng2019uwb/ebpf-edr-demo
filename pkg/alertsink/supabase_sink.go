package alertsink

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"ebpf-edr-demo/internal/alert"
)

// SupabaseSink writes alerts to Supabase PostgreSQL database for persistent storage.
type SupabaseSink struct {
	db *sql.DB
}

func NewSupabaseSink(url, key string) (*SupabaseSink, error) {
	// Parse URL to extract project name: https://jkhwfobxtydpknsplvcv.supabase.co → jkhwfobxtydpknsplvcv
	projectName := strings.TrimPrefix(url, "https://")
	projectName = strings.TrimSuffix(projectName, ".supabase.co")

	hostname := fmt.Sprintf("db.%s.supabase.co", projectName)
	username := "postgres"

	// Use Supavisor pooler endpoint if DATABASE_REGION is set (IPv4-compatible, required for Supabase Free tier on IPv6-only networks)
	// Otherwise try direct endpoint with IPv4 preference, or accept manual override via DATABASE_HOST
	if region := os.Getenv("DATABASE_REGION"); region != "" {
		hostname = fmt.Sprintf("aws-%s.pooler.supabase.com", region)
		username = fmt.Sprintf("postgres.%s", projectName)
	} else if override := os.Getenv("DATABASE_HOST"); override != "" {
		hostname = override
	} else {
		// Fallback: try direct endpoint with IPv4 preference (if available)
		ips, err := net.LookupHost(hostname)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if net.ParseIP(ip).To4() != nil {
					hostname = ip
					break
				}
			}
		}
	}

	connStr := fmt.Sprintf("postgres://%s:%s@%s:5432/postgres?sslmode=require&connect_timeout=5",
		username, key, hostname)

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
