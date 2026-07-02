package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Environment variable names used throughout the project
const (
	// Database configuration
	EnvDatabaseURL    = "DATABASE_URL"
	EnvDatabaseKey    = "DATABASE_KEY"
	EnvDatabaseRegion = "DATABASE_REGION"
	EnvDatabaseHost   = "DATABASE_HOST"

	// Pub/Sub configuration
	EnvPubSubAddr = "PUBSUB_ADDR"
	EnvPubSubKey  = "PUBSUB_KEY"

	// Workload identification
	EnvRegion       = "REGION"
	EnvClusterName  = "CLUSTER_NAME"
	EnvEnv          = "ENV"
	EnvServiceCIDR  = "SERVICE_CIDR"

	// Sensor configuration (optional, for extended deployments)
	EnvSensorType   = "SENSOR_TYPE"
	EnvCollectorURL = "COLLECTOR_URL"
)

// Config holds alert infrastructure settings.
// Service implementations are decoupled — same config works with different backends.
type Config struct {
	// Database connection (any database: Supabase, PostgreSQL, DynamoDB, etc.)
	// URL format depends on backend (e.g., https://...supabase.co for Supabase)
	DatabaseURL string
	DatabaseKey string

	// Pub/Sub address (any pub/sub: Redis, Kafka, RabbitMQ, etc.)
	// Address format depends on backend (e.g., redis://host:port for Redis)
	PubSubAddr string
	PubSubKey  string

	// Local fallback (always available, no configuration needed)
	AlertLogPath string
}

func Load() *Config {
	// Load infra/.env if it exists (optional — supports local development)
	// Try multiple paths since binary can be run from different directories
	envPaths := []string{
		"infra/.env",    // from repo root
		"../infra/.env", // from bin/ directory
	}

	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			break
		} else if !os.IsNotExist(err) {
			log.Printf("warning: loading %s: %v", path, err)
		}
	}

	return &Config{
		DatabaseURL:  os.Getenv(EnvDatabaseURL),
		DatabaseKey:  os.Getenv(EnvDatabaseKey),
		PubSubAddr:   os.Getenv(EnvPubSubAddr),
		PubSubKey:    os.Getenv(EnvPubSubKey),
		AlertLogPath: "alerts/alert.log",
	}
}
