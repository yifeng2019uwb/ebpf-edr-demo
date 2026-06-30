package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
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
	// Load .env file if it exists (optional — supports local development)
	// If .env doesn't exist, falls back to environment variables
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		log.Printf("warning: loading .env: %v", err)
	}

	return &Config{
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		DatabaseKey:  os.Getenv("DATABASE_KEY"),
		PubSubAddr:   os.Getenv("PUBSUB_ADDR"),
		PubSubKey:    os.Getenv("PUBSUB_KEY"),
		AlertLogPath: "alerts/alert.log",
	}
}
