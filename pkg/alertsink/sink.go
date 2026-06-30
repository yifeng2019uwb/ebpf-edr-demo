// Package alertsink provides pluggable alert destinations.
// Alerts can be written to multiple sinks (Redis, Supabase, local file)
// independently, allowing graceful degradation when services are unavailable.
package alertsink

import (
	"ebpf-edr-demo/internal/alert"
)

// Ensure each sink implements alert.Sink interface
var (
	_ alert.Sink = (*FileSink)(nil)
	_ alert.Sink = (*RedisSink)(nil)
	_ alert.Sink = (*SupabaseSink)(nil)
)
