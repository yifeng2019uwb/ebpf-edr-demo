// Package alertsink provides pluggable alert destinations.
// Alerts can be written to multiple sinks (Redis, Supabase, local file)
// independently, allowing graceful degradation when services are unavailable.
package alertsink

import (
	"time"

	"golang.org/x/sys/unix"

	"ebpf-edr-demo/internal/alert"
)

// Ensure each sink implements alert.Sink interface
var (
	_ alert.Sink = (*FileSink)(nil)
	_ alert.Sink = (*RedisSink)(nil)
	_ alert.Sink = (*SupabaseSink)(nil)
)

// bootRealTime is the wall-clock instant at which CLOCK_MONOTONIC read zero (system
// boot), captured once at package init. bpf_ktime_get_ns() returns CLOCK_MONOTONIC
// nanoseconds since boot, so adding an event's reading to bootRealTime yields its
// wall-clock time. Zero if the monotonic clock could not be read — callers then fall
// back to the current time.
var bootRealTime = func() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(ts.Nano()))
}()

// eventWallTime converts a bpf_ktime_get_ns() reading (CLOCK_MONOTONIC ns since boot)
// into a wall-clock UTC timestamp — the time the event actually occurred in the kernel,
// not when userspace got around to processing it. Falls back to the current time when
// the reading is 0 (event carried no timestamp) or the boot offset is unavailable.
func eventWallTime(monotonicNs uint64) time.Time {
	if monotonicNs == 0 || bootRealTime.IsZero() {
		return time.Now().UTC()
	}
	return bootRealTime.Add(time.Duration(monotonicNs)).UTC()
}
