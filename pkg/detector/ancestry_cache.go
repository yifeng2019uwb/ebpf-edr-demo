package detector

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ancestryTTL bounds how long an exec record is kept. Entries only need to
	// survive until the process's children generate events (ms–seconds after spawn);
	// persistent daemons are covered by the static Layer 1 safeInfraPIDs instead.
	ancestryTTL = 10 * time.Minute

	// ancestryMaxEntries caps memory during exec storms (~100B/entry ≈ 6MB).
	ancestryMaxEntries = 65536
)

// AncestryEntry is one exec record: which parent spawned the pid and what binary it ran.
// ExecPath is the full executable path captured in-kernel at exec time, so it stays
// valid (and race-free) after the process exits.
type AncestryEntry struct {
	Ppid      uint32
	ExecPath  string
	FirstSeen time.Time
}

// AncestryCache is a live pid → exec-record map populated from execsnoop events.
// It gives the detector race-free parent identity: an entry is written when a process
// execs, so the parent's identity remains readable after the parent dies — unlike
// reactive /proc reads. Design: docs/DESIGN-PROCESS-ANCESTRY-CACHE.md.
type AncestryCache struct {
	mu      sync.RWMutex
	entries map[uint32]AncestryEntry
	hits    atomic.Int64
	misses  atomic.Int64
}

func NewAncestryCache() *AncestryCache {
	return &AncestryCache{entries: make(map[uint32]AncestryEntry)}
}

// Bootstrap seeds the cache with the processes that already exist at agent
// startup — they exec'd before we could observe it (e.g. long-lived scripts),
// so the exec-event feed alone would never learn them. Uses the same kernel
// truth as Layer 1 discovery: /proc/<pid>/exe + /proc/<pid>/status PPid.
// Note: for scripts, /proc/<pid>/exe resolves to the interpreter binary
// (e.g. /usr/bin/bash), not the script path.
func (c *AncestryCache) Bootstrap() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("ancestry cache: bootstrap /proc scan failed: %v", err)
		return
	}
	seeded := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a pid directory
		}
		pid := uint32(pid64)
		execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			continue // kernel thread, or exited mid-scan
		}
		c.Record(pid, procPPid(pid), execPath)
		seeded++
	}
	log.Printf("ancestry cache: bootstrapped %d pre-existing processes", seeded)
}

// procPPid reads the PPid field from /proc/<pid>/status. Returns 0 if unavailable.
func procPPid(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	// One "Key:\tValue" pair per line; strings.Fields on "PPid:\t270674"
	// yields ["PPid:", "270674"].
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
					return uint32(v)
				}
			}
			break
		}
	}
	return 0
}

// Record stores the exec record for pid, overwriting any previous entry.
// Overwriting is the replace-on-exec property: a reused or re-exec'd PID
// refreshes its own entry before it can spawn children with stale identity.
func (c *AncestryCache) Record(pid, ppid uint32, execPath string) {
	now := time.Now()
	c.mu.Lock()
	if len(c.entries) >= ancestryMaxEntries {
		c.evictLocked(now)
	}
	c.entries[pid] = AncestryEntry{Ppid: ppid, ExecPath: execPath, FirstSeen: now}
	c.mu.Unlock()
}

// Lookup returns the exec record for pid, if still cached.
func (c *AncestryCache) Lookup(pid uint32) (AncestryEntry, bool) {
	c.mu.RLock()
	e, ok := c.entries[pid]
	c.mu.RUnlock()
	if ok {
		c.hits.Add(1)
	} else {
		c.misses.Add(1)
	}
	return e, ok
}

// Sweep evicts entries past the TTL whose process is gone, and logs cache health.
// Still-alive processes (e.g. long-lived pre-agent scripts) are kept with the TTL
// re-armed, so each one costs a single /proc stat per TTL window — their identity
// must stay resolvable as long as they can spawn children.
// Called periodically from the cache-cleanup ticker in main.
func (c *AncestryCache) Sweep() {
	now := time.Now()
	cutoff := now.Add(-ancestryTTL)
	c.mu.Lock()
	for pid, e := range c.entries {
		if !e.FirstSeen.Before(cutoff) {
			continue
		}
		if processAlive(pid) {
			e.FirstSeen = now
			c.entries[pid] = e
			continue
		}
		delete(c.entries, pid)
	}
	size := len(c.entries)
	c.mu.Unlock()
	log.Printf("DEBUG: ancestry cache: %d entries, lookups hit=%d miss=%d", size, c.hits.Load(), c.misses.Load())
}

// processAlive reports whether /proc/<pid> still exists.
func processAlive(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// sweepLocked removes entries first seen before cutoff. Caller holds mu.
func (c *AncestryCache) sweepLocked(cutoff time.Time) {
	for pid, e := range c.entries {
		if e.FirstSeen.Before(cutoff) {
			delete(c.entries, pid)
		}
	}
}

// evictLocked frees space when the hard cap is hit during an exec storm:
// progressively halve the age threshold until below cap. If every entry is
// newer than one second (pathological storm), drop arbitrary entries — a
// deterministic memory bound matters more than entry choice at that point.
// Caller holds mu.
func (c *AncestryCache) evictLocked(now time.Time) {
	for age := ancestryTTL; len(c.entries) >= ancestryMaxEntries && age > time.Second; age /= 2 {
		c.sweepLocked(now.Add(-age))
	}
	for pid := range c.entries {
		if len(c.entries) < ancestryMaxEntries {
			break
		}
		delete(c.entries, pid)
	}
}
