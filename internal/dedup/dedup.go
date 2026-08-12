// Package dedup collapses repeated file-open events from the same process.
//
// Multi-threaded processes open the same file once per thread (N threads = N openat
// events from the sensor). From the detection perspective the open happened once —
// threads share file descriptors and memory — so only the first occurrence within a
// short window is forwarded.
package dedup

import (
	"sync"
	"time"
)

// shardCount distributes lock contention across cores. Events are sharded by pid,
// so all of one process's opens contend on a single shard rather than a global lock.
const shardCount = 32

// key is {process, path} — deliberately NO comm. The sensor's pid is the tgid (same
// for every thread of a process), but its comm is the THREAD name
// (bpf_get_current_comm), so differently-named threads of one process opening the
// same file used to produce distinct keys and double-fire alerts ~80ms apart.
// Filename must be the CString form, NOT the raw [N]byte: trailing bytes after the
// null differ between events for the same open, defeating byte-array dedup.
type key struct {
	pid      uint32
	filename string
}

type shard struct {
	mu   sync.Mutex
	seen map[key]time.Time
}

// Cache tracks recently-seen (pid, filename) pairs. Safe for concurrent use.
type Cache struct {
	window time.Duration
	shards [shardCount]shard
}

// New returns a cache that treats repeats within window as duplicates.
func New(window time.Duration) *Cache {
	c := &Cache{window: window}
	for i := range c.shards {
		c.shards[i].seen = make(map[key]time.Time)
	}
	return c
}

// Seen reports whether (pid, filename) was already recorded within the window,
// recording it when it was not. now is passed in rather than read from the clock
// so callers can drive it deterministically.
func (c *Cache) Seen(pid uint32, filename string, now time.Time) bool {
	k := key{pid: pid, filename: filename}
	s := &c.shards[pid%shardCount]
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.seen[k]; ok && now.Sub(last) < c.window {
		return true
	}
	s.seen[k] = now
	return false
}

// Sweep drops entries older than the window and returns how many were removed.
//
// This is required, not housekeeping: keys carry the pid, and pids keep changing, so
// entries are never overwritten and the maps would otherwise grow for the lifetime of
// the process. At the event rates this agent sees under load that reaches millions of
// entries in a few hours. Call it on an interval near the window — anything longer
// just raises the ceiling on retained entries.
func (c *Cache) Sweep(now time.Time) int {
	cutoff := now.Add(-c.window)
	removed := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, last := range s.seen {
			if last.Before(cutoff) {
				delete(s.seen, k)
				removed++
			}
		}
		s.mu.Unlock()
	}
	return removed
}

// Len returns the number of retained entries across all shards.
func (c *Cache) Len() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n += len(s.seen)
		s.mu.Unlock()
	}
	return n
}
