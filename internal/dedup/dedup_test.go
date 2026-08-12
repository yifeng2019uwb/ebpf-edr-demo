package dedup

import (
	"sync"
	"testing"
	"time"
)

const testWindow = time.Second

func TestSeenSuppressesRepeatWithinWindow(t *testing.T) {
	c := New(testWindow)
	now := time.Now()

	if c.Seen(100, "/etc/passwd", now) {
		t.Fatal("first open reported as duplicate")
	}
	if !c.Seen(100, "/etc/passwd", now.Add(500*time.Millisecond)) {
		t.Fatal("repeat inside the window not reported as duplicate")
	}
	if c.Seen(100, "/etc/passwd", now.Add(2*testWindow)) {
		t.Fatal("repeat past the window reported as duplicate")
	}
}

func TestSeenDistinguishesPidAndFilename(t *testing.T) {
	c := New(testWindow)
	now := time.Now()

	c.Seen(100, "/etc/passwd", now)
	if c.Seen(101, "/etc/passwd", now) {
		t.Error("different pid treated as duplicate")
	}
	if c.Seen(100, "/etc/shadow", now) {
		t.Error("different filename treated as duplicate")
	}
}

// TestSweepBoundsGrowth is the regression test for the leak that made the agent
// grow without bound: keys carry the pid, so nothing is ever overwritten and the
// shard maps only grow until swept.
func TestSweepBoundsGrowth(t *testing.T) {
	c := New(testWindow)
	start := time.Now()

	for pid := uint32(0); pid < 5000; pid++ {
		c.Seen(pid, "/tmp/file", start)
	}
	if got := c.Len(); got != 5000 {
		t.Fatalf("retained %d entries before sweep, want 5000", got)
	}

	// Nothing is past the window yet, so a sweep must not evict anything.
	if removed := c.Sweep(start); removed != 0 {
		t.Fatalf("sweep removed %d entries still inside the window, want 0", removed)
	}
	if got := c.Len(); got != 5000 {
		t.Fatalf("retained %d entries after in-window sweep, want 5000", got)
	}

	// Past the window every entry is collectable.
	if removed := c.Sweep(start.Add(2 * testWindow)); removed != 5000 {
		t.Fatalf("sweep removed %d expired entries, want 5000", removed)
	}
	if got := c.Len(); got != 0 {
		t.Fatalf("retained %d entries after expiry sweep, want 0", got)
	}
}

func TestSweepKeepsRecentDropsExpired(t *testing.T) {
	c := New(testWindow)
	start := time.Now()

	c.Seen(1, "/old", start)
	c.Seen(2, "/new", start.Add(2*testWindow))

	c.Sweep(start.Add(2 * testWindow))

	if got := c.Len(); got != 1 {
		t.Fatalf("retained %d entries, want 1 (the recent one)", got)
	}
	// The surviving entry must still suppress its own repeat.
	if !c.Seen(2, "/new", start.Add(2*testWindow)) {
		t.Error("surviving entry no longer suppresses its repeat")
	}
}

// TestConcurrentSeenAndSweep is a -race guard: the enricher calls Seen from its
// goroutine while the sweeper ticker calls Sweep from another.
func TestConcurrentSeenAndSweep(t *testing.T) {
	c := New(testWindow)
	now := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(base uint32) {
			defer wg.Done()
			for i := uint32(0); i < 1000; i++ {
				c.Seen(base*1000+i, "/tmp/file", now)
			}
		}(uint32(w))
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			c.Sweep(now.Add(2 * testWindow))
		}
	}()
	wg.Wait()
}
