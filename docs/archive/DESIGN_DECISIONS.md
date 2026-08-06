# Design Decisions — eBPF EDR Agent

**Purpose:** Document architectural decisions, tradeoffs, and rationale for future reference and maintenance.

---

## Performance Optimizations (2026-07-03)

### Decision 1: Unsafe Pointer Casting for Event Deserialization

**Context:**
- Current: `binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev)` allocates heap + uses reflection
- Issue: At 50K events/sec, this creates ~50MB/sec of allocations triggering GC pauses
- Hot path: `enrich()` function processes every kernel event

**Decision:** Replace `binary.Read()` with unsafe pointer casting for ProcessEvent, FileEvent, NetEvent

**Implementation:**
```go
// Before: Allocation + reflection overhead
binary.Read(bytes.NewReader(raw.Data), binary.LittleEndian, &ev)

// After: Direct memory access, zero allocation
ev := (*processor.ProcessEvent)(unsafe.Pointer(&raw.Data[0]))
```

**Rationale:**
- Event structs are byte-perfect matches to kernel C structs (verified in processor.go comments)
- Sizes are fixed and known: ProcessEvent=144B, FileEvent=408B, NetEvent=160B
- Buffer sizes from eBPF ring buffer are guaranteed ≥ event size (kernel contract)
- One-way read operation (no mutation of source)
- Safety: Add `if len(raw.Data) < unsafe.Sizeof(processor.ProcessEvent) { return nil }`

**Tradeoffs:**
- ✅ Eliminates allocation per event (major GC pressure relief)
- ✅ Eliminates reflection per event (CPU savings)
- ⚠️ Requires bounds checking before cast (small overhead)
- ⚠️ Pointer arithmetic is harder to debug if buffer is malformed (but kernel-guaranteed)

**Risk Level:** LOW — kernel guarantees buffer size, structs are validated by existing tests

---

### Decision 2: Struct-Key Maps for File Deduplication

**Context:**
- Current: `fileDedupSeen map[string]time.Time` where key = `fmt.Sprintf("%s:%d:%s", path, pid, comm)`
- Issue: `fmt.Sprintf()` allocates string per file event; at 10K file events/sec = 10K string allocs/sec
- Hot path: `enrich()` calls dedup check for every file event

**Decision:** Replace string keys with fixed struct keys

**Implementation:**
```go
type fileDedupKey struct {
    Pid      uint32
    Comm     [128]byte  // TASK_COMM_LEN from eBPF
    Filename [256]byte  // MAX_FILENAME_LEN from eBPF
}

// Before: allocates string
key := fmt.Sprintf("%s:%d:%s", filename, pid, comm)

// After: zero allocation (struct is stack-local or inline in map)
key := fileDedupKey{
    Pid:      pid,
    Comm:     // copy from FileEvent.Comm
    Filename: // copy from FileEvent.Filename
}
```

**Rationale:**
- Array sizes match kernel definitions (not arbitrary):
  - `TASK_COMM_LEN = 128` (defined in kernel/*.h files)
  - `MAX_FILENAME_LEN = 256` (defined in kernel/opensnoop.h)
- FileEvent struct already contains these exact arrays
- Go map keys support struct comparison (==) for bytes arrays
- No allocation: struct is value type, embedded in map internals

**Tradeoffs:**
- ✅ Zero allocation per dedup check
- ✅ No string building overhead
- ✅ Sizes are fixed (kernel contract, can't be longer)
- ⚠️ Struct is larger (128+256+8 bytes vs typically 20-50 byte string), but no heap cost
- ⚠️ Must copy Comm and Filename into key struct (but small cost vs string alloc)

**Risk Level:** LOW — sizes are from kernel definitions, struct comparison is safe in Go

---

### Decision 3: Mutex Sharding for File Dedup Lock Contention

**Context:**
- Current: Single `fileDedupMu sync.Mutex` protects all file event dedup across all goroutines
- Issue: On multi-core systems (8-16 cores), all file events contend on one lock
- Bottleneck: Lock hold time is short (~1μs map lookup), but high contention (10K events/sec)

**Decision:** Shard `fileDedupMu` into 32 independent locks, indexed by PID mod 32

**Implementation:**
```go
// Before: Single lock for all
var fileDedupMu sync.Mutex
var fileDedupSeen map[fileDedupKey]time.Time

// After: 32 shards, each with independent lock
var fileDedupShards [32]struct {
    mu   sync.Mutex
    seen map[fileDedupKey]time.Time
}

// Usage:
shard := pid % 32
fileDedupShards[shard].mu.Lock()
```

**Rationale:**
- PID is uniformly distributed across 32 buckets (hash-like)
- Different PIDs almost never collide on same shard (collisions are fine; just less parallelism)
- Reduces lock contention from O(1 lock) to O(N/32 contention)
- Each shard is independent; no cross-shard synchronization needed

**Tradeoffs:**
- ✅ Dramatically reduces lock contention on high-core systems
- ✅ Same algorithm, just partitioned
- ⚠️ Code complexity increases (32× lock management instead of 1)
- ⚠️ Memory overhead: 32× shard structs (manageable, ~32KB)
- ⚠️ If one PID generates all events, sharding doesn't help (but rare edge case)

**Risk Level:** MEDIUM — increased code complexity, must ensure no cross-shard race conditions

**Validation:** Profile before & after on high-core systems (16+ cores)

---

### Decision 4: Docker API for Container List (vs exec.Command)

**Context:**
- Current: `buildCache()` calls `dockerIDToInfo()` which spawns subprocess `exec.Command("docker", "ps", ...)`
- Issue: Subprocess fork/exec on every refresh cycle; already using Docker API elsewhere
- Parallel pattern: `asyncResolvePID()` already uses `r.cli.ContainerInspect()` API

**Decision:** Replace `exec.Command("docker ps")` with `r.cli.ContainerList()` API call

**Implementation:**
```go
// Before: subprocess fork
out, err := exec.Command("docker", "ps", "--filter", ...).Output()
// parse JSON manually

// After: direct Docker API
containers, err := r.cli.ContainerList(ctx, container.ListOptions{...})
// use container objects directly
```

**Rationale:**
- Docker client (`r.cli`) already exists in DockerResolver
- ContainerList API returns structured Go types (no parsing needed)
- No subprocess overhead (fork, exec, parsing, cleanup)
- Consistent with `asyncResolvePID()` which already uses API
- Docker daemon handles caching internally

**Tradeoffs:**
- ✅ No subprocess overhead
- ✅ Direct structured types (no JSON parsing)
- ✅ Consistent with rest of resolver code
- ✅ Faster in most cases
- ⚠️ Adds another Docker API call during refresh (but already async)
- ⚠️ Docker daemon might rate-limit if too many calls (acceptable; refresh is infrequent)

**Risk Level:** LOW — Docker API is stable, same pattern used elsewhere in codebase

---

## Summary Table

| Optimization | Allocation/Lock Saved | Complexity | Risk | Impact |
|---|---|---|---|---|
| Unsafe casting | binary.Read allocation | Low | Low | High (every event) |
| Struct keys | fmt.Sprintf string | Low | Low | High (file events) |
| Mutex sharding | Lock contention | Medium | Medium | High (multi-core) |
| Docker API | exec.Command fork | Low | Low | Medium (refresh only) |

**Expected Result:** 10K-50K events/sec sustained without GC pauses or mutex contention.

---

## Process Notes

**When to revisit:** After deploying and profiling under sustained load (>10K events/sec for >1 hour)
- Measure GC pause times before/after unsafe casting
- Profile lock contention on multi-core systems
- Verify Docker API doesn't introduce latency spikes

**Future optimizations** (if needed after profiling):
- Replace binary unmarshaling in other pipelines (e.g., detector rules)
- Pre-compile regex patterns instead of dynamic compilation
- Cache resolver results with longer TTLs during stable state
