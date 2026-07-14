# Performance

**Status:** Adequate in practice. Two REST-app load-test attempts (2026-07-13 health-ai,
2026-07-14 order-processor) both fell short of driving the agent to target throughput — see
attempts below. K8s-based event-performance testing is **paused**; next attempt (if any) is a
VM-based synthetic generator.

---

## Context — throughput was never the real problem

An earlier version of this doc framed the agent as a "production blocker" stuck at **146 events/s,
BLOCKED ON MEASUREMENT.** That framing was wrong and is retired. The agent looked blind not because
of throughput but because of a **type-mismatch bug**: `main.go` passed a `*pipeline.EnrichedEvent`
to `WorkloadResolver.Resolve()`, which type-switches only on `*processor.*` events → fell through
to `StateUnknown` for **every** event. Zero detection, on both runtimes. (Root cause writeup in
HANDOFF; memory `resolver-takes-processor-events`.)

Once that was fixed, throughput has **not** been a limiting factor in either Docker or DO K8s
validation. Several allocation/CPU optimizations were already applied along the way — unsafe-pointer
event deserialization, zero-allocation line scanning, and the async resolver worker pool (details in
`OPTIMIZATIONS_IMPLEMENTED.md` and `MICRO_OPTIMIZATIONS.md`).

---

## What we measure today

Per event source, a 10s ticker in `startEventReader` (`cmd/edr-monitor/main.go`) logs a coarse
throughput line to stdout:

```
DEBUG: <source> produced <N> events, resolved=<M> in last 10s
```

- **produced** — raw events read from that source's ring buffer in the window (counter resets every
  10s).
- **resolved** — delta of events that completed enrich → resolve in the window.
- A healthy window has `resolved` tracking `produced`. A large `produced ≫ resolved` gap means
  events are backing up (resolver saturation or a resolution stall). The same reader also tracks a
  `rawDropped` counter for ring-buffer overflow.

This is an eyeball counter, not a benchmark — there is **no CPU or latency measurement** wired in.

---

## Targets (not yet verified)

- **CPU:** 1–5% for the eBPF agent at steady state.
- **Throughput:** sustain **5k–20k events/s** without dropping.

---

## Open task — run a real performance test

No load test has been run to find the actual ceiling. To close this out:

1. Generate sustained event load (file / exec / network) at a **known** rate.
2. Measure agent process CPU under load, alongside the `produced` / `resolved` counter.
3. Watch for ring-buffer drops (`rawDropped`) and a growing `produced ≫ resolved` backlog.
4. Find the rate at which drops or backlog begin — that's the ceiling. Compare against the targets
   above.

Until this is done, treat throughput as **"fine in validation, unmeasured at scale."**

---

## Attempt: driving load via a real REST app (2026-07-13) — inconclusive, but instructive

Tried to generate the load in step 1 indirectly, by load-testing a real multi-service REST app
(healthcare-ai-microservices) deployed on a shared 2-node DO K8s cluster, and watching the
`resolved` counter respond. Result: **HTTP throughput and eBPF `net` event volume turned out to be
decoupled**, which is why this approach didn't close out the open task above — worth recording so
it isn't retried the same way.

- Pushed the app's real HTTP throughput from ~90 req/s to 440+ req/s over several iterations,
  fixing genuine bottlenecks along the way (DB connection pool size, Tomcat thread count, gateway
  CPU limit, client-side connection-pool exhaustion in the load generator itself).
- Despite a ~5x increase in HTTP req/s, the eBPF `net produced` counter stayed flat at **3–33
  events/10s** throughout — effectively background noise, not load-correlated.
- Root cause: connection pooling at every layer (Redis via Lettuce's single multiplexed
  connection, Postgres via HikariCP's fixed pool, the load generator's own keep-alive HTTP client)
  means a connection is established **once** and reused for thousands of requests. No new
  `connect()` syscalls happen per request, so the `lsm-connect.bpf.c` sensor has nothing new to see
  regardless of request rate.
- `file produced` events were the dominant signal (3.6k–8k/10s) but weren't isolated from
  JVM-internal background activity (GC, logging, class-loading) vs. genuine per-request load —
  inconclusive without further controlled comparison.

**Takeaway:** a realistic, well-built pooled-connection service is a poor way to drive the `net`
sensor's throughput test in step 1 — that's a property of good software, not a test bug. Closing
out this open task likely needs a **direct, controlled synthetic generator** (a small program that
triggers `execve`/`open`/`connect` at a known, deliberate rate) rather than indirect REST traffic
through a multi-service stack, regardless of which app generates that traffic.

---

## Attempt 2: driving load via order-processor (2026-07-14) — bottleneck fixed, still short of target

Second try at step 1, this time against `order-processor` (cloud-native-order-processor) on a
fresh DO K8s cluster, using an in-cluster DynamoDB emulator instead of real AWS DynamoDB to avoid
cost. Went further than Attempt 1 — found and fixed a real, reproducible throughput ceiling — but
the resulting load still isn't enough to hit the agent's target event rate.

- Fixed six real bottlenecks incrementally (single uvicorn worker, DynamoDB-emulator K8s resource
  limits, missing replica count, botocore/PynamoDB connection-pool size stuck at the default of 10,
  a redundant coin-price sync job running every 5 minutes across replicas). Throughput crept from
  ~50 to ~80 req/s — better, but still far below any useful load.
- Root cause of the remaining ceiling: **LocalStack itself**, not app code or K8s resources.
  LocalStack wraps a full multi-service Python API-gateway/router in front of DynamoDB even though
  only DynamoDB was ever used — that routing layer was the bottleneck no amount of app-level tuning
  could fix.
- Swapped LocalStack for `amazon/dynamodb-local` (AWS's own lightweight, DynamoDB-only emulator —
  same wire API, no Python proxy hop). Result: throughput jumped **~4x to ~300 req/s** (298.8-305.3
  req/s across repeated runs), average latency dropped from 400-1100ms to **~310ms**, zero pod
  restarts.
- Confirmed ~300 req/s is a real backend ceiling, not a client-concurrency limit: 4x'ing the
  load-generator's worker count (100 → 400) produced **no throughput gain** (305.3 vs 298.8 req/s),
  only added queueing — latency rose to 1212ms and a transient batch of 401s appeared under the
  extra queueing pressure.
- eBPF counters observed during this round: raw (`produced`) events typically ~20,368/10s,
  `resolved` ~1,668/10s. Best one-off sample seen (not sustained): 44,677/10s produced, 17,443/10s
  resolved.
- Target for this round was 50k produced/10s and 5k resolved/10s. Typical numbers run well short of
  both, and even the best one-off sample doesn't reliably clear the produced target — assessment is
  this app would need roughly **10x** more load than it can generate to close in on target.

**Takeaway:** order-processor's own backend ceiling (~300 req/s, set by the DynamoDB emulator +
app capacity, not by client concurrency) is well below what's needed to stress the agent to its
target throughput. Real REST-app load testing on K8s isn't going to close this out — **pausing**
K8s-based event-performance testing here. Next candidate, if picked back up: a direct synthetic
generator run in a VM instead of K8s.
