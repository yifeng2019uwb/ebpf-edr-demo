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

## What we measured

> **The instrumentation described here no longer exists.** The 10s throughput ticker was removed
> in the 2026-08-12 close-out along with the rest of the `DEBUG:` logging. The measurements below
> are kept as the record of what was actually observed; to reproduce them you would need to
> reinstate the counter in `startEventReader`. What remains at runtime is the one-line summary
> printed on shutdown.

Per event source, a 10s ticker in `startEventReader` (`cmd/edr-monitor/main.go`) logged a coarse
throughput line to stdout:

```
DEBUG: <source> produced <N> events, resolved=<M> in last 10s
```

- **produced** — raw events read from *that specific source's* ring buffer in the window (counter
  resets every 10s) — `file`, `process`, and `net` each have their own.
- **resolved** — delta of events that completed enrich → resolve in the window. Unlike `produced`,
  this counter (`resolvedEvents` in `main.go`) is a single `atomic.Int64` shared across all three
  readers, so the `resolved=` value printed on a `file`/`process`/`net` line is the **combined**
  total across all sources in that window, not that source's resolved count alone. In practice
  `file` is ~95% of traffic, so grepping just `file produced` lines is a reasonable proxy for
  overall load, but the paired `resolved=` number on those lines isn't file-only.
- A healthy window has `resolved` tracking `produced`. A large `produced ≫ resolved` gap means
  events are backing up (resolver saturation or a resolution stall). The same reader also tracks a
  `rawDropped` counter for ring-buffer overflow.
- **The 10s window is a logging/IO-saving batch interval, not a target unit.** Logging every event
  (or every second) would add its own I/O overhead, so counts are batched and printed once per 10s.
  All throughput *targets* in this doc are stated in events/**second** — divide the printed
  `produced`/`resolved` counts by 10 before comparing against a target (e.g. `produced 46865... in
  last 10s` = **~4,687 events/s**, not 46,865 events/s).

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
- eBPF counters observed during this round: raw (`produced`) `file` events typically ~20,368/10s
  (**~2,037/s**), paired `resolved` ~1,668/10s (**~167/s**) during steady ~300 req/s HTTP load. A
  short burst mid-run pushed `produced` as high as 46,865/10s (**~4,687/s**) — see sample window
  below. Note the highest `produced` and highest `resolved` values landed in **different** 10s
  windows, not the same one — read them as two separate peaks, not a single "44,677 produced /
  17,443 resolved" pairing. Also note (see "What we measure today" above): the log was grepped for
  `file produced` lines only, and the `resolved=` figure on those lines is the combined
  file+process+net total, not `file`'s resolved count alone — a reasonable proxy since `file` is
  ~95% of traffic, but not an exact per-source match to `produced`.
- **Target for this round was 50,000 produced events/s and 5,000 resolved events/s** — a rate, not
  a per-10s count (the DEBUG log's 10s window is just a batched-logging interval to save I/O, not a
  target unit — see "What we measure today" above). Converting the observed counts to per-second:
  typical steady state (~2,037/s produced) is roughly **~25x short** of the 50k/s target; even the
  best burst window (~4,687/s produced) is still roughly **~10.7x short**. Resolved's best observed
  window (~1,744/s, combined file+process+net — see note above) is roughly **~3x short** of the
  5,000/s target — actually closer to target than produced's shortfall, likely because it's summed
  across all three sources rather than being file-only. Assessment: this app would need roughly an
  order of magnitude (**~10x**) more *sustained* load than it reliably generates to close in on the
  produced target.

### Sample window (raw log, 2026-07-13 22:54:41–22:58:01 UTC)

```
DEBUG: file produced 5572 events, resolved=960 in last 10s
DEBUG: file produced 4972 events, resolved=1381 in last 10s
DEBUG: file produced 5658 events, resolved=2117 in last 10s
DEBUG: file produced 6870 events, resolved=5603 in last 10s
DEBUG: file produced 7318 events, resolved=6067 in last 10s
DEBUG: file produced 7597 events, resolved=5881 in last 10s
DEBUG: file produced 6342 events, resolved=3541 in last 10s
DEBUG: file produced 6710 events, resolved=3884 in last 10s
DEBUG: file produced 6127 events, resolved=4484 in last 10s
DEBUG: file produced 7214 events, resolved=6114 in last 10s
DEBUG: file produced 7375 events, resolved=5589 in last 10s
DEBUG: file produced 9183 events, resolved=12674 in last 10s
DEBUG: file produced 15308 events, resolved=17443 in last 10s
DEBUG: file produced 44677 events, resolved=8353 in last 10s
DEBUG: file produced 34479 events, resolved=5782 in last 10s
DEBUG: file produced 46865 events, resolved=7144 in last 10s
DEBUG: file produced 20224 events, resolved=1326 in last 10s
DEBUG: file produced 6626 events, resolved=452 in last 10s
DEBUG: file produced 7306 events, resolved=612 in last 10s
DEBUG: file produced 4551 events, resolved=398 in last 10s
DEBUG: file produced 4356 events, resolved=416 in last 10s
```

- **Steady state** (first 12 windows): `produced` 5-9k/10s, `resolved` tracking within roughly
  30-80% of `produced` — a normal, healthy-looking ratio at this rate.
- **Burst** (3 windows, ~30s): `produced` jumped to 44,677 → 34,479 → 46,865/10s while `resolved`
  fell to 8,353 → 5,782 → 7,144/10s — a clear `produced ≫ resolved` backlog, i.e. the resolver
  fell behind at this rate rather than keeping pace.
- **Recovery** (remaining windows): `produced` dropped back to the 4-20k/10s range and `resolved`
  tapered down further (down to 398-612/10s) as the burst source subsided and the backlog drained.
- Throughout this whole window — including the backlog spike — **the agent didn't crash or
  restart**, and `order-processor` itself stayed healthy with no added request latency (steady
  ~310ms avg at the time; see Attempt 2 above). That's a real, positive result at this load level:
  the agent absorbs a multi-second backlog under a produced burst and keeps draining it rather than
  wedging or crashing. (This log excerpt doesn't include the `rawDropped` counter, so it confirms
  no crash/hang under backlog, not zero ring-buffer drops during the burst.)

**Takeaway:** order-processor's own backend ceiling (~300 req/s, set by the DynamoDB emulator +
app capacity, not by client concurrency) is well below what's needed to stress the agent to its
target throughput. Real REST-app load testing on K8s isn't going to close this out — **pausing**
K8s-based event-performance testing here. What this round *did* establish: the agent handles
sustained load at the ~5-9k events/10s steady-state level cleanly, and even absorbs a ~45k/10s
burst without crashing — it just falls behind resolving during the burst rather than keeping pace.
Next candidate, if picked back up: a direct synthetic generator run in a VM instead of K8s, ideally
also checking the `rawDropped` counter to see whether backlog windows like the one above lose data.

---

## Open questions — resource budget, buffer sizing, latency tolerance (2026-07-14, unanswered)

Raised while reviewing the order-processor round above. Captured for later — no implementation
this round.

1. **What throughput should the 2-5% CPU/memory budget target on real hardware?** The existing
   target ("CPU: 1-5% for the eBPF agent at steady state") is a percentage, not tied to a concrete
   node size, so it doesn't say what throughput that budget should actually deliver. Example node
   sizes to pin this down against: **4 vCPU / 16Gi** or **2 vCPU / 8Gi** (roughly this project's
   DO K8s node class). Needs either a dedicated CPU-bound synthetic benchmark, or profiling the
   agent's CPU/memory during a controlled event-rate ramp, to answer "at 2-5% of a 4c/16Gi node,
   how many events/s can this agent actually resolve without falling behind?"
2. **Is the 64k raw : 32k resolved buffer ratio (2:1) right?** Current config:
   `rawChCap = 65536`, `enrichedChCap = 32768` (`cmd/edr-monitor/main.go:36-37`) — a 2:1 ratio.
   The *real observed* produced:resolved ratio during this round's K8s load test ran much higher
   than that: roughly **10:1 in steady state** (~2,037/s produced vs ~167/s resolved) and **~2.7:1
   even at the best resolved-catch-up window** (15,308 produced vs 17,443 resolved, one of the few
   windows where resolved actually exceeded produced, likely draining a prior backlog). Buffer
   ratio and processing-rate ratio aren't the same thing, but a buffer sized well below the real
   produced:resolved skew fills up (and starts blocking/dropping) sooner once a burst hits. Should
   the buffer ratio be widened toward that observed skew — proposed range **2-5x, maybe 4x** —
   rather than staying at 2:1?
3. **What's the max acceptable delay for a raw event sitting in the buffer?** At the target rate of
   **50,000 events/s** and a 64k-capacity raw buffer, worst-case queuing delay (buffer completely
   full, draining at zero) works out to **65536 / 50000 ≈ 1.3s**. Open question: is ~1.3s an
   acceptable detection-latency budget for this project, or too slow for what the agent is meant to
   catch? Separately — this doc's own **Targets** section above still says "sustain 5k-20k
   events/s," which doesn't match this round's stated 50k events/s target (2.5-10x higher). Worth
   reconciling which number is the actual target before optimizing buffer sizing around either one.
