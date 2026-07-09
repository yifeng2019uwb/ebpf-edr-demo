# Performance

**Status:** Adequate in practice; **no formal load test run yet** — targets below are unverified.

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
