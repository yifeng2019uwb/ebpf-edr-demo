# Critical Issues — Production Blockers

**Status:** ❌ Not production-ready

Without resolving these issues, this project is a toy. These are **must-fix** before any real deployment.

---

## Issue 1: Performance Bottleneck

**Symptom:**
- Current: 146 events/sec sustained
- Target: 1000+ events/sec (2% CPU budget)
- Gap: 30x too slow

**Impact:**
- During `docker deploy`: rawCh overflows, events dropped
- System cannot sustain realistic workload (1500+ file events/sec)
- eBPF collection capability wasted

**Root Cause:**
- Unknown. Likely lock contention, but unconfirmed.
- Need to measure: resolver locks? dedup locks? channel send? parsing?

**Status:** 🔴 **BLOCKED ON MEASUREMENT**
- Must add debug timing to identify bottleneck
- Cannot optimize without data

---

## Issue 2: Resolution Correctness Under Load

**Symptom:**
- Idle: 146 events/sec, zero errors
- Under load: unknown (not tested)

**Impact:**
- Are events being resolved correctly during bursts?
- Are pending events escalating to unknown too early?
- Cache behavior under contention?

**Status:** 🔴 **NOT TESTED**
- Must run docker deploy and verify resolution accuracy
- Must check alert correctness during bursts

---

## Issue 3: False Positives from Snap/Systemd

**Symptom:**
- Transient processes in namespace 4026532345 (snap/systemd)
- Previously: 100+ false CRITICAL alerts per docker operation
- Now: suppressed by `runtime=docker + state=unknown` logic

**Status:** 🟡 **PARTIALLY FIXED**
- Need production validation with docker deploy
- Need to verify no real escapes are being missed

---

## Next Steps (Priority Order)

1. **Measure performance bottleneck**
   - Add debug timing to enricher
   - Identify which component is slow
   - Collect data, don't change code yet

2. **Run docker deploy with measurement**
   - Test under realistic load
   - Validate resolution accuracy
   - Verify false positives are suppressed

3. **Analyze data + confirm correctness**
   - Match performance data with correctness validation
   - Identify root cause of bottleneck
   - Verify no regressions

4. **Optimize only after understanding**
   - Based on data, fix the real bottleneck
   - Ensure correctness maintained
   - Re-test under load

---

## Definition of "Production Ready"

- ✅ Handles 1000+ events/sec at <5% CPU
- ✅ Resolution accuracy validated under load
- ✅ False positive rate acceptable (<1% noise)
- ✅ No event loss during bursts
- ✅ Metrics show correct behavior
