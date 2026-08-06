# Design: Behavior Module (Baseline Normal, Score Deviations)

**Date:** 2026-08-05
**Status:** DRAFT — goal and scope only. Design work continues 2026-08-06.
**Relates to:** HANDOFF.md "Future ideas" (Behavioral & anomaly detection, exception scaling).

---

## 1. Goal

Add a second detection layer on top of the existing YAML rule engine: instead of only
matching fixed conditions, baseline what's normal per workload and score deviations from it.
Feeds from the LOW/info-level alert stream (already persisted to Supabase from both Docker VM
and DO K8s) rather than requiring new telemetry.

## 2. Scope

Covers behavior **for the MITRE techniques the rule engine already detects** — this is an
additional signal layer on existing coverage, not new threat coverage:

`T1059` (shell execution), `T1105` (ingress tool transfer), `T1613` (container/resource
discovery), `T1036` (masquerading), `T1552.001`/`T1552.004` (credentials/private keys),
`T1003.008` (OS credential dumping), `T1053.003` (scheduled task/cron), `T1082` (system info
discovery), `T1070.003` (clear command history), `T1041` (exfiltration over C2).

**Hard constraint: current eBPF hooks only.** No new kernel probes for this work — the input
is limited to what `execsnoop` (`exec_event`: pid/ppid/uid/mnt_ns_id/event_time/exec_path/
cgroup/has_tty/args), `lsm-file` (`file_event`: +f_mode/ret/comm/filename), and `lsm-connect`
(`net_event`: +dst_ip/dst_port/comm) already capture. If a behavior turns out to need a field
none of the three hooks provide, that's a separate, later decision (new hook = bigger,
separately-scoped change — see the Falco/Tetragon rule redesign's documented gaps in
`rules/*.yaml` for the same constraint already applied to the rule engine).

## 3. Non-goals

- Not general ML-based anomaly detection. Narrower: baseline observed patterns for known
  techniques, not learn arbitrary statistical normalcy.
- Not the "exception scaling" (per-image-digest learned trust) idea — related, but a separate
  design (see HANDOFF.md "Future ideas").
- Not a replacement for the YAML rule engine — an additional layer alongside it.

## 4. Input

The LOW/info-level alert stream — includes both naturally-LOW rules (`T1082`,
`T1070.003`) and the newly-added `service_unresolved_severity` downgrades (`T1059`/`T1105`/
`T1613` firing at LOW instead of CRITICAL/HIGH when the container's real service name isn't
resolved yet — see HANDOFF.md "Implemented but NOT yet live-validated"). Individually noisy,
low-confidence events are the intended raw material here, not something to filter out first.

## 5. Open questions (continue here 2026-08-06)

- What "normal" means per workload: keyed by resolved `service`, by container image, or both?
- What gets baselined first — process ancestry chains, file access patterns, network
  destinations — and in what order?
- Scoring approach: not yet decided; avoid committing to a specific statistical/ML method
  before the input shape (previous question) is settled.
- Where this runs: a separate service reading from Supabase (as HANDOFF.md's original framing
  assumed), or a component of the existing agent? Affects real-time vs. batch scoring.
