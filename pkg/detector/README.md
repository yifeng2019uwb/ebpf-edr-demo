# pkg/detector — Detection Engine & Response

Evaluates the declarative rules against enriched kernel events, issues alerts with a severity,
and executes the rule's requested response where one is set.

## What it does

- Receives enriched events (process, file, network — each carrying workload identity)
- Matches them against the declarative rules, ordered by severity; first match wins
- Issues an alert with a severity and, when the rule sets one, a response action
- Executes response actions (e.g. kill a process, block an address)

## Key idea

Rules are data (YAML); the engine is code. Match conditions, severity, order, exceptions, and
responses live in the rules — the engine hardcodes no per-rule policy, so tuning a detection
needs no code change.

## See also

- Detection model and policy layers — [docs/DETECTION-RULES-AND-POLICY.md](../../docs/DETECTION-RULES-AND-POLICY.md)
- Parent verification / ancestry — [docs/DESIGN-PROCESS-ANCESTRY-CACHE.md](../../docs/DESIGN-PROCESS-ANCESTRY-CACHE.md)
