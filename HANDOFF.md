# Project Handoff — Current Status

**Last Updated:** 2026-07-10
**Status:** ✅ Detection + response working and validated on DO K8s
(`./validate-do-k8s.sh` 11/11) and Docker VM (`validate.sh` 12/12). Alerts + LOW
telemetry persist to Supabase from both environments.

**Next:** trusted-application whitelist redesign (see **Active design** below) — currently
BLOCKING: the EDR DaemonSet is removed from DO K8s (it was killing cilium), and localstack
tripping kill_process blocks the order-processor load test.
For multi-step work: STOP after each step for user review before starting the next.

---

## Doc map — read these, don't re-derive from code

| Need | Source of truth |
|---|---|
| System architecture / pipeline | `docs/CURRENT_DESIGN.md` |
| Detection rules + policy layers (per-rule) | `docs/DETECTION-RULES-AND-POLICY.md` |
| Parent verification / ancestry cache | `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md` |
| MITRE technique table + responses | `docs/MITRE-COVERAGE.md` |
| Throughput / perf state + targets | `docs/PERFORMANCE.md` |
| Setup / build / deploy / validate / sinks | `docs/SETUP.md` |
| Open issues / next steps | this file |

**Ground truth (YAML rules + Go engine):** matching, severity, order, and `response:` are
declared in `rules/process.yaml` / `file.yaml` / `network.yaml` (per-sensor detections);
`rules/common.yaml` holds shared lists + Layer 1/2 config. `pkg/detector/yaml_detector.go` is
the engine (plus Go-only pipeline logic: ppid==1 skip, ancestry walk, telemetry);
`pkg/detector/response.go` executes responses. Resolver is `pkg/workload/`; sink/env config is
`internal/config/config.go`.

**Deploy flows:** health-ai `kubernetes/deploy.sh app` refreshes the `ebpf-alerts`
ConfigMap/Secret from this repo's `infra/.env` (`_ensure_ebpf_config`) and applies the local
DS manifest. The standalone `scripts/deploy-ebpf-k8s.sh` does the same but curls the manifest
from GitHub main — keep the two scripts' ConfigMap keys in sync.

**Hard constraints (also in CLAUDE.md):** never run git; never edit `.bpf.c`; never edit
`infra/.env` (secrets — user edits on the VM); no TODO / future-commitment comments.

---

## Active design — trusted-application whitelist (agreed direction, NOT yet built)

**Problem (confirmed on the VM 2026-07-10).** The current `customer_applications` whitelist
matches on **comm** (`comm_base_in` → `filepath.Base(comm)`). comm is the binary/interpreter,
not the app: localstack reads its own TLS cert (`/var/lib/localstack/cache/server.test.pem.key`)
with `comm=python`, so `T1552_004` fires and `kill_process` SIGKILLs it. Adding `localstack` to
`customer_applications` does nothing — comm is `python`, never `localstack`. Same class of bug
killed cilium on K8s (comm=cilium-agent reading its Hubble `server.key`).

**Agreed model: trusted app = identify by SERVICE, allow only KNOWN actions.** Not blanket
trust. Two parts combined:
1. **Identity by resolved service, not comm.** The alert already carries the stable
   `service=localstack` (resolved workload identity). comm can't identify an app; service can.
2. **Scoped to expected actions.** A trusted service is exempted only for its *known* behaviors
   (e.g. localstack: read its own `*.pem/.key` under `/var/lib/localstack/`, connect out to
   AWS). Anything outside the profile (localstack spawning a shell, reading `/etc/shadow`) still
   alerts. This keeps monitoring on a trusted-but-compromised app.

**Options weighed (for the eventual build):**
- A — global service skip (`trusted_services` → skip ALL detection): simplest, but too coarse
  (blanket trust, no monitoring if compromised). Rejected as the whole answer.
- B — per-rule `service_in` exception: reuses the existing, tested `service_in` primitive
  (T1041 already uses it); needs `service` populated into file/process `matchInput` (currently
  only network sets it). This is the mechanism for "scoped to known actions".
- C — path exception (add `/var/lib/localstack/` to an exclude list, like `pem_exclude_paths`):
  narrowest, but whack-a-mole per app and ignores the network alerts.

Direction = **B as the mechanism, expressed as a per-service action profile** (service +
its allowed actions/paths). Design the profile shape before coding — do NOT quick-patch.

**Out of scope for this change (separate issue): cilium.** It resolved to
`service=k8s-pod-<hash>` with empty namespace (resolver can't identify kube-system pods before
CNI is up), so no service/name whitelist reliably catches it. Needs a namespace-resolution fix.

---

## Plan — next steps

1. **K8s load test — via the order service.** health-ai is unsuitable for load testing
   (each account needs manual creation work); order service goes on the SAME DO cluster,
   own namespace. Scope agreed (2026-07-10): core 5 services only (gateway, auth, user,
   order, inventory — no frontend/insights), in-cluster LocalStack DynamoDB + Redis
   (mirrors the local compose design, no AWS), nothing else in the repo changes.
   **DEPLOYED 2026-07-10** to DO cluster (`kubernetes/do/`): all 5 services + redis +
   localstack `1/1 Running`, gateway public at **http://209.38.174.3:8080** (`/health` OK).
   Node pool resized 1→2 (`s-2vcpu-4gb`) — one node couldn't fit both stacks. Fixes made
   during bring-up: `enableServiceLinks: false` on all 5 (K8s injected `GATEWAY_PORT=tcp://…`
   which the Go gateway read as its port → crash); localstack mem limit 1→2Gi (OOM exit 247);
   gateway Service is `type: LoadBalancer` (matches health-ai). Images built on the VM
   (buildx segfaults under QEMU on the ARM Mac), pushed to ghcr, packages set public.
   Remaining: DynamoDB tables NOT yet created (deploy.sh timed out before table-init — rerun
   `./deploy.sh` now that localstack is up); then the load test per `docs/PERFORMANCE.md`:
   baseline → ramp load → find per-source ceiling (watch `rawDropped`/`enrichedDropped`/
   `alertDropped` + `produced≫resolved` backlog + agent CPU) → `validate-do-k8s.sh`
   under peak load → soak for memory growth.
   **BLOCKED on:** the trusted-app whitelist redesign above — the EDR agent must go back on
   the cluster before any load test, but redeploying it as-is re-kills cilium + localstack.
2. **Activate `block_ip` kernel side — AFTER the load test** (active blocking would skew
   test traffic). Needs `lsm-connect.bpf.c` map uncomment + `go generate` on the Linux VM
   (documented activation path in `pkg/detector/response.go`) — the sanctioned exception
   to the no-BPF-edits rule. validate.sh T4's block-verification steps (bpftool flush,
   EPERM checks) are already in place and become meaningful once this lands.
3. **Opportunistic, no schedule:** items in Deferred / known issues below.

---

## Deferred / known issues (documented, none blocking)

- **`block_ip` kernel side not compiled** (= plan item 2). T1041 declares
  `response: block_ip` but the `blocked_ips` LPMTrie map in `kernel/lsm-connect.bpf.c` is
  commented out — responder skips with a log line (alert-only in practice).
- **`validate.sh` T1611 overlay test out.** Blocked on the disabled T1611
  host-reads-container-overlay rule and its allowlist design; the rule's data
  (`container_fs_paths`) stays in common.yaml.
- **Docker container cache never evicts.** `listenDockerEvents()` is disabled in
  `DockerResolver.Start()` — its reconnect/recovery path had unresolved issues and is hard to
  test without a scriptable Docker daemon. Cache-cleanup (and `lightweightRefresh()`) lived
  only there, so `r.cache`/`r.containerToNs` only grow. Not a correctness problem — containers
  are still discovered on-demand via `asyncResolvePID` — just a slow memory/staleness leak.
- **File-dedup shard maps never evict.** `fileDedupShards_array` (main.go) has no sweep — the
  cleanup worker only sweeps the ancestry cache — so entries ({pid, filename} → time) accumulate
  forever. Tiny entries, slow growth; same class as the Docker cache leak. Fix is a periodic
  sweep dropping entries older than `fileDedupWindow`.
- **`network_init.go` privateNets is dead code** — populated (SERVICE_CIDR/GKE CIDR) but never
  read; the YAML `private_ranges` list is the real check. Remove or wire when touched next.
- **EDR DaemonSet removed from DO K8s (2026-07-10).** `kubectl -n kube-system delete ds ebpf-edr`
  — it was SIGKILLing cilium (T1552_004 on cilium's Hubble `server.key`), so a fresh node's
  cilium never bootstrapped and the node's `agent-not-ready` taint never cleared, blocking all
  scheduling. Image was `ghcr.io/yifeng2019uwb/ebpf-edr:latest`. Re-add (health-ai
  `deploy.sh` or `scripts/deploy-ebpf-k8s.sh`) ONLY after the trusted-app whitelist fix +
  image rebuild, else it re-kills cilium on the next Hubble cert rotation.
- **cilium namespace resolution.** kube-system pods can resolve to `service=k8s-pod-<hash>`,
  empty namespace (resolver needs CNI that cilium itself provides — chicken/egg on a cold
  node), so `ignore_namespaces: [kube-system]` doesn't catch them. Blocks reliably trusting
  cilium; see Active design "out of scope" note.

**Dedup gotcha (keep in mind when touching the enricher):** `fileDedupKey` is {Pid, Filename}
— deliberately no comm (sensor comm is the THREAD name; including it caused double alerts).
`runc:[…]` events are excluded from the dedup map: runc reads /etc/passwd + /etc/group during
docker-exec setup and then execs the target under the SAME pid, so recording them would
dedup-shadow the target's own first read (T1082 missed `cat /etc/passwd`).

---

## Future initiative: Behavioral & Anomaly Detection

Add threat detection from historical alert data in Supabase: baseline normal behavior, detect
anomalies (unusual process chains, abnormal file access, unexpected connections), score
deviations rather than only matching YAML rules. The LOW telemetry stream (off the dashboard,
persisted to file + Supabase) is this service's input. Design and implementation not started;
persistence infrastructure is ready — Supabase now receives from both Docker VM and DO K8s.
