# Environment Findings & Rule Improvement Notes

Observations from running the eBPF sensor across different environments.
Add findings here — do not change rules one-by-one without documenting WHY first.

---

## Environment Comparison

| Capability | GCP VM (GKE) | DO Droplet | DO App Platform |
|---|---|---|---|
| eBPF runs | ✅ | ✅ | ❌ no kernel access |
| Container identity (service/pod) | ❌ empty | ✅ resolved | N/A |
| `memlock` rlimit | ✅ | ✅ | ❌ operation not permitted |

---

## False Positives

### Spring Boot Actuator Health Checks

**Alert pattern:**
```
rule=T1059_unix_shell_execution comm=/bin/sh  level=CRITICAL
rule=T1105_ingress_tool_transfer comm=/usr/bin/wget  level=HIGH
```

**Cause:**
Docker `CMD-SHELL` health check runs:
`/bin/sh -c "wget -qO- http://localhost:PORT/actuator/health || exit 1"`
- `/bin/sh` spawn → triggers T1059 (shellBinaries match)
- `/usr/bin/wget` → triggers T1105 (networkBinaries match)

**Affected services:** auth-service, provider-service, ai-service, gateway

**Current workaround:** none — `sh` and `wget` not yet whitelisted

**Proposed fix options:**
1. Add `sh` + `wget` to `whitelistComm` — dev/staging only, broad suppression
2. Check ppid to confirm parent is Docker health check process — targeted but more code
3. Per-env whitelist config — cleaner long term

**Rule improvement needed:**
- Health check spawned shells should not alert — need parent process context
- `wget` to `localhost` (loopback) should not alert — need destination-aware filtering for process events (already done for lsm-connect)

---

## DO Droplet Findings

- Container identity (`service=`, `pod=`) resolved correctly from Docker labels
- GCP VM had empty `service` and `pod` fields — investigate why label detection differs
- eBPF loads cleanly on Ubuntu 24.04 kernel 6.8.0-71-generic with no config changes

---

## DOKS-Specific Findings

### Node-Level False Positives
DOKS Ubuntu nodes run system processes outside any pod namespace — these trigger `T1611_escape_to_host_ns`:

| Process | Reason | Action |
|---|---|---|
| `/sbin/fstrim` | DO node disk trim maintenance | Add to `unknownNsCommsWhitelist` |
| `exim4` | Mail transfer agent pre-installed on Ubuntu DOKS nodes | Add to `unknownNsCommsWhitelist` |

### Ring Buffer Errors
```
enrich: bad execsnoop event: EOF
```
eBPF ring buffer drops events intermittently on DOKS. Likely kernel version difference vs GKE.
- GKE uses `UBUNTU_CONTAINERD` image with eBPF-tuned kernel
- DOKS uses standard Ubuntu 24.04 — may need ring buffer size tuning
- Does not crash the agent — events resume after EOF

### No Native Log Console
DOKS has no built-in web log viewer (unlike GKE Cloud Logging).
Options: `kubectl logs`, forward to DO managed OpenSearch, or self-host Loki+Grafana.

### Validation Script Differences (validate-doks.sh vs validate-gke.sh)

| | GKE | DOKS |
|---|---|---|
| Alert sink | Cloud Logging (JSON payload) | Agent stdout (plaintext key=value) |
| Read method | `gcloud logging read` | `kubectl logs --since-time=<RFC3339>` |
| IP field name | `dst_ip=` | `dst=` (includes port, e.g. `8.8.8.8:80`) |

All 11 validation tests (V2–V12) pass on DOKS with these differences accounted for.

---

## To Investigate Later

- Why does DO Droplet resolve Docker container names but GCP VM did not?
- Add destination-aware filtering for `wget`/`curl` in process events (not just lsm-connect)
- Consider per-environment whitelist config file instead of hardcoded lists
- `env=` field is empty on DO Droplet — should be populated with `dev`/`staging`/`prod`
