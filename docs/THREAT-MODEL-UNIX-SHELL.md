# Threat Model — T1059.004 Unix Shell Execution

Shell execution is the hardest of our detections to get right: `bash`/`sh` runs constantly in
legitimate containers, so the shell itself is not the signal. This records why context decides,
and what that implies for the design. Field decisions for the exec sensor live in
EXECVE-EVENT-DESIGN.md; the fix direction is the trusted-app whitelist in HANDOFF.md.

---

## The problem: shell execution is normal

The same shell exec is benign or malicious depending on context, not on the binary:

| Context | Who ran it | Doing what | Verdict |
|---|---|---|---|
| Build / CI | build tooling | install/build commands | benign |
| Health check | the app itself | one-shot probe command | benign |
| RCE | a web server | download-and-pipe-to-shell | malicious |
| Interactive backdoor | a remote session | interactive shell | malicious |
| Malware stage | an unknown binary | decode-and-run an obfuscated payload | malicious |

"A shell ran in a container" cannot be the whole signal — it fires on every build and health
check. What separates malicious from benign is **which service ran it, from what parent, doing
what** — identity and context, not the shell binary.

---

## Real attack cases

The malicious rows are not hypothetical:

- **VShell (2025).** A downloader shell-execs an obfuscated payload, fetches a second-stage ELF,
  and runs it in memory masquerading as a kernel thread.
- **Hildegard (K8s cryptojacking).** Initial RCE pipes a downloader into a shell; the malware then
  spawns shells to enumerate the cluster and exfiltrate the service-account token.
- **Legitimate build (the false-positive foil).** CI runs a shell to install dependencies — the
  same `bash -c` exec, entirely benign.

They share a shape: the malicious ones are an *unexpected* service/parent running a shell that
does something out of profile; the benign ones are an expected service doing expected work.

---

## Implication for the design

The discriminator is **service identity + expected behavior** — exactly the trusted-app whitelist
(HANDOFF Active design): identify the workload by resolved service, and alert when it steps
outside its known-good actions. Matching more on the exec event itself does not separate a CI
shell from an RCE shell; only knowing "this service is not supposed to spawn a shell" does.

So T1059 is a **know-the-service-and-its-profile** problem, not a **capture-more-exec-fields**
problem. The sensor's job is to carry the identity inputs (service via the resolver, parent via
the ancestry walk); the decision lives in the whitelist. This is why the exec field scope in
EXECVE-EVENT-DESIGN.md excludes args and capabilities — no rule, including this one, consumes them.

---

## Sources

- [VShell campaign](https://www.picussecurity.com/resource/blog/t1059-004-unix-shell)
- [Hildegard K8s cryptojacking](https://www.sysdig.com/blog/indicators-compromise-kubernetes)
- [Container escape techniques](https://unit42.paloaltonetworks.com/container-escape-techniques/)
- [MITRE T1059.004](https://attack.mitre.org/techniques/T1059/004/)
