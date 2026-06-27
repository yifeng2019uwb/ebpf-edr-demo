# ebpf-edr-demo — Claude Instructions

## NOT COMMIT FOR ME
Never run `git add`, `git commit`, or `git push`. Write files and stop.
The user reviews all changes and commits themselves.

## Do not change .bpf.c files
All detection and policy logic belongs in Go. BPF C files are sensors only.
Changing `.bpf.c` requires a Linux rebuild on the GCP VM — avoid unless truly necessary.
Current files are correct scope:
- `kernel/execsnoop.bpf.c` — process events, no changes needed
- `kernel/opensnoop.bpf.c` — file events, possibly ENOENT (deferred decision)
- `kernel/lsm-connect.bpf.c` — network events, no changes needed

## Think before coding
Read HANDOFF.md first. Discuss design before writing any code.

## No TODO comments in personal projects
This is a personal learning project, not a production product. Never use TODO/FIXME/NOTE comments implying future commitment.
Instead, use plain comments explaining current state or design rationale.

Examples:
- ❌ `// TODO: Add AWS support` 
- ✅ `// AWS support (design ready, not yet validated)`
- ❌ `// FIXME: optimize this later`
- ✅ `// currently sequential, could parallelize if needed`

Be honest about scope: design can be extensible, but don't promise future work in a learning project.
