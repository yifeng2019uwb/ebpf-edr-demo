# ebpf-edr-demo — Claude Instructions

## NOT COMMIT FOR ME
Never run `git add`, `git commit`, or `git push`. Write files and stop.
The user reviews all changes and commits themselves.

## Do not change .bpf.c files
All detection and policy logic belongs in Go. BPF C files are sensors only.
Changing `.bpf.c` requires a Linux rebuild with clang — no longer available, the project is
archived (see HANDOFF.md). Current files and their hooks:
- `kernel/execsnoop.bpf.c` — process events, `tracepoint/syscalls/sys_enter_execve`
- `kernel/lsm-file.bpf.c` — file events, `lsm.s/file_open` + `do_sys_openat2` k/kretprobes
  (the denial path). Replaced the retired `opensnoop.bpf.c`.
- `kernel/lsm-connect.bpf.c` — network events, `lsm/socket_connect`

## Think before coding
Read HANDOFF.md first — it records why the project stopped and what is knowingly unfixed.
Discuss design before writing any code.

## No live test environment
There is no cluster or VM to validate against any more. Changes that alter runtime behaviour
under load cannot be verified here, so prefer documenting a gap over "fixing" it blind.
Compiler, `go vet`, and unit tests are the whole verification budget.

## No TODO comments in personal projects
This is a personal learning project, not a production product. Never use TODO/FIXME/NOTE comments implying future commitment.
Instead, use plain comments explaining current state or design rationale.

Examples:
- ❌ `// TODO: Add AWS support` 
- ✅ `// AWS support (design ready, not yet validated)`
- ❌ `// FIXME: optimize this later`
- ✅ `// currently sequential, could parallelize if needed`

Be honest about scope: design can be extensible, but don't promise future work in a learning project.
