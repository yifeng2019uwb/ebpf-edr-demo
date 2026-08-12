# kernel/ — eBPF Kernel Programs

Three eBPF programs that run in the Linux kernel and capture security events.

## Programs

**execsnoop.bpf.c** — Process Execution
- Hook: `sys_enter_execve`
- Captures: Process ID, parent ID, command, working directory
- Detects: Shell spawn, tool execution, script invocation

**lsm-file.bpf.c** — File Access
- Hook: `lsm.s/file_open` (LSM = Linux Security Module), plus `do_sys_openat2`
  kprobe/kretprobe for the denial path (opens that fail with -EACCES/-EPERM)
- Captures: File path, process ID, open mode, return code
- Detects: Credential access (/etc/shadow), SSH keys, configuration files
- Replaced the retired `opensnoop.bpf.c`, which hooked `sys_enter_openat` and so missed
  busybox/Alpine's direct `SYS_open` calls. The LSM hook fires for every open variant —
  open, openat, openat2, io_uring.

**lsm-connect.bpf.c** — Network Connections
- Hook: `lsm/socket_connect`
- Captures: Destination IP, destination port, process ID
- Detects: External connections, data exfiltration, C2 communication

## How They Work

Each program:
1. Reads event data from kernel context
2. Publishes to a ring buffer (lock-free, efficient)
3. Userspace reads ring buffer and processes events

## Building

Requires Linux with clang + BPF headers. Run on Linux VM only:

```bash
make generate        # Compiles .bpf.c → .o + Go wrappers
```

Generated files go to `pkg/bpf/`:
- `*_bpfel.go` — Go wrappers, **committed to git**
- `*.o` — compiled BPF objects, **gitignored**, embedded into the binary at build time

Because the `.o` files are not committed, a fresh clone cannot build or vet
`cmd/edr-monitor` until `make generate` has run on a Linux host with clang. This is why
`make vet` excludes `cmd/`.

## Limitations

- `block_ip` is not active at all — the `blocked_ips` LPMTrie in `lsm-connect.bpf.c` is
  commented out, so network responses are alert-only. Activation steps are in
  `pkg/detector/response.go`.
- No IPv6 blocking (blockIP only supports IPv4)
- Network events carry no L4 protocol, so TCP and UDP cannot be distinguished
- LSM hooks require kernel 5.8+
- Some distros disable LSM hooks in config
- BPF verifier limits on instruction complexity

## Extending

To add new detection:
1. **If kernel event needed**: Add eBPF hook to .bpf.c
2. **If parsing kernel data**: Update event struct
3. **If no new kernel event needed**: Just add YAML rule

Most detections can be done in YAML without changing C code.

---

**Last Updated:** 2026-08-12
