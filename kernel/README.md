# kernel/ — eBPF Kernel Programs

Three eBPF programs that run in the Linux kernel and capture security events.

## Programs

**execsnoop.bpf.c** — Process Execution
- Hook: `sys_enter_execve`
- Captures: Process ID, parent ID, command, working directory
- Detects: Shell spawn, tool execution, script invocation

**opensnoop.bpf.c** — File Access
- Hook: `lsm/file_open` (LSM = Linux Security Module)
- Captures: File path, process ID, open flags
- Detects: Credential access (/etc/shadow), SSH keys, configuration files

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

Generated files go to `pkg/bpf/` (committed to git):
- `*_bpfel.go` — Go wrappers with embedded .o binaries
- Ready to deploy without clang

## Limitations

- No IPv6 blocking (blockIP only supports IPv4)
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

**Last Updated:** 2026-06-30
