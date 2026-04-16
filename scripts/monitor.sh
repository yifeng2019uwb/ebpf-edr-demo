#!/bin/bash
# monitor.sh — attach eBPF tracepoint to execve syscall and pipe events to the Python agent

sudo bpftrace -e '
tracepoint:syscalls:sys_enter_execve {
    printf("{\"pid\":%d,\"parent\":\"%s\",\"path\":\"%s\"}\n",
        pid, comm, str(args->filename));
}' | python3 agent/main.py
