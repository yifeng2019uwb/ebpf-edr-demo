# eBPF EDR Demo — Makefile

KERNEL_DIR = kernel
BPF_SRC    = $(KERNEL_DIR)/execsnoop.bpf.c
BPF_OBJ    = $(KERNEL_DIR)/execsnoop.bpf.o

# Compile the eBPF kernel program to BPF bytecode
compile:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/bpf \
		-I./kernel \
		-c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "Compiled: $(BPF_OBJ)"
	@file $(BPF_OBJ)

# Run the full EDR pipeline: bpftrace kernel monitor → Python agent
run:
	sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("{\"pid\":%d,\"parent\":\"%s\",\"path\":\"%s\"}\n", pid, comm, str(args->filename)); }' | python3 agent/main.py

# Trigger a test alert — run this in a second terminal while 'make run' is active
test:
	@echo "Triggering test alert: execution from /tmp..."
	@cp /bin/ls /tmp/test_edr_ls && /tmp/test_edr_ls > /dev/null && rm /tmp/test_edr_ls
	@echo "Check Terminal 1 for the alert."

.PHONY: compile run test
