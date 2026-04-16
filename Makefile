# eBPF EDR Demo — Makefile

KERNEL_DIR = kernel
BPF_SRC    = $(KERNEL_DIR)/execsnoop.bpf.c
BPF_OBJ    = $(KERNEL_DIR)/execsnoop.bpf.o

# Compile the eBPF kernel program to BPF bytecode
compile:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/bpf \
		-I../bpf-developer-tutorial/third_party/vmlinux/x86 \
		-c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "Compiled: $(BPF_OBJ)"
	@file $(BPF_OBJ)

# Run the full EDR pipeline: bpftrace kernel monitor → Python agent
run:
	sudo bpftrace -f json -e ' \
	tracepoint:syscalls:sys_enter_execve { \
		printf("{\"pid\":%d,\"parent\":\"%s\",\"path\":\"%s\"}\n", \
			pid, comm, str(args->filename)); \
	}' | python3 agent/main.py

# Trigger a test alert by executing a binary from /tmp
test:
	@echo "Triggering test alert: execution from /tmp..."
	cp /bin/ls /tmp/test_edr_ls
	/tmp/test_edr_ls /tmp
	rm /tmp/test_edr_ls
	@echo "Check alerts/alert.log for the triggered alert."

.PHONY: compile run test
