// Package bpf handles loading and attaching eBPF programs to kernel hooks.
// Run `go generate ./pkg/bpf/` (or `make generate`) to rebuild the generated wrappers
// after modifying any .bpf.c file in kernel/.
//
// NOTE: go generate requires clang, llvm, and libbpf-dev installed on a Linux host.
// The generated *_bpf*.go files must be committed so CI can build without clang.
//
//go:generate go tool bpf2go -target bpfel -type exec_event -output-stem process -cflags "-I../../kernel -I/usr/include/bpf -D__TARGET_ARCH_x86" Proc ../../kernel/execsnoop.bpf.c
//go:generate go tool bpf2go -target bpfel -type file_event -output-stem file -cflags "-I../../kernel -I/usr/include/bpf -D__TARGET_ARCH_x86" Fs ../../kernel/lsm-file.bpf.c
//go:generate go tool bpf2go -target bpfel -type net_event -output-stem lsm -cflags "-I../../kernel -I/usr/include/bpf -D__TARGET_ARCH_x86" Sock ../../kernel/lsm-connect.bpf.c
package bpf
