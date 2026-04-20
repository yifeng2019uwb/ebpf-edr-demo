// Package bpf handles loading and attaching eBPF programs to kernel hooks.
// Run `go generate ./pkg/bpf/` (or `make generate`) to rebuild the generated wrappers
// after modifying any .bpf.c file in kernel/.
//
// NOTE: go generate requires clang, llvm, and libbpf-dev installed on a Linux host.
// The generated *_bpf*.go files must be committed so CI can build without clang.

//go:generate go tool bpf2go -tags linux -cflags "-I../../../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" process ../../kernel/execsnoop.bpf.c
//go:generate go tool bpf2go -tags linux -cflags "-I../../../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" file ../../kernel/opensnoop.bpf.c
//go:generate go tool bpf2go -tags linux -cflags "-I../../../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" lsm ../../kernel/lsm-connect.bpf.c

package bpf
