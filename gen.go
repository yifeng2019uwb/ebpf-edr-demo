//go:generate go tool bpf2go -tags linux -cflags "-I../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" process kernel/execsnoop.bpf.c
//go:generate go tool bpf2go -tags linux -cflags "-I../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" file kernel/opensnoop.bpf.c
//go:generate go tool bpf2go -tags linux -cflags "-I../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" exit kernel/exitsnoop.bpf.c
//go:generate go tool bpf2go -tags linux -cflags "-I../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" lsm kernel/lsm-connect.bpf.c

package main
