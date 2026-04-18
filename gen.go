//go:generate go tool bpf2go -tags linux -cflags "-I../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" process kernel/execsnoop.bpf.c
//go:generate go tool bpf2go -tags linux -cflags "-I../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" file kernel/opensnoop.bpf.c
//go:generate go tool bpf2go -tags linux -target amd64 -cflags "-I../bpf-developer-tutorial/src/third_party/vmlinux/x86 -I/usr/include/bpf" tcp kernel/tcpconnlat.bpf.c

package main
