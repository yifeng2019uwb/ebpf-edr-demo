//go:generate go tool bpf2go -tags linux process kernel/execsnoop.bpf.c
//go:generate go tool bpf2go -tags linux network kernel/networkmonitor.bpf.c
//go:generate go tool bpf2go -tags linux file kernel/opensnoop.bpf.c

package main