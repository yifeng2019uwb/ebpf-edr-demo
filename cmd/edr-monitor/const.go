package main

import "ebpf-edr-demo/pkg/workload"

const (
	// defaultRuntime is the runtime to use if -runtime flag is not provided
	defaultRuntime = string(workload.RuntimeDocker)

	// validRuntimes lists supported runtimes for flag help text
	validRuntimes = "docker|k8s"

	// Log names for event readers (used in error logging)
	logNameProcess = "process"
	logNameFile    = "file"
	logNameNet     = "net"

	// Rules file path
	rulesFilePath = "rules/default.yaml"

	// Environment names
	envGCP = "gcp"
)
