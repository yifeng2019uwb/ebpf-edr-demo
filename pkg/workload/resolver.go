//go:build linux

package workload

import "os"

func NewResolver(runtime string) WorkloadResolver {
	node, _ := os.Hostname()
	region := os.Getenv("REGION")

	switch runtime {
	case "k8s":
		return &K8sResolver{node: node, region: region}
	default:
		return &DockerResolver{node: node, region: region}
	}
}
