package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// deployAgentIdentities returns the IAM member strings for all eBPF agent SAs.
// Pass the result directly into IAMBinding.Members in base.go.
//
// To add a new environment: add its SA member string to the returned array
// and run pulumi up — base.go picks it up automatically.
//
// GCP-native environments (GCP VM, GKE): use compute/workload-identity SA — no key file needed.
// Non-GCP environments: require a dedicated SA with key file — see legacy/infra/oracle-agents.go
// for the pattern used for the former Oracle VMs (terminated 2026-06-06).
//
// Note: sensor VM IAM is managed separately in sensor.go (deploySensor),
// only provisioned when sensorEnabled=true. No entry needed here.
func deployAgentIdentities(ctx *pulumi.Context) (pulumi.StringArray, error) {

	// GCP Compute VM running Docker (cloud-native-order-processor, OpenClaw project)
	gcpDockerVMSA := pulumi.String("serviceAccount:323172929342-compute@developer.gserviceaccount.com")

	// GKE Workload Identity SA (order-processor-sa, bound via K8s ServiceAccount)
	// Commented out — SA is deleted when GKE cluster is destroyed.
	// Uncomment when running: make test-env-up
	// gkeWorkloadSA := pulumi.String("serviceAccount:order-processor-sa@" + project + ".iam.gserviceaccount.com")

	return pulumi.StringArray{
		gcpDockerVMSA,
		// gkeWorkloadSA, // add back when GKE is running (make test-env-up)
	}, nil
}
