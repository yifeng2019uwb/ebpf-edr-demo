package main

import (
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/serviceaccount"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// deployAgentIdentities returns the IAM member strings for all eBPF agent SAs.
// Pass the result directly into IAMBinding.Members in base.go.
//
// To add a new environment: add its SA member string to the returned array
// and run pulumi up — base.go picks it up automatically.
//
// GCP-native (GCP VM, GKE): use compute/workload-identity SA — no key file needed.
// Non-GCP (Oracle VMs):     dedicated SA with key file — created as Pulumi resource.
func deployAgentIdentities(ctx *pulumi.Context) (pulumi.StringArray, error) {

	// ── GCP-native agents ─────────────────────────────────────────────────────

	// GCP Compute VM running Docker (cloud-native-order-processor)
	gcpDockerVMSA := pulumi.String("serviceAccount:323172929342-compute@developer.gserviceaccount.com")

	// GKE Workload Identity SA (order-processor-sa, bound via K8s ServiceAccount)
	gkeWorkloadSA := pulumi.String("serviceAccount:order-processor-sa@" + project + ".iam.gserviceaccount.com")

	// ── Non-GCP agents ────────────────────────────────────────────────────────

	// Oracle Cloud VMs (VM1: gateway+auth, VM2: provider+ai) — shared SA.
	// Key deployed via: EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh
	// Key retrieved after pulumi up: pulumi stack output oracleAgentKey --show-secrets
	oracleSA, err := serviceaccount.NewAccount(ctx, "healthcare-oracle-agent", &serviceaccount.AccountArgs{
		AccountId:   pulumi.String("healthcare-oracle-agent"),
		DisplayName: pulumi.String("Healthcare Oracle VM eBPF agent (VM1 + VM2)"),
		Project:     pulumi.String(project),
	})
	if err != nil {
		return nil, err
	}

	oracleKey, err := serviceaccount.NewKey(ctx, "healthcare-oracle-agent-key", &serviceaccount.KeyArgs{
		ServiceAccountId: oracleSA.Name,
	})
	if err != nil {
		return nil, err
	}
	ctx.Export("oracleAgentKey", pulumi.ToSecret(oracleKey.PrivateKeyData))

	oracleSAMember := oracleSA.Email.ApplyT(func(e string) string {
		return "serviceAccount:" + e
	}).(pulumi.StringOutput)

	return pulumi.StringArray{
		gcpDockerVMSA,
		gkeWorkloadSA,
		oracleSAMember,
	}, nil
}
