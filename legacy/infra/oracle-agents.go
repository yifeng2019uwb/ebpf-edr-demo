// LEGACY — Oracle Cloud Free Tier account terminated 2026-06-06.
// All Oracle VMs (VM1: 163.192.46.25, VM2: 163.192.30.193) deleted.
// This file is kept for reference if Oracle Cloud VMs are used again.
//
// To re-enable: copy this code back into infra/agents.go and add
// oracleSAMember to the returned StringArray in deployAgentIdentities.

package main

// Oracle Cloud VMs (VM1: gateway+auth, VM2: provider+ai) — shared GCP SA.
// Key deployed via: EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh
// Key retrieved after pulumi up: pulumi stack output oracleAgentKey --show-secrets
//
// func deployOracleAgentSA(ctx *pulumi.Context) (pulumi.StringOutput, error) {
// 	oracleSA, err := serviceaccount.NewAccount(ctx, "healthcare-oracle-agent", &serviceaccount.AccountArgs{
// 		AccountId:   pulumi.String("healthcare-oracle-agent"),
// 		DisplayName: pulumi.String("Healthcare Oracle VM eBPF agent (VM1 + VM2)"),
// 		Project:     pulumi.String(project),
// 	})
// 	if err != nil {
// 		return pulumi.StringOutput{}, err
// 	}
//
// 	oracleKey, err := serviceaccount.NewKey(ctx, "healthcare-oracle-agent-key", &serviceaccount.KeyArgs{
// 		ServiceAccountId: oracleSA.Name,
// 	})
// 	if err != nil {
// 		return pulumi.StringOutput{}, err
// 	}
// 	ctx.Export("oracleAgentKey", pulumi.ToSecret(oracleKey.PrivateKey))
//
// 	return oracleSA.Email.ApplyT(func(e string) string {
// 		return "serviceAccount:" + e
// 	}).(pulumi.StringOutput), nil
// }
