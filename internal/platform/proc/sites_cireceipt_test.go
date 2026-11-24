// SPDX-License-Identifier: Apache-2.0

package proc

func init() {
	startSites = append(startSites,
		startSite{file: "internal/check/cireceipt/cosign.go", fn: "runCosign", call: "proc.Start", n: 1, rel: guarded, when: "shared pinned verifier start; Start refuses unexpected armed callers"},
		startSite{file: "internal/check/cireceipt/cosign.go", fn: "CosignVerifier.verify", call: "cireceipt.runCosign", n: 1, rel: beforeArm, when: "receipt reader only, in a process that holds no fanotify group"},
	)
}
