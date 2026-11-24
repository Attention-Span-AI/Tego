// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/attention-span-ai/tego/internal/runscope"

// membershipLine is the line doctor prints about this process's own run-membership answer (selfAnswer, ADR 0100
// item (7)): the answer laid out by runscope.Describe, with the seccomp mode the rule recorded outside the kernel's
// first cgroup namespace. The mode is a fact for whoever reads the line, never a condition of the answer (the
// signed rule's fact 4c is removed: under WSL's mirrored networking every ordinary shell carries a filter). It is
// "" for an outside answer that recorded nothing, so ordinary Linux in the first cgroup namespace prints nothing
// new. Doctor decides nothing on it.
func membershipLine(a runscope.Answer) string {
	d := runscope.Describe(a)
	if a.Outside() && d.Seccomp == "" {
		return ""
	}
	return "run membership (this process): " + d.String()
}
