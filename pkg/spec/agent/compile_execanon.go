// SPDX-License-Identifier: Apache-2.0

package agent

// execAnonymousOptOut warns when the contract sets exec.anonymous: true (SEMANTICS §4). The opt-out
// drops tiers 1 and 2's creation-time refusal of an exec-capable memfd and has the supervisor allow an
// anonymous image, so any binary the agent can read, or bytes it downloads, can be written into a memfd and
// run whatever exec.allow names. It is a legitimate choice for a runtime that needs a memfd (on a kernel
// without MFD_NOEXEC_SEAL the refusal covers every memfd, data included), which is why it warns rather than
// refuses; the warning is what makes a choice that is otherwise visible only in contract_hash explicit at
// compile. The capability line it names is tier 1's: tier 2's handle does not narrow exec.deny by the
// inherited tier-1 row yet, so the warning says so rather than promise a false there.
func (k *compiler) execAnonymousOptOut() {
	e := k.c.Exec
	if e == nil || !e.Anonymous {
		return
	}
	k.ds.warnf(k.pos("exec.anonymous"), CodeUnenforced, "exec.anonymous: true lets the agent run anonymous images: "+
		"any binary it can read, or bytes it writes, can be copied into a memfd and run, so exec.allow no longer bounds "+
		"what runs; tiers 1 and 2 then create memfds without refusal, each anonymous exec is allowed and recorded "+
		"fileless, and at tier landlock the run's capability line reports exec.deny false (at tier cgroup the line "+
		"still reads exec.deny true, though exec.allow bounds anonymous execs there no more than at tier landlock)").
		fix("drop exec.anonymous unless the agent needs an executable memfd; on a kernel without MFD_NOEXEC_SEAL " +
			"(most kernels below Linux 6.3) it also restores data memfds, which a restricted-exec run otherwise refuses")
}
