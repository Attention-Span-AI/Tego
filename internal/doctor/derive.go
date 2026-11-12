// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// This file is the one tier derivation (docs/p0/limits-check-doctor-cli.md R27 Output). `tego
// doctor` reports it and `tego run` selects from it: internal/cli selects through Report.Select, which
// offers enforce.Select this report's Probe and explains a refused tier with this report's own lines
// (whyNot), never through a gate of its own, so the two cannot drift apart again. A run's report (ForRun) is
// this same derivation over the checks of the tiers its selection can reach, and reports no tier above them
// (unprobed); at and below them its Probe and WhyNot are doctor's. It is the machine's
// probes ANDed with the build's answer (enforce.Buildable), and each tier's list of what is missing
// begins with the whole list of the tier below it, because each tier is the one below plus more
// (docs/ARCHITECTURE.md §2, ADR 0011).

// probe derives which tiers this machine and this binary can provide. Every machine answer comes from a
// functional probe, never from a version comparison (docs/ARCHITECTURE.md §14: "the runtime probes, never
// trusts a version"); D1 is the one exception, and missingFor says why it stays.
func (st probeState) probe() backend.Probe {
	return backend.Probe{
		backend.TierLandlock: len(st.missingFor(backend.TierLandlock)) == 0,
		backend.TierCgroup:   len(st.missingFor(backend.TierCgroup)) == 0,
		backend.TierBPFLSM:   len(st.missingFor(backend.TierBPFLSM)) == 0,
	}
}

// missingFor lists what stands between this machine and one tier: the tier below's whole list first,
// then this tier's own probes in probe order, then the build.
//
// Tier 1 needs D5 (both halves, blocksEveryTier), D1, D3 and D4. D3 is there because every run is created
// in the delegated cgroup it checks and is stopped through that cgroup's cgroup.kill; a run cannot start
// without it. D1 is there because the kernel floor it checks, 5.14, stands for mechanisms no functional
// probe exercises (pidfd_getfd, seccomp CONTINUE, clone3 into a cgroup); a release below the floor, or one
// D1 cannot parse, is outside what the launcher supports, so the derivation fails closed on it rather than
// promise a run the launch may not complete. Every one of these is also a tier-2 and tier-3 blocker,
// because tier 2 installs tier 1's Landlock ruleset and seccomp filter and inherits its supervisor
// (enforce-cgroup-observe.md §5 R1): ADR 0011 gives delete, rename and mkdir at tier 2 to "Landlock inside
// the run", so a machine without Landlock has no tier 2 either.
func (st probeState) missingFor(t backend.Tier) []string {
	return st.missingAs(t, t)
}

// missingAs is missingFor(t) for the section of tier asked, which inherits t's list: a line that names the
// tier it is about names asked, so tier bpflsm's root line says bpflsm, not cgroup.
func (st probeState) missingAs(t, asked backend.Tier) []string {
	if st.unprobed(t) {
		// Its own checks were never run, so it is not offered: a check not run has established nothing
		// (Result.Skipped). The one line says so rather than listing each check as failed.
		return []string{fmt.Sprintf("not probed: this run's tier selection cannot reach tier %s, so its checks "+
			"were not run (tego doctor runs them)", t)}
	}
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	failed := func(id CheckID) {
		if r, ok := st.byID[id]; ok && !r.OK {
			add("%s: %s", id, r.Detail)
		}
	}
	switch t {
	case backend.TierLandlock:
		out = append(out, st.blocksEveryTier()...)
		failed(CheckKernel)
		failed(CheckCgroupV2)
		if r, ok := st.byID[CheckLandlock]; ok && !r.OK {
			add("landlock: %s", r.Detail)
		} else if st.landlockABI > 0 && st.landlockABI < MinLandlockABI {
			add("landlock ABI %d is below the supported minimum %d (rename and link would be confined to one directory)",
				st.landlockABI, MinLandlockABI)
		}
	case backend.TierCgroup:
		out = append(out, st.missingAs(backend.TierLandlock, asked)...)
		if !st.root {
			add("root: tier %s needs CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN", asked)
		}
		failed(CheckBTF)
		failed(CheckFanotify)
		out = append(out, st.missingHooks(backend.TierCgroup)...)
		// D7 can fail before it tests a single hook: as root, a BTF that cilium/ebpf cannot parse
		// (btf.LoadKernelSpec) fails D7 with no rows. D2 parses the file too, but this derivation does not rely on it:
		// the per-hook rows above then say nothing, so D7's own failure is read here; otherwise
		// the tier would be offered and Prepare would fail loading programs after the run's ledger and
		// cgroup exist. Tier bpflsm inherits the line through this list, so it is not repeated there.
		if st.root && !st.testedHooks(backend.TierCgroup) {
			failed(CheckPrograms)
		}
	case backend.TierBPFLSM:
		out = append(out, st.missingAs(backend.TierCgroup, asked)...)
		if why, _ := st.lsm.bpfInactive(); why != "" {
			add("lsm: %s", why)
		}
		if st.lsm.BPFActive && st.lsm.Functional != "" && !strings.HasPrefix(st.lsm.Functional, "confirmed") {
			add("lsm: %s", st.lsm.Functional)
		}
		// Tier 3's rows are the plane's: tier bpflsm is the plane in LSM mode (docs/p0/enforce-plane.md R19).
		out = append(out, st.planeMissing()...)
	// Observe asks nothing of the machine; auto is resolved before a tier is derived.
	case backend.TierObserve, backend.TierAuto:
	}
	if err := st.buildable(t); err != nil {
		add("build: %v", err)
	}
	return out
}

// outsideUserManager is Report.OutsideUserManager: D3 failed beside the user manager's cgroup, that failure is the
// whole of tier landlock's missing list, and the machine config's ceiling (unbounded, or tier landlock) lets a run
// take tier landlock once it starts inside that cgroup. As root D3 never fails so: uid 0 places anywhere.
func (st probeState) outsideUserManager(ceiling backend.Tier) bool {
	d3, ok := st.byID[CheckCgroupV2]
	if !ok || d3.OK || !d3.beside || st.root || st.unprobed(backend.TierLandlock) {
		return false
	}
	if ceiling != "" && ceiling != backend.TierLandlock {
		return false
	}
	return len(st.missingFor(backend.TierLandlock)) == 1
}

// noUserManager is Report.NoUserManager: D3 failed because no user manager runs for the invoking uid
// (cgroup.ErrNoUserManager), that failure is the whole of tier landlock's missing list, and the ceiling lets a run take
// tier landlock once that manager runs and tego runs in a shell inside it. Root never fails D3 so.
func (st probeState) noUserManager(ceiling backend.Tier) bool {
	d3, ok := st.byID[CheckCgroupV2]
	if !ok || d3.OK || !d3.noManager || st.root || st.unprobed(backend.TierLandlock) {
		return false
	}
	if ceiling != "" && ceiling != backend.TierLandlock {
		return false
	}
	return len(st.missingFor(backend.TierLandlock)) == 1
}

// unprobed reports whether tier t lies above the checks this state holds (probeState.reach). Only ForRun
// makes such a state, for a run whose selection neither picks nor explains any tier above its reach.
func (st probeState) unprobed(t backend.Tier) bool {
	return st.reach != "" && !t.AtOrBelow(st.reach)
}

// buildable is the build's half of the derivation, enforce.Buildable unless a test describes another build.
func (st probeState) buildable(t backend.Tier) error {
	if st.built != nil {
		return st.built(t)
	}
	return enforce.Buildable(t)
}

// blocksEveryTier lists the D5 answers that stand between this machine and every enforcement tier
// at once, Yama's first. Every tier installs the tier-1 seccomp filter and hands its listener to the
// supervisor — tier 2 installs the same Landlock ruleset and filter as tier 1 and inherits its
// supervisor (internal/runtime/enforce/select.go construct, enforce-cgroup-observe.md §5 R1), and
// tier 3 is tier 2 plus BPF LSM — so D5 failing in either half leaves no tier a run could get:
//
//   - Yama: the supervisor reads the agent's sockaddrs and argv with process_vm_readv and takes the
//     listener with pidfd_getfd, both PTRACE_MODE_ATTACH_REALCREDS, and a launch under
//     ptrace_scope >= 2 aborts at pidfd_getfd (ErrNotifyFDUnavailable) rather than degrading. It is
//     the one condition under which every other probe can pass and no run can still work.
//   - The round trip: a NEW_LISTENER filter this process may not install (EACCES from an outer
//     filter, EBUSY under another supervisor's listener) is one the launcher may not install
//     either.
//
// Fail closed on both, so doctor never reports a tier a run cannot reach. A round-trip failure is
// listed by D5's own detail, which names the round trip alone (seccompVerdictOn reports it without
// Yama's sentence), so neither reason is ever printed twice.
func (st probeState) blocksEveryTier() []string {
	var out []string
	if st.ptrace.Blocked != "" {
		out = append(out, st.ptrace.Blocked)
	}
	if st.seccompErr != nil {
		detail := st.seccompErr.Error()
		if r, ok := st.byID[CheckSeccomp]; ok {
			detail = r.Detail
		}
		out = append(out, fmt.Sprintf("%s: %s", CheckSeccomp, detail))
	}
	return out
}

// everyTierFixes is blocksEveryTier's remedies, in the same order.
func (st probeState) everyTierFixes() []string {
	var out []string
	if st.ptrace.Blocked != "" && st.ptrace.Fix != "" {
		out = append(out, st.ptrace.Fix)
	}
	if st.seccompErr != nil {
		if r, ok := st.byID[CheckSeccomp]; ok && r.Fix != "" {
			out = append(out, r.Fix)
		}
	}
	return out
}

// tierOneFixes is the remedy of every tier-1 blocker, in missingFor's order: D5's (Yama's, then the round
// trip's), then D1's, D3's and D4's.
func (st probeState) tierOneFixes() []string {
	fixes := st.everyTierFixes()
	for _, id := range []CheckID{CheckKernel, CheckCgroupV2, CheckLandlock} {
		if r, ok := st.byID[id]; ok && !r.OK && r.Fix != "" {
			fixes = append(fixes, r.Fix)
		}
	}
	return fixes
}

// testedHooks reports whether D7 produced a row for any hook of tier t.
func (st probeState) testedHooks(t backend.Tier) bool {
	for _, h := range st.hooks {
		if h.Tier == t && !h.CapabilityOnly {
			return true
		}
	}
	return false
}

// missingHooks lists the D7 hooks of one tier that did not load and attach. A run of D7 that never
// happened (no root) contributes nothing here: the root line above already says why. An optional hook
// this kernel predates is not missing: the tier runs without it (cgroup/connect_unix and
// cgroup/sendmsg_unix below 6.7, enforce-cgroup-observe.md §5 R7), and the capability matrix's note says
// what then decides what it would have. *Amended:* connect_unix used to be required here, so below 6.7
// doctor, and `tego run`, which selects from this derivation, offered no tier cgroup although the backend
// runs there without it.
func (st probeState) missingHooks(t backend.Tier) []string {
	var out []string
	for _, h := range st.hooks {
		if h.Tier == t && !h.CapabilityOnly && !h.OK() && !h.Absent {
			out = append(out, fmt.Sprintf("%s: %s", h.Hook, h.Detail))
		}
	}
	return out
}

// missing builds the per-tier gap map for every tier above the one this machine reached.
func (st probeState) missing(reached backend.Tier) map[backend.Tier][]string {
	out := map[backend.Tier][]string{}
	for _, t := range backend.Tiers() {
		if t == backend.TierObserve {
			continue
		}
		if reached != "" && t.AtOrBelow(reached) {
			continue
		}
		if reasons := st.missingFor(t); len(reasons) > 0 {
			out[t] = reasons
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fix is the one line that makes the next tier up available (R27). It is built from the machine's
// own state — the active LSM list for the GRUB line, the missing privilege otherwise — never from a
// canned string that might name the wrong LSMs.
//
// Tier 1's blockers come first whichever tier is next, because they block every tier (missingFor), and
// all of their remedies go on the one line: a line naming only the first is not the line that makes tier 1
// available — at ptrace_scope=3 with Landlock missing from lsm=, the operator would reboot for Yama's boot
// setting, re-run doctor, and only then learn that the lsm= line needed the same reboot. Yama's remedy
// leads, and a reboot after it does not undo it: at scope 2 the remedy is the sysctl.d setting, which the
// boot applies again (a bare `sysctl -w` would be lost to it), and at scope 3 it is a boot setting itself.
//
// Above tier 1 the line is the first that applies of: the binary, privilege, the boot change, the kernel
// build. The binary leads because no change to the machine makes a tier this build cannot construct
// available; a tier no build of this version carries has no fix line at all, since naming a machine
// change for it would promise a tier the change cannot deliver.
func (st probeState) fix(reached backend.Tier) string {
	return st.fixFor(nextTier(reached))
}

// fixFor is the one line that makes tier next available, by the rules fix describes; "" when nothing is
// missing for it or no machine change or build of this version delivers it. fix asks it about the tier one
// above the reached one, and a run refused a tier it asked for by name is told the line for that tier
// (whyNot).
func (st probeState) fixFor(next backend.Tier) string {
	if next == "" || len(st.missingFor(next)) == 0 {
		return ""
	}
	if fixes := st.tierOneFixes(); next == backend.TierLandlock || len(fixes) > 0 {
		return strings.Join(fixes, "; and ")
	}
	if st.unprobed(next) {
		return "run tego doctor for what tier " + string(next) + " needs here"
	}
	if err := st.buildable(next); err != nil {
		var nb *enforce.NotBuiltError
		if errors.As(err, &nb) {
			return nb.Fix
		}
		return ""
	}
	if !st.root {
		return "re-run as root for the tier-2 and tier-3 probes: " + sudoDoctor()
	}
	if next == backend.TierBPFLSM {
		if _, fix := st.lsm.bpfInactive(); fix != "" {
			return fix
		}
	}
	// Only the checks tier next reads have a say in its line. D6 gates tier bpflsm alone, so tier cgroup's line
	// never names the lsm= reboot, which would not deliver it; and D7's own fix is worded for every row it tested,
	// tier 3's included, so tier cgroup's comes from tier cgroup's rows. That is also what makes a run's line the
	// same as doctor's: a run at reach cgroup runs neither D6 nor tier 3's rows (R27 "What a run probes").
	ids := []CheckID{CheckBTF, CheckFanotify, CheckPrograms}
	if next == backend.TierBPFLSM {
		ids = append(ids, CheckLSM)
	}
	for _, id := range ids {
		r, ok := st.byID[id]
		if !ok || r.OK {
			continue
		}
		fix := r.Fix
		// Tier bpflsm reads tier cgroup's rows and the plane's (its own legacy rows gate nothing, missingFor), so both
		// take the fix of tier cgroup's rows, which is also what a run at reach bpflsm, running no other row, finds.
		if id == CheckPrograms && next != backend.TierLandlock && st.testedHooks(backend.TierCgroup) {
			fix = programsVerdict(st.tierRows(backend.TierCgroup)).Fix
		}
		if fix != "" {
			return fix
		}
	}
	if next == backend.TierBPFLSM {
		return st.planeFix()
	}
	return ""
}

// tierRows is D7's rows for the hooks of tier t, in D7's order.
func (st probeState) tierRows(t backend.Tier) []HookResult {
	var out []HookResult
	for _, h := range st.hooks {
		if h.Tier == t && !h.Capture && !h.CapabilityOnly {
			out = append(out, h)
		}
	}
	return out
}

// whyNot is, per enforcement tier this machine and this binary cannot provide, what doctor prints about
// it: the missing list and the fix line for that tier, joined into one line. It is what a run refused that
// tier is told (Report.Select), so `tego run` and `tego doctor` never give two accounts of one tier.
func (st probeState) whyNot() map[backend.Tier]string {
	out := map[backend.Tier]string{}
	for _, t := range backend.Tiers() {
		if t == backend.TierObserve {
			continue
		}
		reasons := st.missingFor(t)
		if len(reasons) == 0 {
			continue
		}
		line := fmt.Sprintf("missing for %s: %s", t, strings.Join(reasons, "; "))
		if f := st.fixFor(t); f != "" {
			line += "; fix: " + f
		}
		out[t] = line
	}
	return out
}

// nextTier is the tier one rank above reached, "" at the top.
func nextTier(reached backend.Tier) backend.Tier {
	tiers := make([]backend.Tier, 0, 3)
	for _, t := range backend.Tiers() {
		if t != backend.TierObserve {
			tiers = append(tiers, t)
		}
	}
	sort.Slice(tiers, func(i, j int) bool { return tiers[i].Rank() < tiers[j].Rank() })
	if reached == "" {
		return tiers[0]
	}
	for i, t := range tiers {
		if t == reached && i+1 < len(tiers) {
			return tiers[i+1]
		}
	}
	return ""
}
