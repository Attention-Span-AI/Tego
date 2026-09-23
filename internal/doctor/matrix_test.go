// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestMachineMatrixNameEntries: fs.deny_read.created_later (ADR 0043) on this machine. Tier cgroup's conditional cell
// is on where a plane mode passed the probe, and off on the fanotify fallback, whose note says what it does refuse;
// tier bpflsm's is on; tier landlock's is the static cell, held reads' (ADR 0069).
func TestMachineMatrixNameEntries(t *testing.T) {
	fallback := func(st *probeState) { st.plane.Selected = PlaneFanotify }
	for _, tc := range []struct {
		name string
		tier backend.Tier
		edit func(*probeState)
		want bool
		note string
	}{
		{"tier cgroup on a plane mode", backend.TierCgroup, nil, true, "decision plane in lsm mode refuses"},
		{"tier cgroup on the fanotify fallback", backend.TierCgroup, fallback, false, "fanotify listener refuses"},
		{"tier bpflsm", backend.TierBPFLSM, nil, true, ""},
		{"tier landlock (held reads, ADR 0069)", backend.TierLandlock, nil, true, ""},
	} {
		set, notes := state(tc.edit).machineMatrix(tc.tier)
		if got := set.Has(backend.CapReadDenyCreatedLater); got != tc.want {
			t.Errorf("%s: fs.deny_read.created_later %v, want %v (note %q)", tc.name, got, tc.want, notes[backend.CapReadDenyCreatedLater])
		}
		if !strings.Contains(notes[backend.CapReadDenyCreatedLater], tc.note) {
			t.Errorf("%s: note %q, want it to say %q", tc.name, notes[backend.CapReadDenyCreatedLater], tc.note)
		}
	}
}

// TestMachineMatrixTurnsOffWhatThisKernelCannotDo is R27's "the table with this machine's values
// substituted": the static column is written for the mechanism at its best, and a row this kernel's
// Landlock ABI cannot deliver has to read no, with the measured value saying why.
func TestMachineMatrixTurnsOffWhatThisKernelCannotDo(t *testing.T) {
	cases := []struct {
		name    string
		tier    backend.Tier
		edit    func(*probeState)
		off     []backend.Capability
		on      []backend.Capability
		noteFor backend.Capability
		note    string
	}{
		{
			name:    "Landlock ABI 2 has no network rules at all",
			tier:    backend.TierLandlock,
			edit:    func(st *probeState) { st.landlockABI = 2 },
			off:     []backend.Capability{backend.CapNetHostDeny, backend.CapUDPByDestination},
			on:      []backend.Capability{backend.CapFileWriteDeny, backend.CapExecDeny},
			noteFor: backend.CapNetHostDeny,
			note:    "ABI 2 has no network rules",
		},
		{
			name:    "Landlock ABI 7 keeps TCP but not UDP ports",
			tier:    backend.TierLandlock,
			edit:    func(st *probeState) { st.landlockABI = 7 },
			on:      []backend.Capability{backend.CapNetHostDeny, backend.CapUnixSockets},
			noteFor: backend.CapUDPPortInKernel,
			note:    "UDP ports need ABI 10",
		},
		{
			name:    "Landlock ABI 9 has RESOLVE_UNIX",
			tier:    backend.TierLandlock,
			edit:    func(st *probeState) { st.landlockABI = 9 },
			noteFor: backend.CapUnixSockets,
			note:    "RESOLVE_UNIX available",
		},
		{
			name: "tier 2 without connect_unix falls back to seccomp",
			tier: backend.TierCgroup,
			edit: func(st *probeState) {
				st.plane = passingPlane("")
				st.plane.Selected = PlaneFanotify
				for i := range st.hooks {
					if st.hooks[i].Hook == "cgroup/connect_unix" {
						st.hooks[i].Attached = false
					}
				}
			},
			noteFor: backend.CapUnixSockets,
			note:    "fall back to the seccomp supervisor",
		},
		{
			// enforce-plane 2.11: below 6.7 the plane's socket hooks decide unix names, so the seccomp wording is wrong.
			name: "tier 2 without connect_unix under a selected plane says the plane decides unix names",
			tier: backend.TierCgroup,
			edit: func(st *probeState) {
				st.plane = passingPlane("")
				for i := range st.hooks {
					if st.hooks[i].Hook == "cgroup/connect_unix" || st.hooks[i].Hook == "cgroup/sendmsg_unix" {
						st.hooks[i].Loaded, st.hooks[i].Attached = false, false
					}
				}
				st.hooks = append(st.hooks, passingPlaneRows()...)
			},
			noteFor: backend.CapUnixSockets,
			note:    "decision plane's socket_connect and socket_sendmsg hooks",
		},
		{
			name:    "tier 2 refuses with EPERM where the kernel takes no errno reply (every kernel so far)",
			tier:    backend.TierCgroup,
			edit:    func(st *probeState) { st.fanotify.DenyErrno, st.plane = false, nil },
			noteFor: backend.CapFileWriteDeny,
			note:    "reaches the agent as EPERM",
		},
		{
			// The listener sends the bare FAN_DENY whatever the kernel would take, so a kernel that
			// takes EACCES changes nothing the agent sees.
			name:    "tier 2 still refuses with EPERM where the kernel would take EACCES",
			tier:    backend.TierCgroup,
			edit:    func(st *probeState) { st.fanotify.DenyErrno, st.plane = true, nil },
			noteFor: backend.CapFileWriteDeny,
			note:    "still reaches the agent as EPERM",
		},
		{
			// enforce-plane R2, R22: where the probe selected a plane mode, tier cgroup has no fanotify group
			// and its refusals read EACCES.
			name:    "tier 2 on the plane in LSM mode refuses writes with EACCES",
			tier:    backend.TierCgroup,
			edit:    func(st *probeState) { st.plane = passingPlane("") },
			on:      []backend.Capability{backend.CapFileWriteDeny, backend.CapReadDeny, backend.CapExecDeny},
			noteFor: backend.CapFileWriteDeny,
			note:    "decision plane in lsm mode, not fanotify: a refusal reaches the agent as EACCES",
		},
		{
			name: "tier 2 on the plane in fmod_ret mode refuses exec with EACCES",
			tier: backend.TierCgroup,
			edit: func(st *probeState) {
				st.plane = passingPlane("")
				st.plane.Selected = string(bpfobj.PlaneFmodRet)
			},
			noteFor: backend.CapExecDeny,
			note:    "decision plane in fmod_ret mode",
		},
		{
			// ADR 0041 D7: the built-in deny_write targets are race-free where a plane mode decides them.
			name:    "tier 2 on a plane mode protects the write targets",
			tier:    backend.TierCgroup,
			edit:    func(st *probeState) { st.plane = passingPlane("") },
			on:      []backend.Capability{backend.CapProtectedWriteTargets},
			noteFor: backend.CapProtectedWriteTargets,
			note:    "decision plane in lsm mode decides them by inode",
		},
		{
			name: "tier 2 on the fanotify fallback leaves the write targets best effort",
			tier: backend.TierCgroup,
			edit: func(st *probeState) {
				st.plane = passingPlane("")
				st.plane.Selected = PlaneFanotify
			},
			off:     []backend.Capability{backend.CapProtectedWriteTargets},
			noteFor: backend.CapProtectedWriteTargets,
			note:    "best effort",
		},
		{
			name: "tier 2 on the fanotify fallback keeps the EPERM note",
			tier: backend.TierCgroup,
			edit: func(st *probeState) {
				st.plane = passingPlane("")
				st.plane.Selected = PlaneFanotify
			},
			noteFor: backend.CapFileWriteDeny,
			note:    "reaches the agent as EPERM",
		},
		{
			// agent-contract R19: below ABI 6 nothing refuses an abstract name bound outside the run, and
			// doctor says so for both tiers that apply a Landlock ruleset.
			name:    "Landlock ABI 5 has no abstract-socket scope",
			tier:    backend.TierLandlock,
			edit:    func(st *probeState) { st.landlockABI = 5 },
			off:     []backend.Capability{backend.CapUnixAbstractScope},
			noteFor: backend.CapUnixAbstractScope,
			note:    "nothing refuses an abstract unix name bound outside a run",
		},
		{
			// The row says yes where its note says the names are refused: it said no beside that note.
			name:    "tier 2 inherits the scope from Landlock ABI 6",
			tier:    backend.TierCgroup,
			edit:    func(st *probeState) { st.landlockABI = 6 },
			on:      []backend.Capability{backend.CapUnixAbstractScope},
			noteFor: backend.CapUnixAbstractScope,
			note:    "Landlock ABI 6: each run's ruleset refuses",
		},
		{
			name:    "tier 3 inherits the scope from Landlock ABI 6",
			tier:    backend.TierBPFLSM,
			edit:    func(st *probeState) { st.landlockABI = 6 },
			on:      []backend.Capability{backend.CapUnixAbstractScope},
			noteFor: backend.CapUnixAbstractScope,
			note:    "Landlock ABI 6: each run's ruleset refuses",
		},
		{
			name:    "Landlock ABI 7 refuses abstract names bound outside the run",
			tier:    backend.TierLandlock,
			edit:    func(st *probeState) { st.landlockABI = 7 },
			on:      []backend.Capability{backend.CapUnixAbstractScope},
			noteFor: backend.CapUnixAbstractScope,
			note:    "Landlock ABI 7: each run's ruleset refuses",
		},
		{
			name:    "tier 3 whose hooks never ran",
			tier:    backend.TierBPFLSM,
			edit:    func(st *probeState) { st.lsm.Functional = "attached but never ran" },
			noteFor: backend.CapRecordExecOpenNet,
			note:    "did not confirm the hooks run",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, notes := state(tc.edit).machineMatrix(tc.tier)
			for _, c := range tc.off {
				if set.Has(c) {
					t.Errorf("%s is still on", c)
				}
			}
			for _, c := range tc.on {
				if !set.Has(c) {
					t.Errorf("%s was turned off and should not have been", c)
				}
			}
			if tc.noteFor != "" && !strings.Contains(notes[tc.noteFor], tc.note) {
				t.Errorf("note for %s is %q, want it to mention %q", tc.noteFor, notes[tc.noteFor], tc.note)
			}
		})
	}
}

// TestMachineMatrixNeverAddsACapability: a probe can only take a row away, never grant one the tier
// does not define. Conditional rows need their own measured ABI or hook evidence (machineMatrix).
func TestMachineMatrixNeverAddsACapability(t *testing.T) {
	for _, tier := range backend.Tiers() {
		st := state(func(st *probeState) { st.landlockABI = 11 })
		set, _ := st.machineMatrix(tier)
		static := backend.Matrix(tier)
		for _, c := range backend.AllCapabilities() {
			if c == backend.CapUnixAbstractScope || c == backend.CapUnixDestinationKernel || c == backend.CapProtectedWriteTargets ||
				c == backend.CapReadDenyCreatedLater {
				continue
			}
			if set.Has(c) && !static.Has(c) {
				t.Errorf("tier %s: %s is on for this machine but not in the static column", tier, c)
			}
		}
	}
}

// TestMachineMatrixOnAnEmptyTier: a machine that reaches no tier at all must not panic on the
// nil column backend.Matrix returns.
func TestMachineMatrixOnAnEmptyTier(t *testing.T) {
	set, notes := state(func(st *probeState) { st.landlockABI = 1 }).machineMatrix("")
	if len(set) != 0 {
		t.Errorf("an empty tier has capabilities: %v", set)
	}
	if len(notes) != 0 {
		t.Errorf("an empty tier has notes: %v", notes)
	}
}

func TestHookOK(t *testing.T) {
	st := state(nil)
	if !st.hookOK("cgroup/connect_unix") {
		t.Error("a hook that loaded and attached reads as unavailable")
	}
	if st.hookOK("cgroup/nonexistent") {
		t.Error("a hook that was never probed must not read as available")
	}
	if (probeState{}).hookOK("cgroup/connect_unix") {
		t.Error("an unprobed machine must not claim a hook")
	}
}
