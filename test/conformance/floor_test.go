// SPDX-License-Identifier: Apache-2.0

package conformance

import "testing"

// TestTruncateCellsTakeTheFloorBelowABI3: below Landlock ABI 3 (kernels before 6.2, AL2023's 6.1) tier 1's filter
// refuses every truncate(2) with EPERM before any rule, the supervisor or a plane hook sees it (enforce-landlock
// E31, REASON-CHANNEL): the kernel runner must want that refusal there, with no ledger line, in every run (each
// keeps tier 1's Landlock domain and filter), and each cell's own expectation from ABI 3. No other op changes.
// The machines are 6.17, honour MFD_NOEXEC_SEAL, as every kernel from 6.3 does, and answer sock_diag for AF_UNIX, so that no cell's want_where
// answers (TestWantWhereAnswersOnItsMachines holds those).
func TestTruncateCellsTakeTheFloorBelowABI3(t *testing.T) {
	truncates := 0
	for _, fx := range Fixtures() {
		for i := range fx.Cells {
			c := &fx.Cells[i]
			for k, own := range c.Want {
				below, ok := c.WantOn(k, Machine{Kernel: [2]int{6, 17}, ABI: TruncateABI - 1, MemfdNoexecSeal: true, UnixDiag: true})
				at, ok3 := c.WantOn(k, Machine{Kernel: [2]int{6, 17}, ABI: TruncateABI, MemfdNoexecSeal: true, UnixDiag: true})
				if !ok || !ok3 {
					t.Fatalf("%s: no expectation at %v", fx.ID(c), k)
				}
				if at != own {
					t.Errorf("%s at %v on ABI %d: %+v, want the cell's own %+v", fx.ID(c), k, TruncateABI, at, own)
				}
				want := own
				if c.Op == OpTruncate {
					want = Want{Verdict: Refused, NoLine: true, Errno: 1} // EPERM
				}
				if below != want {
					t.Errorf("%s at %v on ABI %d: %+v, want %+v", fx.ID(c), k, TruncateABI-1, below, want)
				}
			}
			if _, ok := c.WantOn(Key{TierCgroup, ModeLSM}, Machine{ABI: TruncateABI - 1}); ok {
				t.Errorf("%s: WantOn invents an expectation for a key the cell does not name", fx.ID(c))
			}
			if c.Op == OpTruncate {
				truncates++
			}
		}
	}
	if truncates == 0 {
		t.Fatal("no truncate cell: the floor has nothing to check")
	}
}

// TestGeneratedTruncateCellsTakeTheFloorBelowABI3: a generated cell has no want of its own (the kernel is its judge),
// yet below Landlock ABI 3 tier 1's filter answers its truncate the same way on every axis, so WantOn gives the
// floor there for every key, and from ABI 3 nothing: the cell is judged. Every other generated op is judged on
// every ABI. Only the AL2023 guest row (ABI 2) reaches this branch in a run, so it is pinned here.
func TestGeneratedTruncateCellsTakeTheFloorBelowABI3(t *testing.T) {
	floor := Want{Verdict: Refused, NoLine: true, Errno: 1} // EPERM
	keys := []Key{{TierLandlock, ModeNone}, {TierCgroup, ModeFanotify}, {TierCgroup, ModeLSM}, {TierCgroup, ModeFmodRet}, {TierBPFLSM, ModeLSM}}
	truncates := 0
	for _, fx := range GenFSGrid() {
		for i := range fx.Cells {
			c := &fx.Cells[i]
			if !c.Generated {
				t.Fatalf("%s: a grid cell that is not generated", fx.ID(c))
			}
			for _, k := range keys {
				below, has := c.WantOn(k, Machine{Kernel: [2]int{6, 17}, ABI: TruncateABI - 1, MemfdNoexecSeal: true, UnixDiag: true})
				if c.Op == OpTruncate {
					if !has || below != floor {
						t.Errorf("%s at %v on ABI %d: %+v (%v), want the floor %+v", fx.ID(c), k, TruncateABI-1, below, has, floor)
					}
				} else if has {
					t.Errorf("%s at %v on ABI %d: %+v, want no expectation (judged)", fx.ID(c), k, TruncateABI-1, below)
				}
				if at, has := c.WantOn(k, Machine{Kernel: [2]int{6, 17}, ABI: TruncateABI, MemfdNoexecSeal: true, UnixDiag: true}); has {
					t.Errorf("%s at %v on ABI %d: %+v, want no expectation (judged)", fx.ID(c), k, TruncateABI, at)
				}
			}
			if c.Op == OpTruncate {
				truncates++
			}
		}
	}
	if truncates == 0 {
		t.Fatal("no generated truncate cell: the floor has nothing to check")
	}
}

// TestWantWhereAnswersOnItsMachines: a cell's want_where answers on the machines it names and nowhere else, and only
// for the columns it sets. The memfd cells are refused at creation, EACCES, wherever the kernel honours
// MFD_NOEXEC_SEAL; on a kernel without it tiers 1 and 2 answer ENOSYS and the plane decides the image itself
// (enforce-landlock R11a, enforce-plane R27). The third party's refusal reads observed where the kernel recorder
// writes the line up to 6.12 (ADR 0016). An attach out of the run is the plane's EACCES on an axis whose plane answers
// before Landlock (plane_first), Landlock's EPERM elsewhere.
func TestWantWhereAnswersOnItsMachines(t *testing.T) {
	// The baseline has no abstract-name scope; the ABI >= 6 conditional
	// expectation is tested by constructing its own matching machine below.
	current := Machine{Kernel: [2]int{6, 17}, ABI: 5, MemfdNoexecSeal: true, UnixDiag: true}
	seen := 0
	for _, fx := range Fixtures() {
		for i := range fx.Cells {
			c := &fx.Cells[i]
			for n, cw := range c.WantWhere {
				seen++
				// on, a machine the condition names: its kernel bound, its seal fact, else the current machine's.
				on := current
				if b, err := parseBound(cw.Where.KernelMax); err == nil {
					on.Kernel = b
				} else if b, err := parseBound(cw.Where.KernelMin); err == nil {
					on.Kernel = b
				}
				if cw.Where.ABIMin != 0 {
					on.ABI = cw.Where.ABIMin
				} else if cw.Where.ABIMax != 0 {
					on.ABI = cw.Where.ABIMax
				}
				if cw.MemfdNoexecSeal != nil {
					on.MemfdNoexecSeal = *cw.MemfdNoexecSeal
				}
				if cw.PlaneFirst != nil {
					on.PlaneFirst = *cw.PlaneFirst
				}
				if cw.SupervisorRoot != nil {
					on.SupervisorRoot = *cw.SupervisorRoot
				}
				if cw.UnixDiag != nil {
					on.UnixDiag = *cw.UnixDiag
				}
				if cw.ExecmodRefused != nil {
					on.ExecmodRefused = *cw.ExecmodRefused
				}
				if cw.Matches(current) || !cw.Matches(on) {
					t.Fatalf("%s: want_where[%d] matches the current machine or not its own", fx.ID(c), n)
				}
				for k, own := range c.Want {
					if got, _ := c.WantOn(k, current); got != own {
						t.Errorf("%s at %v on the current machine: %+v, want the cell's own %+v", fx.ID(c), k, got, own)
					}
					want, set := cw.Want[k]
					if !set {
						want = own
					}
					if got, _ := c.WantOn(k, on); got != want {
						t.Errorf("%s at %v on want_where[%d]'s machine: %+v, want %+v", fx.ID(c), k, n, got, want)
					}
				}
			}
			unsealed := current
			unsealed.MemfdNoexecSeal = false
			if c.Op != OpMemfdCreate || fx.Name != "exec" {
				continue
			}
			if w, _ := c.WantOn(Key{TierLandlock, ModeNone}, unsealed); w.Errno != 38 {
				t.Errorf("%s: tier landlock without MFD_NOEXEC_SEAL wants %+v, the refusing arm answers ENOSYS", fx.ID(c), w)
			}
			if w, _ := c.WantOn(Key{TierBPFLSM, ModeLSM}, unsealed); w.Verdict != Allow {
				t.Errorf("%s: the plane without MFD_NOEXEC_SEAL wants %+v; a run the plane decides has no refusing arm", fx.ID(c), w)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no table cell has a want_where")
	}
}
