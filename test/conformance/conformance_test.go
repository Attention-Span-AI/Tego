// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The unprivileged runner (ADR 0017 (b)): every cell's expected verdict against `tego compile --test` for
// each tier the cell names, plus checks that the table itself is well formed. It needs no privilege and no
// kernel feature: compile makes no kernel call (ADR 0019).

const baselinePath = "testdata/baseline.json"

// TestModuleMountsStandAlone: a fixture's mounts are made together, and a kernel without one of them (ENODEV) leaves
// the whole fixture not run (MOUNTS-ABSENT) unless TEGO_CONFORMANCE_FS_REQUIRE names it, which root-suites.sh does
// only where it loads the module. So a mount every kernel has (bind, tmpfs) never shares a fixture with one a row may
// lack (overlay, btrfs): its cells run on every root row, not only where the module is loaded.
func TestModuleMountsStandAlone(t *testing.T) {
	for _, fx := range Fixtures() {
		var module, builtin []string
		for _, m := range fx.Mounts {
			switch m.Kind {
			case MountOverlay, MountBtrfs:
				module = append(module, m.Kind+" at "+m.At)
			default:
				builtin = append(builtin, m.Kind+" at "+m.At)
			}
		}
		if len(module) > 0 && len(builtin) > 0 {
			t.Errorf("fixture %s mounts %v, which a kernel may lack, beside %v, which every kernel has: a row without the module would run none of them",
				fx.Name, module, builtin)
		}
	}
}

func TestCellTableIsWellFormed(t *testing.T) {
	fixtures := Fixtures()
	ids := map[string]bool{}
	cells := 0
	for i := range fixtures {
		fx := &fixtures[i]
		owned := map[string]string{}
		for j := range fx.Cells {
			c := &fx.Cells[j]
			cells++
			id := fx.ID(c)
			if ids[id] {
				t.Errorf("cell %s is defined twice", id)
			}
			ids[id] = true
			if len(c.Want) == 0 {
				t.Errorf("%s has no expectation", id)
			}
			// Every cell owns its paths, so one action's ledger line is never another's (the runner finds a
			// cell's line by path).
			for _, p := range []string{c.Path, c.Dest} {
				if p == "" || c.Op == OpConnectTCP || c.Op == OpConnectUDP || (c.Op == OpSymlink && p == c.Dest) {
					continue // a symlink's target is text, not an action path
				}
				if other, dup := owned[p]; dup {
					t.Errorf("%s and %s both act on %s", id, other, p)
				}
				owned[p] = id
			}
			for k, w := range c.Want {
				if w.Verdict != Allow && w.Verdict != Refused {
					t.Errorf("%s: verdict %q at %v", id, w.Verdict, k)
				}
				switch k.Tier {
				case TierLandlock:
					if k.Mode != ModeNone {
						t.Errorf("%s: tier landlock has no plane mode, got %q", id, k.Mode)
					}
				case TierCgroup, TierBPFLSM:
					if !validMode(k.Mode) {
						t.Errorf("%s: mode %q is not one of %v", id, k.Mode, Modes)
					}
				default:
					t.Errorf("%s: unknown tier %q", id, k.Tier)
				}
			}
			// v1 fills tier landlock and tier cgroup in the fanotify mode, every cell.
			for _, k := range []Key{{TierLandlock, ModeNone}, {TierCgroup, ModeFanotify}} {
				if _, ok := c.Want[k]; !ok && c.Unasked[k] == "" {
					t.Errorf("%s lacks its %v expectation, and does not say why it is unasked", id, k)
				}
			}
			// T10: every cell states what tier bpflsm's plane (mode lsm) gives it. The compile runner asks it, and the
			// kernel runner's tier cgroup in each plane mode the machine passes answers it too (TIER3-PLAN T6).
			if _, ok := c.Want[Key{TierBPFLSM, ModeLSM}]; !ok {
				t.Errorf("%s lacks its bpflsm/lsm expectation", id)
			}
			for k := range c.Want {
				if k.Tier == TierCgroup && !containsMode(FilledModes, k.Mode) {
					t.Errorf("%s: v1 fills only %v at tier cgroup, got %q; a new mode extends FilledModes with its runner", id, FilledModes, k.Mode)
				}
			}
			if c.Finding != "" {
				if _, ok := c.Want[Key{c.FindingAt, wantMode(c.FindingAt)}]; !ok {
					t.Errorf("%s: Finding names tier %q, which the cell has no expectation for", id, c.FindingAt)
				}
				t.Logf("finding on %s at %s: %s", id, c.FindingAt, c.Finding)
			}
		}
	}
	if cells < 40 {
		t.Errorf("%d cells, v1 seeds at least 40", cells)
	}
	// Every space of ADR 0017 is built: a cell a table names is run, so no table defers one.
	for _, d := range Deferred() {
		t.Errorf("deferred cell %s (%s): a cell a table names is one it runs", d.Name, d.Why)
	}
	t.Logf("%d cells in %d fixtures", cells, len(fixtures))
}

func wantMode(t Tier) Mode {
	if t == TierLandlock {
		return ModeNone
	}
	return ModeFanotify
}

func validMode(m Mode) bool { return containsMode(Modes, m) }

func containsMode(ms []Mode, m Mode) bool {
	for _, x := range ms {
		if x == m {
			return true
		}
	}
	return false
}

// TestBaselineIsWellFormed holds the checked-in baseline to baselineProblems: every entry names a cell of a space
// and a reason (never the placeholder an update writes), no entry is a fail-open, and the file is canonical.
func TestBaselineIsWellFormed(t *testing.T) {
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	cells, err := AllCells()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range baselineProblems(data, cells) {
		t.Error(p)
	}
}

// TestInvariantsCatchAFailOpen is the suite's own self-test (ADR 0017): an outcome where the kernel allowed what
// the contract refuses fails an invariant, whatever the tier's plan or the decision core say.
func TestInvariantsCatchAFailOpen(t *testing.T) {
	m := Model{Write: []string{"out"}, DenyRead: []string{"secrets", "out/keys"}, ExecAllow: []string{"bin/tool"}, NetDeclared: true,
		NetAllow: []string{"127.0.0.1:1"}}
	ok := Outcome{OK: true}
	anon, noExec, keyring, direct := m, m, m, m // the opt-outs: exec: {anonymous: true}, no exec.allow, keyring: true, fs.reads: direct
	anon.ExecAnonymous, noExec.ExecAllow, keyring.Keyring, direct.Reads = true, nil, true, ReadsDirect
	rules := m
	rules.ExecDeny, rules.ExecAllow = []string{"git push"}, nil // the command rule alone
	cases := []struct {
		name string
		c    Cell
		tier Tier
		want bool   // a violation
		m    *Model // the case's own model, m where nil
	}{
		{"write outside", Cell{Op: OpWriteOpen, Path: "notes.txt"}, TierCgroup, true, nil},
		{"write inside", Cell{Op: OpWriteOpen, Path: "out/a"}, TierCgroup, false, nil},
		{"rename out", Cell{Op: OpRename, Path: "out/a", Dest: "b"}, TierLandlock, true, nil},
		{"read deny_read", Cell{Op: OpRead, Path: "secrets/k"}, TierLandlock, true, nil},
		// fs.reads: auto, the default, holds a run's reads where a deny_read lies inside a write entry (ADR 0069): the
		// nested entry's reads are refused at landlock, its modifications are not (held reads refuse reads only).
		{"read nested deny_read at landlock (held reads)", Cell{Op: OpRead, Path: "out/keys/k"}, TierLandlock, true, nil},
		{"read nested deny_read at landlock under fs.reads: direct (unenforced there)", Cell{Op: OpRead, Path: "out/keys/k"}, TierLandlock, false, &direct},
		{"write nested deny_read at landlock (held reads refuse reads only)", Cell{Op: OpWriteOpen, Path: "out/keys/k"}, TierLandlock, false, nil},
		{"read nested deny_read at cgroup", Cell{Op: OpRead, Path: "out/keys/k"}, TierCgroup, true, nil},
		{"read through a symlink to a deny_read", Cell{Op: OpRead, Path: "out/l", Canon: "secrets/k"}, TierCgroup, true, nil},
		{"exec outside exec.allow", Cell{Op: OpExec, Path: "bin/other"}, TierCgroup, true, nil},
		{"exec allowed", Cell{Op: OpExec, Path: "bin/tool"}, TierCgroup, false, nil},
		{"connect undeclared", Cell{Op: OpConnectTCP, Addr: "127.0.0.1:2"}, TierCgroup, true, nil},
		{"connect declared", Cell{Op: OpConnectTCP, Addr: "127.0.0.1:1"}, TierCgroup, false, nil},
		{"rename onto deny_write at bpflsm", Cell{Op: OpRename, Path: "out/evil", Dest: "out/.git/config"}, TierBPFLSM, true, nil},
		{"link onto deny_write at bpflsm", Cell{Op: OpLink, Path: "out/evil", Dest: "out/.git/config"}, TierBPFLSM, true, nil},
		{"rename onto deny_write at landlock (best effort)", Cell{Op: OpRename, Path: "out/evil", Dest: "out/.git/config"}, TierLandlock, false, nil},
		{"write to deny_write at bpflsm", Cell{Op: OpWriteOpen, Path: "out/.git/config"}, TierBPFLSM, true, nil},
		{"write to deny_write at landlock", Cell{Op: OpWriteOpen, Path: "out/.git/config"}, TierLandlock, false, nil},
		{"rename beside deny_write at bpflsm", Cell{Op: OpRename, Path: "out/a", Dest: "out/b"}, TierBPFLSM, false, nil},
		{"symlink to deny_write is only a target", Cell{Op: OpSymlink, Path: "out/l", Dest: "out/.git/config"}, TierBPFLSM, false, nil},
		{"symlink outside write", Cell{Op: OpSymlink, Path: "l", Dest: "out/a"}, TierLandlock, true, nil},
		{"symlink inside write", Cell{Op: OpSymlink, Path: "out/l", Dest: "x"}, TierLandlock, false, nil},
		{"link into write", Cell{Op: OpLink, Path: "notes", Dest: "out/l"}, TierLandlock, false, nil},
		{"link outside write", Cell{Op: OpLink, Path: "out/a", Dest: "l"}, TierLandlock, true, nil},
		{"mapexec of writable code at bpflsm", Cell{Op: OpMapExec, Path: "out/code"}, TierBPFLSM, true, nil},
		{"mapexec of writable code at cgroup (tiers 1-2 decide no mapping)", Cell{Op: OpMapExec, Path: "out/code"}, TierCgroup, false, nil},
		{"mapexec of exec.allow code at bpflsm", Cell{Op: OpMapExec, Path: "bin/tool"}, TierBPFLSM, false, nil},
		{"read in an exec grant inside deny_read at landlock", Cell{Op: OpRead, Path: "secrets/bin/x", Exception: "exec", ExceptionAt: TierLandlock}, TierLandlock, false, nil},
		{"same read without the exception", Cell{Op: OpRead, Path: "secrets/bin/x"}, TierCgroup, true, nil},
		// A bind alias of a deny_read beneath a granted name (enforce-landlock E32 (ii)): the stated exception covers the
		// read through that other name at its tier only, never the target's own path.
		{"read through an alias beneath a sibling at landlock", Cell{Op: OpRead, Path: "pub/alias/k", Canon: "secrets/k", Exception: "E32 (ii)", ExceptionAt: TierLandlock}, TierLandlock, false, nil},
		{"same alias read at cgroup", Cell{Op: OpRead, Path: "pub/alias/k", Canon: "secrets/k", Exception: "E32 (ii)", ExceptionAt: TierLandlock}, TierCgroup, true, nil},
		{"the exception never covers the target's own path", Cell{Op: OpRead, Path: "secrets/k", Exception: "E32 (ii)", ExceptionAt: TierLandlock}, TierLandlock, true, nil},
		{"mknod outside write", Cell{Op: OpMknod, Path: "dev0"}, TierLandlock, true, nil},
		{"mknod inside write", Cell{Op: OpMknod, Path: "out/dev0"}, TierLandlock, false, nil},
		{"mknod under a nested deny_read at cgroup", Cell{Op: OpMknod, Path: "out/keys/dev0"}, TierCgroup, true, nil},
		{"race write under a nested deny_read at cgroup", Cell{Op: OpRaceSymlinkWrite, Path: "out/link", Dest: "out/keys/k", Canon: "out/keys/k"}, TierCgroup, true, nil},
		{"send-udp undeclared", Cell{Op: OpSendUDP, Addr: "127.0.0.1:2"}, TierCgroup, true, nil},
		{"send-udp declared", Cell{Op: OpSendUDP, Addr: "127.0.0.1:1"}, TierCgroup, false, nil},
		// Space 2: every spelling of an exec is held to exec.allow, and an anonymous image to the memfd arm (SEMANTICS §4).
		{"exec through the loader outside exec.allow", Cell{Op: OpExecLoader, Path: "bin/other"}, TierCgroup, true, nil},
		{"exec through the loader of exec.allow", Cell{Op: OpExecLoader, Path: "bin/tool"}, TierCgroup, false, nil},
		{"execveat of a descriptor outside exec.allow", Cell{Op: OpExecveatFD, Path: "bin/other"}, TierLandlock, true, nil},
		{"exec of /proc/self/fd outside exec.allow", Cell{Op: OpExecProcFD, Path: "bin/other"}, TierBPFLSM, true, nil},
		{"memfd exec where exec is restricted", Cell{Op: OpMemfdExec}, TierLandlock, true, nil},
		{"memfd map-exec where exec is restricted", Cell{Op: OpMemfdMapExec}, TierBPFLSM, true, nil},
		{"memfd exec with exec: {anonymous: true}", Cell{Op: OpMemfdExec}, TierCgroup, false, &anon},
		{"memfd exec where nothing restricts exec", Cell{Op: OpMemfdMapExec}, TierCgroup, false, &noExec},
		{"execmod of writable code at bpflsm", Cell{Op: OpExecmod, Path: "out/code"}, TierBPFLSM, true, nil},
		{"execmem of writable code at bpflsm", Cell{Op: OpExecmem, Path: "out/code"}, TierBPFLSM, true, nil},
		{"execmod at cgroup (tiers 1-2 decide no mapping)", Cell{Op: OpExecmod, Path: "out/code"}, TierCgroup, false, nil},
		{"execmod of exec.allow code at bpflsm", Cell{Op: OpExecmod, Path: "bin/tool"}, TierBPFLSM, false, nil},
		{"map-exec with READ_IMPLIES_EXEC at bpflsm", Cell{Op: OpMapExecRIE, Path: "out/code"}, TierBPFLSM, true, nil},
		{"mprotect-exec at bpflsm", Cell{Op: OpMprotectExec, Path: "out/code"}, TierBPFLSM, true, nil},
		{"mprotect with READ_IMPLIES_EXEC at bpflsm", Cell{Op: OpMprotectRIE, Path: "out/code"}, TierBPFLSM, true, nil},
		{"mprotect-exec at landlock", Cell{Op: OpMprotectExec, Path: "out/code"}, TierLandlock, false, nil},
		// The TOCTOU races (space 4): their success is the target's, Canon.
		{"race read of a deny_read", Cell{Op: OpRaceSymlinkRead, Path: "out/link", Dest: "secrets/k", Canon: "secrets/k"}, TierLandlock, true, nil},
		{"race read of a granted file", Cell{Op: OpRaceSymlinkRead, Path: "out/link", Dest: "out/a", Canon: "out/a"}, TierLandlock, false, nil},
		{"race write of a deny_write target at bpflsm", Cell{Op: OpRaceSymlinkWrite, Path: "out/link", Dest: "out/.git/config", Canon: "out/.git/config"}, TierBPFLSM, true, nil},
		{"race write of a deny_write target at landlock (best effort)", Cell{Op: OpRaceSymlinkWrite, Path: "out/link", Dest: "out/.git/config", Canon: "out/.git/config"}, TierLandlock, false, nil},
		{"race write outside write", Cell{Op: OpRaceSymlinkWrite, Path: "out/link", Dest: "notes", Canon: "notes"}, TierLandlock, true, nil},
		{"argv race that ran the denied vector unrefused", Cell{Op: OpRaceArgvExec, Path: "t/race/git", Argv: []string{"git", "push"}}, TierLandlock, true, &rules},
		// The process and control ops (E54): nothing crosses the run's boundary, and the keyring and bpf(2) stay shut.
		{"ptrace attach to the host at landlock", Cell{Op: OpPtraceAttach, Target: TargetHost}, TierLandlock, true, nil},
		{"ptrace attach to the host at cgroup", Cell{Op: OpPtraceAttach, Target: TargetHost}, TierCgroup, true, nil},
		{"ptrace attach to the host at bpflsm", Cell{Op: OpPtraceAttach, Target: TargetHost}, TierBPFLSM, true, nil},
		{"ptrace attach to the run's own child", Cell{Op: OpPtraceAttach, Target: TargetChild}, TierBPFLSM, false, nil},
		{"traceme of a tracer outside the run at bpflsm", Cell{Op: OpPtraceTraceme, Target: TargetOrphan}, TierBPFLSM, true, nil},
		{"traceme of a tracer outside the run at cgroup (Landlock admits it)", Cell{Op: OpPtraceTraceme, Target: TargetOrphan}, TierCgroup, false, nil},
		{"traceme of the run's own parent", Cell{Op: OpPtraceTraceme, Target: TargetParent}, TierBPFLSM, false, nil},
		{"keyctl without keyring: true", Cell{Op: OpKeyctl}, TierLandlock, true, nil},
		{"add_key without keyring: true", Cell{Op: OpAddKey}, TierCgroup, true, nil},
		{"request_key without keyring: true", Cell{Op: OpRequestKey}, TierBPFLSM, true, nil},
		{"keyctl with keyring: true", Cell{Op: OpKeyctl}, TierBPFLSM, false, &keyring},
		{"bpf at cgroup", Cell{Op: OpBPF}, TierCgroup, true, nil},
		{"bpf at bpflsm", Cell{Op: OpBPF}, TierBPFLSM, true, nil},
		{"bpf at landlock (tier 1 has no arm)", Cell{Op: OpBPF}, TierLandlock, false, nil},
	}
	m.DenyWrite = []string{"out/.git/config"}
	m.ExecAllow = append(m.ExecAllow, "secrets/bin")
	for _, tc := range cases {
		cm := m
		if tc.m != nil {
			cm = *tc.m
		}
		if got := Invariant(cm, &tc.c, tc.tier, ok) != ""; got != tc.want {
			t.Errorf("%s: violation=%v, want %v", tc.name, got, tc.want)
		}
		if v := Invariant(cm, &tc.c, tc.tier, Outcome{Errno: 13}); v != "" {
			t.Errorf("%s: a refused action broke %q", tc.name, v)
		}
	}
}

// TestInvariantReadIsDecidedByTheNearestEntry: a write entry nested inside a deny_read regrants read beneath it,
// and a deny_read nested inside that regrant denies again (SEMANTICS §2, nearest wins). The oracle called the
// first a fail-open at the root tiers (filesystem.yaml regranted-read, root-suites R2) because it checked only
// that some enforced deny_read covered the read.
func TestInvariantReadIsDecidedByTheNearestEntry(t *testing.T) {
	type read struct {
		name string
		m    Model
		path string
		want bool // a violation
	}
	// out is writable, so tier 1 enforces neither deny_read; the root tiers decide each read by its nearest entry.
	nested := Model{Write: []string{"out/", "out/secret/open/"}, DenyRead: []string{"out/secret/", "out/secret/open/sealed"}}
	// Nothing above keys is writable, so tier 1 enforces it too, and the regrant's union reopens it there as well.
	top := Model{Write: []string{"keys/open"}, DenyRead: []string{"keys"}}
	for _, tier := range []Tier{TierLandlock, TierCgroup, TierBPFLSM} {
		reads := []read{
			{"top-level deny_read", top, "keys/k", true},
			{"regrant inside a top-level deny_read", top, "keys/open/k", false},
			{"a sibling named like the regrant is not under it", top, "keys/openly/k", true},
		}
		if tier != TierLandlock {
			reads = append(reads,
				read{"denied subtree", nested, "out/secret/read.txt", true},
				read{"write regrant inside the deny_read", nested, "out/secret/open/read.txt", false},
				read{"deny_read inside the regrant", nested, "out/secret/open/sealed/k", true},
			)
		}
		for _, r := range reads {
			c := Cell{Op: OpRead, Path: r.path}
			if got := Invariant(r.m, &c, tier, Outcome{OK: true}) != ""; got != r.want {
				t.Errorf("%s (%s at %s): violation=%v, want %v", r.name, r.path, tier, got, r.want)
			}
		}
	}
}

// TestInvariantNearestEntryDecidesEveryAction: the nearest-wins walk of SEMANTICS §2 decides a mutation as it
// decides a read. Where the tier enforces it, a deny_read nested in a write entry refuses every modification beneath
// it (ADR 0021 (5) at tier cgroup's listener, the plane by inode), a rename or a hard link out of it included
// (supervisor R15d), and a write entry nested in that deny_read grants them again. At tier landlock the ruleset
// leaves such a deny_read unenforced (parent writable): under fs.reads: direct nothing beneath it is held to it, and
// under auto, the default, the run holds its reads, so its reads are refused and its modifications are not (ADR
// 0069). The order the contract declares its entries in decides nothing, and neither does the spelling (a symlink
// into the subtree).
func TestInvariantNearestEntryDecidesEveryAction(t *testing.T) {
	// Three levels: out is writable, out/a denied, out/a/b regranted, out/a/b/c denied again.
	deep := Model{Write: []string{"out", "out/a/b"}, DenyRead: []string{"out/a", "out/a/b/c"}, Reads: ReadsDirect}
	reversed := Model{Write: []string{"out/a/b/", "out/"}, DenyRead: []string{"out/a/b/c/", "out/a/"}, Reads: ReadsDirect}
	rootOnly := map[Tier]bool{TierCgroup: true, TierBPFLSM: true}
	none := map[Tier]bool{}
	cases := []struct {
		name string
		c    Cell
		want map[Tier]bool // a violation, per tier
	}{
		{"read in the denied level", Cell{Op: OpRead, Path: "out/a/k"}, rootOnly},
		{"read in the regranted level", Cell{Op: OpRead, Path: "out/a/b/k"}, none},
		{"read three levels deep", Cell{Op: OpRead, Path: "out/a/b/c/k"}, rootOnly},
		{"unlink regranted", Cell{Op: OpUnlink, Path: "out/a/b/f"}, none},
		{"unlink in the nested deny_read", Cell{Op: OpUnlink, Path: "out/a/f"}, rootOnly},
		{"create in the nested deny_read", Cell{Op: OpCreate, Path: "out/a/new"}, rootOnly},
		{"creat in the nested deny_read", Cell{Op: OpCreat, Path: "out/a/new-c"}, rootOnly},
		{"creat regranted", Cell{Op: OpCreat, Path: "out/a/b/new-c"}, none},
		{"mkdir three levels deep", Cell{Op: OpMkdir, Path: "out/a/b/c/d"}, rootOnly},
		{"write-open in the nested deny_read", Cell{Op: OpWriteOpen, Path: "out/a/w"}, rootOnly},
		{"truncate regranted", Cell{Op: OpTruncate, Path: "out/a/b/t"}, none},
		{"symlink created in the nested deny_read", Cell{Op: OpSymlink, Path: "out/a/l", Dest: "x"}, rootOnly},
		{"rename out of the nested deny_read", Cell{Op: OpRename, Path: "out/a/f", Dest: "out/f"}, rootOnly},
		{"rename into the nested deny_read", Cell{Op: OpRename, Path: "out/f", Dest: "out/a/f"}, rootOnly},
		{"rename within the regrant", Cell{Op: OpRename, Path: "out/a/b/f", Dest: "out/a/b/g"}, none},
		{"rename of the deny_read directory itself", Cell{Op: OpRename, Path: "out/a", Dest: "out/a.old"}, rootOnly},
		{"exchange into the nested deny_read", Cell{Op: OpExchange, Path: "out/f", Dest: "out/a/f"}, rootOnly},
		{"exchange out of the nested deny_read", Cell{Op: OpExchange, Path: "out/a/f", Dest: "out/f"}, rootOnly},
		{"exchange within the regrant", Cell{Op: OpExchange, Path: "out/a/b/f", Dest: "out/a/b/g"}, none},
		{"hard link out of the nested deny_read", Cell{Op: OpLink, Path: "out/a/f", Dest: "out/l"}, rootOnly},
		{"hard link into the regrant", Cell{Op: OpLink, Path: "out/f", Dest: "out/a/b/l"}, none},
		{"unlink spelled through a symlink into the nested deny_read", Cell{Op: OpUnlink, Path: "out/link/f", Canon: "out/a/f"}, rootOnly},
		{"write-open beside the entries", Cell{Op: OpWriteOpen, Path: "out/w"}, none},
	}
	for _, m := range []struct {
		name string
		m    Model
	}{{"declared outside in", deep}, {"declared inside out", reversed}} {
		for _, tc := range cases {
			for _, tier := range []Tier{TierLandlock, TierCgroup, TierBPFLSM} {
				if got := Invariant(m.m, &tc.c, tier, Outcome{OK: true}) != ""; got != tc.want[tier] {
					t.Errorf("%s, %s at %s: violation=%v, want %v", m.name, tc.name, tier, got, tc.want[tier])
				}
				if v := Invariant(m.m, &tc.c, tier, Outcome{Errno: 13}); v != "" {
					t.Errorf("%s, %s at %s: a refused action broke %q", m.name, tc.name, tier, v)
				}
			}
		}
	}
	// Under fs.reads: auto the reads beneath a nested deny_read are refused at tier landlock too, as at the root tiers,
	// and nothing else changes there.
	for _, m := range []Model{deep, reversed} {
		m.Reads = ""
		for _, tc := range cases {
			want := tc.want[TierLandlock] || tc.c.Op == OpRead && tc.want[TierCgroup]
			if got := Invariant(m, &tc.c, TierLandlock, Outcome{OK: true}) != ""; got != want {
				t.Errorf("fs.reads: auto, %s at landlock: violation=%v, want %v", tc.name, got, want)
			}
		}
	}
}

// TestConformanceCompile is the unprivileged compile runner: every cell against compile --test per tier. Its tego
// is the tegobpf build (the committed objects; no privilege, no kernel call), whose reach holds tiers cgroup and
// bpflsm, so the build that runs those columns answers them: a landlock-only build compiles no name entry (ADR 0043
// Consequence 11) and would answer the root columns of a name cell as if none existed.
func TestConformanceCompile(t *testing.T) {
	bin, err := buildTego(t.TempDir(), "tegobpf")
	if err != nil {
		t.Fatal(err)
	}
	actor := buildActor(t)
	failures := map[string]string{}
	ran := map[string]bool{}
	fixtures, _ := selectedFixtures(t)
	for _, fx := range fixtures {
		fx := fx
		if !hasCompileRow(&fx) {
			continue // every cell is no_compile (a memfd names no path): compile --test has nothing to answer
		}
		dir := t.TempDir()
		e := materialize(t, dir, &fx, actor)
		environ := machineConfig(t, e)
		table := compileJSON(t, bin, e, environ)
		fails, overGrants := compileFailures(t, bin, e, environ, &fx, compileReach(t, table))
		for k, v := range fails {
			failures[k] = v
		}
		for _, o := range overGrants {
			t.Errorf("COMPILE-OVER-GRANT %s", o)
		}
		// The oracle's enforcement predicates against compile's per-entry markers (capability.go): a disagreement
		// is an over-claim or an oracle stricter than the product, fixed on one side, never baselined.
		problems, err := CompileCapabilityCrossCheck(fx.Model, table, projectRel(e.project))
		if err != nil {
			t.Fatalf("%s: %v", fx.Name, err)
		}
		for _, p := range problems {
			t.Errorf("CAPABILITY %s: %s", fx.Name, p)
		}
		for i := range fx.Cells {
			c := &fx.Cells[i]
			if _, ok := compileAction(c); !ok || c.NoCompile != "" {
				continue
			}
			for _, tier := range c.Tiers() {
				ran[RunnerCompile+"|"+string(tier)] = true
			}
		}
	}
	settleBaseline(t, "compile --test and a cell", ran, failures)
	t.Logf("%d compile disagreements", len(failures))
}

// TestActorIsStatic guards what the cells assume of the agent: the actor is a static, CGO-off build, so it runs in
// any guest without a loader and no fixture's contract has to grant one (a dynamically linked actor would open
// and map its loader and libraries before its own code runs). Tier 2 itself no longer needs a static stage: its
// marks are placed after the stage's execve (ADR 0021 (4)).
func TestActorIsStatic(t *testing.T) {
	if why, err := dynamicReason(buildActor(t)); err != nil {
		t.Fatal(err)
	} else if why != "" {
		t.Errorf("the actor is dynamically linked: it %s", why)
	}
}

// dynamicReason says why the ELF at path is dynamically linked ("" when it is static): a PT_INTERP program
// header (whatever loader path it names) or DT_NEEDED entries. That, not a loader's name appearing in the bytes,
// is what makes the kernel run a loader before the actor's own code.
func dynamicReason(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return "has a PT_INTERP program header", nil
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		return "needs " + strings.Join(libs, ", "), nil
	}
	return "", nil
}

// TestDynamicReasonSeesAnyInterpreter checks the check itself: an ELF naming a musl loader in its PT_INTERP (no
// "ld-linux" anywhere in it) is dynamic, and a -buildmode=exe actor is not. The dynamic one is written here, a minimal
// ELF64 executable of one PT_INTERP program header, rather than linked: the KVM guest's go shim serves the prebuilt
// static actor for every build of the package (test/vm/go-shim.sh), whatever -buildmode and -ldflags ask, so a
// linked PIE never reached the check there.
func TestDynamicReasonSeesAnyInterpreter(t *testing.T) {
	// In the root guest `go` is test/vm/go-shim.sh, which serves the prebuilt static actor whatever the flags, so
	// the PIE build this check needs cannot be made there; the shim answers nothing but `go build`.
	if err := exec.Command("go", "version").Run(); err != nil {
		t.Skipf("no Go toolchain to build a PIE actor with (go version: %v)", err)
	}
	dir := t.TempDir()
	musl := filepath.Join(dir, "actor-musl")
	if err := os.WriteFile(musl, elfWithInterp("/lib/ld-musl-x86_64.so.1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if why, err := dynamicReason(musl); err != nil || why == "" {
		t.Errorf("an ELF with a musl interpreter: reason %q, err %v; want it reported dynamic", why, err)
	}
	static := filepath.Join(dir, "actor-static")
	cmd := exec.Command("go", "build", "-o", static, "-buildmode=exe", "github.com/attention-span-ai/tego/test/conformance/cmd/actor")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, b)
	}
	if why, err := dynamicReason(static); err != nil || why != "" {
		t.Errorf("a -buildmode=exe actor: reason %q, err %v; want static", why, err)
	}
}

// elfWithInterp is a minimal little-endian ELF64 x86-64 executable whose one program header is a PT_INTERP naming
// interp: all debug/elf needs to read the program headers.
func elfWithInterp(interp string) []byte {
	const ehsize, phsize = 64, 56
	name := append([]byte(interp), 0)
	b := make([]byte, ehsize+phsize+len(name))
	le := binary.LittleEndian
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(b[16:], uint16(elf.ET_EXEC))
	le.PutUint16(b[18:], uint16(elf.EM_X86_64))
	le.PutUint32(b[20:], uint32(elf.EV_CURRENT))
	le.PutUint64(b[32:], ehsize) // e_phoff
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[54:], phsize)
	le.PutUint16(b[56:], 1) // e_phnum
	ph := b[ehsize:]
	le.PutUint32(ph[0:], uint32(elf.PT_INTERP))
	le.PutUint32(ph[4:], uint32(elf.PF_R))
	le.PutUint64(ph[8:], ehsize+phsize)      // p_offset
	le.PutUint64(ph[32:], uint64(len(name))) // p_filesz
	le.PutUint64(ph[40:], uint64(len(name))) // p_memsz
	le.PutUint64(ph[48:], 1)
	copy(b[ehsize+phsize:], name)
	return b
}

// TestCellNamesMatchOps: a cell named for a send must do a send (OpSendUDP, an unconnected sendto), so no
// "send-*" cell claims coverage of the sendto/sendmsg path through a connect; and the undeclared send is a cell.
func TestCellNamesMatchOps(t *testing.T) {
	found := false
	for _, fx := range Fixtures() {
		for _, c := range fx.Cells {
			if strings.HasPrefix(c.Name, "send-") && c.Op != OpSendUDP {
				t.Errorf("%s/%s is named for a send but its op is %s", fx.Name, c.Name, c.Op)
			}
			found = found || fx.ID(&c) == "net/send-udp-undeclared" && c.Op == OpSendUDP
		}
	}
	if !found {
		t.Error("the unconnected UDP send to an undeclared destination is no cell")
	}
}
