// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// stallWarnings is the stall-reads-unseen findings among ds.
func stallWarnings(ds []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Code == CodeStallReadsUnseen {
			out = append(out, d)
		}
	}
	return out
}

// TestStallAfterWarnsWhereReadsAreUnseen (custom-agent POC, item 4): at tier landlock under record: summary or off a
// read is never a line, so a stall_after the contract sets ends an agent that only reads. Compile says so, naming
// record: full and a root tier as the ways out, at landlock alone (so `tego run` prints it again once a run lands
// there). At a root tier under record: summary a read is counted in an aggregate flushed every 5 s, so a stall_after
// under twice that window is warned there, at the root tiers alone. At a root tier under record: off
// each allowed open, path change and connect of a stall-bounded run stamps the run's activity in the kernel
// (limits R4), so a root tier under off is not warned whatever the stall_after, and the landlock warning
// under off offers it as it is, with no record: summary and no 10s floor (it was warned there, and offered only with
// summary, while an allowed open made no sample). record: full, a long stall_after
// at a root tier under summary and a contract with no stall_after are not warned. The binary builds landlock and
// cgroup, so the only root tier a fix may offer to pin is cgroup.
func TestStallAfterWarnsWhereReadsAreUnseen(t *testing.T) {
	const base = "version: 0\nname: stallreads\ncommand: [\"/bin/sh\"]\n"
	landlock := []backend.Tier{backend.TierLandlock}
	cgroup := []backend.Tier{backend.TierCgroup}
	for _, tc := range []struct {
		name, extra string
		want        [][]backend.Tier // the tiers of each warning, in the order Compile sorts them
	}{
		{"landlock, summary", "tier: landlock\nrecord: summary\nlimits: {stall_after: 5s}\n", [][]backend.Tier{landlock}},
		{"landlock, the default record", "tier: landlock\nlimits: {stall_after: 5s}\n", [][]backend.Tier{landlock}},
		{"landlock, off", "tier: landlock\nrecord: off\nlimits: {stall_after: 5s}\n", [][]backend.Tier{landlock}},
		{"auto, summary, short", "limits: {stall_after: 5s}\n", [][]backend.Tier{cgroup, landlock}}, // sorted by message
		{"auto, summary, long", "limits: {stall_after: 10s}\n", [][]backend.Tier{landlock}},
		{"auto, off", "record: off\nlimits: {stall_after: 5s}\n", [][]backend.Tier{landlock}},
		{"landlock, full", "tier: landlock\nrecord: full\nlimits: {stall_after: 5s}\n", nil},
		{"pinned cgroup, summary, 2s", "tier: cgroup\nlimits: {stall_after: 2s}\n", [][]backend.Tier{cgroup}},
		{"pinned cgroup, summary, 9s", "tier: cgroup\nlimits: {stall_after: 9s}\n", [][]backend.Tier{cgroup}},
		{"pinned cgroup, summary, 10s", "tier: cgroup\nlimits: {stall_after: 10s}\n", nil},
		{"pinned cgroup, off", "tier: cgroup\nrecord: off\nlimits: {stall_after: 2s}\n", nil},
		{"pinned cgroup, off, long", "tier: cgroup\nrecord: off\nlimits: {stall_after: 1m}\n", nil},
		{"pinned cgroup, full", "tier: cgroup\nrecord: full\nlimits: {stall_after: 2s}\n", nil},
		{"landlock, no stall_after", "tier: landlock\nlimits: {wall: 1h}\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.load(base + tc.extra)
			_, ds := f.compile(c, WithTiers(backend.TierLandlock, backend.TierCgroup))
			got := stallWarnings(ds)
			if len(got) != len(tc.want) {
				t.Fatalf("%d warnings, want %d:\n%s", len(got), len(tc.want), render(ds))
			}
			off := strings.Contains(tc.extra, "record: off")
			for i, d := range got {
				if !slices.Equal(d.Tiers(), tc.want[i]) {
					t.Fatalf("warning %d holds in %v, want %v: %+v", i, d.Tiers(), tc.want[i], d)
				}
				if d.Severity != SeverityWarning || !strings.Contains(d.Message, "stall_after") || !strings.Contains(d.Fix, "record: full") {
					t.Fatalf("the warning %+v: want a warning naming record: full", d)
				}
				// No fix offers record: off, nor a tier this binary does not build.
				if strings.Contains(d.Fix, "record: off") || strings.Contains(d.Fix, "bpflsm") {
					t.Fatalf("the fix %q: offers record: off or a tier the binary does not build", d.Fix)
				}
				if d.Tier != backend.TierLandlock && off {
					t.Fatalf("a root tier under record: off is warned, though its kernel stamps each allowed open as activity: %+v", d)
				}
				switch {
				case d.Tier == backend.TierLandlock && off:
					// Under off a root tier counts each allowed open at once, through the kernel's stamp, so it is
					// offered as it is: no record: summary and no 10s floor.
					if !strings.Contains(d.Fix, "pin tier: cgroup, where the kernel stamps each allowed open as activity at once") ||
						strings.Contains(d.Fix, "at least 10s") || strings.Contains(d.Fix, "summary") {
						t.Fatalf("the landlock record: off warning's fix %q: want tier cgroup, whose kernel stamps each allowed open, with no summary and no floor", d.Fix)
					}
				case d.Tier == backend.TierLandlock:
					// Under summary a root tier is a way out only with a stall_after past twice the window.
					if !strings.Contains(d.Fix, "pin tier: cgroup with a stall_after of at least 10s") || strings.Contains(d.Fix, "activity at once") {
						t.Fatalf("the landlock warning's fix %q: want tier cgroup with a stall_after of at least 10s", d.Fix)
					}
				default:
					if !strings.Contains(d.Message, "flushed every 5s") || !strings.Contains(d.Fix, "at least 10s") {
						t.Fatalf("the root-tier warning %+v: want the 5s window and a stall_after of at least 10s", d)
					}
				}
			}
		})
	}
}

// stallExpect is what the stall warning printed at one tier says.
type stallExpect struct {
	says        string
	fix, notFix []string // what its fix says, and does not
}

// TestStallWarningFollowsTheRunsRecordAndObserve: the warning is derived from the record the
// run makes (WithRecord, `tego run --record`), not the contract's, and an --observe run (WithObserve), which installs
// tier landlock's filter, is warned too, in TierObserve, even for a contract that pins a root tier. Its fix offers only
// what changes that run: no root tier for a warning that holds in an --observe run
// alone, a root tier outside --observe when it holds at landlock too, only a root tier this binary builds and the
// machine's tier ceiling admits, and --record wording for a mode that came from it. Under record: off a root tier counts
// each allowed open at once through the kernel's activity stamp, so it is not warned there and is
// offered as it is (it was warned, and offered only with record: summary, while an open made no sample).
func TestStallWarningFollowsTheRunsRecordAndObserve(t *testing.T) {
	const base = "version: 0\nname: stallreads\ncommand: [\"/bin/sh\"]\nlimits: {stall_after: 2s}\n"
	ll, ob, cg := backend.TierLandlock, backend.TierObserve, backend.TierCgroup
	for _, tc := range []struct {
		name, extra string
		opts        []CompileOption
		ceiling     backend.Tier // the machine config's tier, "" for auto
		record      RecordMode
		at          map[backend.Tier]stallExpect // the tiers ForTier prints the warning at, and what it says there
	}{
		{"summary contract, --record full", "tier: landlock\nrecord: summary\n", []CompileOption{WithRecord(RecordFull)}, "", RecordFull, nil},
		{"full contract, --record summary", "tier: landlock\nrecord: full\n", []CompileOption{WithRecord(RecordSummary)}, "", RecordSummary,
			map[backend.Tier]stallExpect{ll: {says: "under --record summary",
				fix: []string{"run with --record full", "pin tier: cgroup with a stall_after of at least 10s"}, notFix: []string{"set record", "outside --observe", "bpflsm"}}}},
		{"full contract, --record off", "tier: landlock\nrecord: full\n", []CompileOption{WithRecord(RecordOff)}, "", RecordOff,
			map[backend.Tier]stallExpect{ll: {says: "under --record off",
				fix:    []string{"run with --record full", "pin tier: cgroup, where the kernel stamps each allowed open as activity at once"},
				notFix: []string{"set record", "summary", "at least 10s"}}}},
		{"landlock, --observe", "tier: landlock\n", []CompileOption{WithObserve()}, "", RecordSummary,
			map[backend.Tier]stallExpect{
				ll: {says: "at tier landlock and in an --observe run", fix: []string{"set record: full", "outside --observe, pin tier: cgroup"}},
				ob: {says: "at tier landlock and in an --observe run", fix: []string{"set record: full", "outside --observe, pin tier: cgroup"}},
			}},
		{"pinned cgroup, off, --observe", "tier: cgroup\nrecord: off\n", []CompileOption{WithObserve()}, "", RecordOff,
			map[backend.Tier]stallExpect{
				ob: {says: "in an --observe run", fix: []string{"set record: full", "raise stall_after"}, notFix: []string{"root tier", "pin tier"}},
			}},
		{"pinned cgroup, summary, --observe", "tier: cgroup\nrecord: summary\n", []CompileOption{WithObserve()}, "", RecordSummary,
			map[backend.Tier]stallExpect{ob: {notFix: []string{"pin tier"}}, cg: {notFix: []string{"pin tier"}}}},
		{"pinned cgroup, --record summary", "tier: cgroup\nrecord: full\n", []CompileOption{WithRecord(RecordSummary)}, "", RecordSummary,
			map[backend.Tier]stallExpect{cg: {says: "at tier cgroup under --record summary", fix: []string{"run with --record full"}, notFix: []string{"set record", "--record off"}}}},
		{"pinned cgroup, --record off", "tier: cgroup\nrecord: full\n", []CompileOption{WithRecord(RecordOff)}, "", RecordOff, nil},
		{"pinned cgroup, summary contract", "tier: cgroup\nrecord: summary\n", nil, "", RecordSummary,
			map[backend.Tier]stallExpect{cg: {says: "at tier cgroup under record: summary", fix: []string{"set record: full", "raise stall_after to at least 10s"}, notFix: []string{"--record", "record: off", "activity at once"}}}},
		{"--observe, record: full", "tier: landlock\nrecord: full\n", []CompileOption{WithObserve()}, "", RecordFull, nil},
		// A root tier is offered only where pinning one changes the run.
		{"landlock-only build", "tier: landlock\n", []CompileOption{WithTiers(backend.TierLandlock)}, "", RecordSummary,
			map[backend.Tier]stallExpect{ll: {fix: []string{"set record: full", "raise stall_after"}, notFix: []string{"pin", "root tier"}}}},
		{"machine ceiling landlock", "tier: landlock\n", nil, backend.TierLandlock, RecordSummary,
			map[backend.Tier]stallExpect{ll: {fix: []string{"set record: full", "raise stall_after"}, notFix: []string{"pin", "root tier"}}}},
		{"machine ceiling landlock, off", "tier: landlock\nrecord: off\n", nil, backend.TierLandlock, RecordOff,
			map[backend.Tier]stallExpect{ll: {fix: []string{"set record: full", "raise stall_after"}, notFix: []string{"pin", "root tier", "summary"}}}},
		{"every tier built", "tier: landlock\n", []CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)}, "", RecordSummary,
			map[backend.Tier]stallExpect{ll: {fix: []string{"pin a root tier (cgroup or bpflsm) with a stall_after of at least 10s"}}}},
		// `tego run --tier landlock` pins the run, and a contract's tier: cgroup then
		// conflicts with the flag, so the root tier is offered without the flag.
		{"--tier landlock, every tier built", "tier: landlock\n", []CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM), WithTierFlag(backend.TierLandlock)}, "", RecordSummary,
			map[backend.Tier]stallExpect{ll: {fix: []string{"without --tier landlock, pin a root tier (cgroup or bpflsm) with a stall_after of at least 10s"}}}},
		{"--tier landlock, --observe", "tier: landlock\n", []CompileOption{WithTierFlag(backend.TierLandlock), WithObserve()}, "", RecordSummary,
			map[backend.Tier]stallExpect{
				ll: {fix: []string{"outside --observe and without --tier landlock, pin tier: cgroup"}},
				ob: {fix: []string{"outside --observe and without --tier landlock, pin tier: cgroup"}},
			}},
		{"machine ceiling cgroup, every tier built", "tier: landlock\n", []CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)}, backend.TierCgroup, RecordSummary,
			map[backend.Tier]stallExpect{ll: {fix: []string{"pin tier: cgroup with a stall_after of at least 10s"}, notFix: []string{"bpflsm"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.ceiling != "" {
				f.machine.Tier = tierCeil(tc.ceiling)
			}
			c := f.load(base + tc.extra)
			rt, ds := f.compile(c, append([]CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup)}, tc.opts...)...)
			if rt.Record != tc.record {
				t.Fatalf("the table's record is %s, want %s", rt.Record, tc.record)
			}
			for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierObserve, backend.TierCgroup, backend.TierBPFLSM} {
				got := stallWarnings(ForTier(ds, tier))
				want, ok := tc.at[tier]
				if (len(got) > 0) != ok {
					t.Fatalf("at tier %s: warned %v, want %v:\n%s", tier, len(got) > 0, ok, render(ds))
				}
				if !ok {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("at tier %s: %d stall warnings, want one:\n%s", tier, len(got), render(ds))
				}
				if !strings.Contains(got[0].Message, want.says) {
					t.Fatalf("at tier %s: %q, want it to say %q", tier, got[0].Message, want.says)
				}
				for _, s := range want.fix {
					if !strings.Contains(got[0].Fix, s) {
						t.Fatalf("at tier %s: the fix %q, want it to say %q", tier, got[0].Fix, s)
					}
				}
				for _, s := range want.notFix {
					if strings.Contains(got[0].Fix, s) {
						t.Fatalf("at tier %s: the fix %q says %q, which does not change this run", tier, got[0].Fix, s)
					}
				}
			}
		})
	}
}

// TestStallWarningFollowsWhatTheFilterNotifies: what the warning calls
// unseen is what the run's filter and recorder leave out, which the contract's gate and ask entries change. A read gate
// or an fs.ask_read entry has the filter notify every read-open at every tier, and under record: off each
// notification the supervisor answers is activity, so a reader is not stalled there; under summary a read the gate
// scores is its own line at every tier, but an fs.ask_read entry alone records none (quietRead). At a root tier
// under off nothing is warned whatever the gate and ask entries: what the supervisor is not notified of, the kernel
// stamps (before, an fs gate or ask entry left reads alone unseen there and the warning said reads
// alone). A pure reader under a read gate, and a pure writer under a read gate or an fs.ask scope, ran to their end
// in the KVM guest under a warning that said they were ended as stalled.
func TestStallWarningFollowsWhatTheFilterNotifies(t *testing.T) {
	ll, cg := backend.TierLandlock, backend.TierCgroup
	type want struct {
		says, notSays []string
		fix, notFix   []string
	}
	landlockReads := want{says: []string{"at tier landlock under", "a read is not recorded"}}
	const readGate, writeGate = `fs.read matches "*.pem"`, "fs.write outside worktree"
	for _, tc := range []struct {
		name, tier, record, fs, gate string
		at                           map[backend.Tier]want // the tiers a warning holds at, and what it says
	}{
		{"landlock, off, read gate", "landlock", "off", "", readGate, nil},
		{"landlock, summary, read gate", "landlock", "summary", "", readGate, nil},
		{"landlock, off, ask_read", "landlock", "off", "ask_read", "", nil},
		// An fs.ask_read entry alone notifies reads but records none under summary (quietRead), so they are no line.
		{"landlock, summary, ask_read", "landlock", "summary", "ask_read", "", map[backend.Tier]want{ll: landlockReads}},
		{"landlock, off, fs.ask", "landlock", "off", "ask", "", map[backend.Tier]want{ll: landlockReads}},
		{"landlock, off, write gate", "landlock", "off", "", writeGate, map[backend.Tier]want{ll: landlockReads}},
		// fs.ask_read compiles at tier landlock alone (TestAskReadRefusedAtTiersThatCannotHoldARead), so no root-tier
		// case has one.
		{"cgroup, off, read gate", "cgroup", "off", "", readGate, nil},
		{"cgroup, off, fs.ask", "cgroup", "off", "ask", "", nil},
		{"cgroup, off, write gate", "cgroup", "off", "", writeGate, nil},
		// Under summary a read the gate scores is its own event at a root tier too (the recorder's gate-scored read
		// skips the aggregate), so the window does not delay it.
		{"cgroup, summary, read gate", "cgroup", "summary", "", readGate, nil},
		{"cgroup, summary, write gate", "cgroup", "summary", "", writeGate, map[backend.Tier]want{cg: {says: []string{"flushed every 5s"}}}},
		{"cgroup, off, no gate or ask", "cgroup", "off", "", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			secret := filepath.Join(f.root, "vault", "token")
			if err := os.MkdirAll(filepath.Dir(secret), 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(secret, "real", 0o600)
			y := "version: 0\nname: stallreads\ncommand: [\"/bin/sh\"]\ntier: " + tc.tier + "\nrecord: " + tc.record +
				"\nlimits: {stall_after: 2s}\nfs:\n  write: [\"out/\"]\n"
			switch tc.fs {
			case "ask_read":
				y += "  ask_read: [\"" + secret + "\"]\n"
			case "ask":
				y += "  ask: [\"sealed/\"]\n"
			}
			if tc.gate != "" {
				y += "gate:\n  rules:\n    - '" + tc.gate + "': 10\n"
			}
			rt, ds := f.compile(f.load(y), WithTiers(backend.TierLandlock, backend.TierCgroup))
			if got := rt.NotifiesReads(); got != (tc.fs == "ask_read" || tc.gate == readGate) {
				t.Fatalf("NotifiesReads() = %v", got)
			}
			if got := rt.HoldsFSNotifications(); got != (tc.fs != "" || tc.gate != "") {
				t.Fatalf("HoldsFSNotifications() = %v", got)
			}
			for _, tier := range []backend.Tier{ll, backend.TierObserve, cg, backend.TierBPFLSM} {
				got := stallWarnings(ForTier(ds, tier))
				w, ok := tc.at[tier]
				if (len(got) > 0) != ok {
					t.Fatalf("at tier %s: warned %v, want %v:\n%s", tier, len(got) > 0, ok, render(ds))
				}
				if !ok {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("at tier %s: %d stall warnings, want one:\n%s", tier, len(got), render(ds))
				}
				for _, s := range w.says {
					if !strings.Contains(got[0].Message, s) {
						t.Fatalf("at tier %s: %q, want it to say %q", tier, got[0].Message, s)
					}
				}
				for _, s := range w.notSays {
					if strings.Contains(got[0].Message, s) {
						t.Fatalf("at tier %s: %q says %q", tier, got[0].Message, s)
					}
				}
				for _, s := range w.fix {
					if !strings.Contains(got[0].Fix, s) {
						t.Fatalf("at tier %s: the fix %q, want it to say %q", tier, got[0].Fix, s)
					}
				}
				for _, s := range w.notFix {
					if strings.Contains(got[0].Fix, s) {
						t.Fatalf("at tier %s: the fix %q says %q", tier, got[0].Fix, s)
					}
				}
			}
		})
	}
}
