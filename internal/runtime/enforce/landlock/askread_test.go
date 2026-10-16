// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// An fs.ask_read entry (POC 2026-10-06) is a deny_read to the ruleset: its target is sealed with no right and its
// ancestors get READ_DIR only, exactly as a plain deny_read's, so a read the supervisor does not hold is refused
// by the kernel. And because the supervisor has to find the reads it holds, the filter notifies every open under
// every record mode, as record: full does; a table without one keeps the write-only open arm.
func TestAskReadIsADenyReadToTheRulesetAndNotifiesEveryOpen(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "vault/token", "vault/other", "work/")
	vault := filepath.Join(root, "vault")
	for _, mode := range []agent.RecordMode{agent.RecordSummary, agent.RecordOff, agent.RecordFull} {
		ask := agent.FSRule{Path: vault, Resolved: vault, Kind: agent.FSDenyRead, AskRead: true, Raw: vault}
		rt := &agent.RuleTable{Contract: contractWith(true, true), Record: mode, FS: []agent.FSRule{ask}}
		h, _ := prepare(t, 7, rt)
		target, ok := h.entry(vault)
		if !ok || target.Kind != kindDenyTarget || target.Access != 0 {
			t.Fatalf("%s: the ask_read target %+v, %v: want sealed with no right, as a deny_read", mode, target, ok)
		}
		assertAncestorOnly(t, h, root, []string{"vault"})
		if !h.filterOpts.askRead {
			t.Fatalf("%s: the filter was built without the ask_read open arm", mode)
		}
		for _, arch := range []Arch{ArchX86_64, ArchARM64} {
			tab, err := tableFor(arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, open := range []struct {
				nr   uint32
				args []uint64
			}{{tab.Open, []uint64{0x1234, unix.O_RDONLY}}, {tab.OpenAt, []uint64{3, 0x1234, unix.O_RDONLY}}} {
				if open.nr == noSyscall {
					continue
				}
				if got := planeVerdict(t, arch, h.filterOpts, open.nr, open.args...); got != retNotify {
					t.Fatalf("%s: a read-open on %s answered %#x, want a notification", mode, arch, got)
				}
			}
		}
		if !hasAsk(rt) {
			t.Fatalf("%s: an ask_read table permitted a plane notification handover", mode)
		}
		// The same table with the marker off is an ordinary deny_read: reads are notified under full only.
		plain := &agent.RuleTable{Contract: contractWith(true, true), Record: mode, FS: []agent.FSRule{{Path: vault, Resolved: vault, Kind: agent.FSDenyRead}}}
		ph, _ := prepare(t, 7, plain)
		if ph.filterOpts.askRead {
			t.Fatalf("%s: a deny_read alone turned the ask_read arm on", mode)
		}
		tab, _ := tableFor(ArchX86_64)
		want := uint32(retAllow)
		if mode == agent.RecordFull {
			want = retNotify
		}
		if got := planeVerdict(t, ArchX86_64, ph.filterOpts, tab.OpenAt, 3, 0x1234, unix.O_RDONLY); got != want {
			t.Fatalf("%s: a deny_read-only table's read-open answered %#x, want %#x", mode, got, want)
		}
	}
}
