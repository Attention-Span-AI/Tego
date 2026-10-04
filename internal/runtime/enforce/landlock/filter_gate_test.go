// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestGateReadNotifiesUnderSummaryAndOffOnBothArchitectures(t *testing.T) {
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
			if got := planeVerdict(t, arch, filterOpts{abi: 10}, open.nr, open.args...); got != retAllow {
				t.Fatalf("legacy read on %s: %#x", arch, got)
			}
			if got := planeVerdict(t, arch, filterOpts{abi: 10, gateRead: true}, open.nr, open.args...); got != retNotify {
				t.Fatalf("gate read on %s: %#x", arch, got)
			}
		}
	}
}

// TestWriteGateNotifiesTheChmodFamilyUnderEveryRecordLevel: the supervisor scores a mode change as an fs.write
// (gateFS) and refuses one above the threshold, but the filter notified the chmod family under record: full only,
// so under the default summary, and off, an fs.write gate never saw a chmod the kernel then performed with no
// decision and no line (gate.md: enabled action kinds retain notifications in summary/off). With no write gate,
// or a read gate alone, the family stays record: full only.
func TestWriteGateNotifiesTheChmodFamilyUnderEveryRecordLevel(t *testing.T) {
	write, err := gate.New([]gate.Rule{{Predicate: gate.WriteOutsideWorktree, Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	read, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "/secret/*", Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		gate *gate.Policy
		mode agent.RecordMode
		want uint32
	}{
		{"write gate, summary", write, agent.RecordSummary, retNotify},
		{"write gate, off", write, agent.RecordOff, retNotify},
		{"write gate, full", write, agent.RecordFull, retNotify},
		{"read gate, summary", read, agent.RecordSummary, retAllow},
		{"no gate, off", nil, agent.RecordOff, retAllow},
		{"no gate, full", nil, agent.RecordFull, retNotify},
	} {
		h, _ := prepare(t, 7, &agent.RuleTable{Contract: &agent.Contract{}, Gate: tc.gate, Record: tc.mode})
		for _, arch := range []Arch{ArchX86_64, ArchARM64} {
			tab, err := tableFor(arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tab.Chmod {
				if got := planeVerdict(t, arch, h.filterOpts, s.NR, 3, 0x1234, 0o777); got != tc.want {
					t.Errorf("%s: %s %s answered %#x, want %#x", tc.name, arch, s.Name, got, tc.want)
				}
			}
		}
	}
}

// attrWrites are the attribute-change families beside chmod: the extended-attribute calls that set or remove an
// attribute (setxattr(2) and removexattr(2) with their l- and f- forms, and the *at forms of 6.13) and the chown
// family. chown and lchown are x86-64's legacy forms, which arm64's generic table does not have.
var attrWrites = []string{"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",
	"setxattrat", "removexattrat", "chown", "lchown", "fchown", "fchownat"}

// TestWriteGateNotifiesTheAttributeFamilies of GATE-STEP2-ROWS: a POSIX ACL is an extended
// attribute (system.posix_acl_access), and setting one rewrites the file's mode bits as chmod(2) does, so under an
// fs.write gate `setfacl -m u::rwx,g::r-x,o::r-x ../outside/p.txt` turned a 0600 file outside the worktree 0755 while
// chmod of it was refused: the filter notified the xattr family under no option, so the gate never scored it and no
// line was written. A chown, which hands the group bits to another group, was the same gap. A write gate now has the
// filter notify every call that sets or removes an attribute, and the chown family, at every record level, so the
// supervisor scores each as a write (recordAttr). Without a write gate neither family is notified, record: full
// included: nothing below a decision plane refuses one, and record: full's promise is reads, mmap and chmod.
func TestWriteGateNotifiesTheAttributeFamilies(t *testing.T) {
	write, err := gate.New([]gate.Rule{{Predicate: gate.WriteOutsideWorktree, Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	read, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "/secret/*", Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		gate *gate.Policy
		mode agent.RecordMode
		want uint32
	}{
		{"write gate, summary", write, agent.RecordSummary, retNotify},
		{"write gate, off", write, agent.RecordOff, retNotify},
		{"write gate, full", write, agent.RecordFull, retNotify},
		{"read gate, summary", read, agent.RecordSummary, retAllow},
		{"read gate, full", read, agent.RecordFull, retAllow},
		{"no gate, off", nil, agent.RecordOff, retAllow},
		{"no gate, full", nil, agent.RecordFull, retAllow},
	} {
		h, _ := prepare(t, 7, &agent.RuleTable{Contract: &agent.Contract{}, Gate: tc.gate, Record: tc.mode})
		for _, c := range []struct {
			arch   Arch
			goarch string
		}{{ArchX86_64, "amd64"}, {ArchARM64, "arm64"}} {
			canon, err := testutil.LinuxSyscalls(c.goarch)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range attrWrites {
				nr, ok := canon[name]
				if !ok && c.goarch == "arm64" && (name == "chown" || name == "lchown") {
					continue
				}
				if !ok {
					t.Fatalf("%s has no %s", c.goarch, name)
				}
				if got := planeVerdict(t, c.arch, h.filterOpts, nr, 3, 0x1234, 0x2345, 0, 0); got != tc.want {
					t.Errorf("%s: %s %s answered %#x, want %#x", tc.name, c.arch, name, got, tc.want)
				}
			}
		}
	}
}

// TestWriteGateFilterGolden keeps a human-readable dump of the filter of a run whose gate scores fs.write, per arch,
// under record: summary (gateWrite, ADR 0041 Step 2): TestFilterGolden's plain filter plus the notify arms of the
// chmod family and of the xattr and chown families, which is what a reviewer diffs when the
// gate's notified set changes.
func TestWriteGateFilterGolden(t *testing.T) {
	for _, tc := range []struct {
		file string
		arch Arch
	}{
		{"filter_x86_64_gate_write.txt", ArchX86_64},
		{"filter_arm64_gate_write.txt", ArchARM64},
	} {
		t.Run(tc.file, func(t *testing.T) {
			insts, err := buildFilter(tc.arch, filterOpts{abi: minTruncateABI, unixBinds: true, gateWrite: true})
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			for i, ins := range insts {
				fmt.Fprintf(&buf, "%3d %-16T %v\n", i, ins, ins)
			}
			path := filepath.Join("testdata", tc.file)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if !bytes.Equal(want, buf.Bytes()) {
				t.Errorf("write-gate filter differs from %s:\n%s", path, buf.String())
			}
		})
	}
}

func TestFilesystemGateKeepsPlaneNotifications(t *testing.T) {
	for _, predicate := range []gate.Predicate{gate.ReadMatches, gate.WriteOutsideWorktree} {
		argument := "/secret/*"
		if predicate == gate.WriteOutsideWorktree {
			argument = ""
		}
		p, err := gate.New([]gate.Rule{{Predicate: predicate, Argument: argument, Score: 90}}, 50, 80)
		if err != nil {
			t.Fatal(err)
		}
		if !hasAsk(&agent.RuleTable{Gate: p}) {
			t.Fatal("filesystem gate permitted notification handover")
		}
	}
}
