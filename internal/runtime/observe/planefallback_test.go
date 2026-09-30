// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// planeFSSample builds the plane's own fallback sample (KindPlaneFS, struct tego_ev_plane) of a refusal on a hook
// whose recorder fexit is not attached: the object's directory and final component, and file_open's flags.
func planeFSSample(h sample, hook uint16, rule uint32, dev, dirIno uint64, name string, flags uint32) []byte {
	h.Kind = KindPlaneFS
	h.Verdict = KernelRefused
	h.RuleIdx = uint16(rule)
	e := bpf.PlaneEvent{Hdr: h.header(PlaneSize), StartNS: h.Start, RuleIdx: rule, Hook: hook, Dev: kernelDev(dev),
		DirIno: dirIno, Flags: flags}
	copy(e.Path[:], fixed(name, PathMax))
	if len(name) > 0 && len(name) < PathMax {
		e.PathOK = 1
	}
	return wire(&e)
}

// TestRecorderNamesPlaneFallbackSamples is TIER3-PLAN T9b in the recorder (enforce-plane §7, R23): where the build's
// recorder fexit on a hook is not attached, the plane's own sample of the refusal (KindPlaneFS) is the action's one
// fs line, named as that fexit's line would have been: the operation its hook stands for (an rmdir the unlink, a
// mknod the open with O_CREAT, both truncate hooks the truncate), the file through the directory index, the rule
// and reason compile --test's bpflsm column gives the same action, mechanism plane and the mode; kept under
// record: off, since each is a refusal.
func TestRecorderNamesPlaneFallbackSamples(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t)
			rt, rows := planeTable(f)
			rt.Record = mode
			f.rules = rt
			s := filepath.Join(f.out, "s")
			if err := os.Mkdir(s, 0o755); err != nil {
				t.Fatal(err)
			}
			di, ok := statDevIno(s)
			if !ok {
				t.Fatal("could not stat the deny_read directory")
			}
			row := uint32(planeRow(t, rows, s))
			eval := decide.NewPlaneEvaluator(rt)
			at := func(name string) string { return filepath.Join(s, name) }
			cases := []struct {
				hook, name string
				code       bpf.ReasonCode
				rule       uint32
				flags      uint32
				op         string
				wantFlags  int
				action     agent.Action
				planeWhy   string
			}{
				{"file_open", "k", bpf.ReasonReadDenied, row, unix.O_RDONLY, record.FSOpen, unix.O_RDONLY,
					agent.Action{Kind: agent.ActionFSRead, Path: at("k")}, ""},
				{"file_open", "w", bpf.ReasonReadDenied, row, unix.O_RDWR, record.FSOpen, unix.O_RDWR,
					agent.Action{Kind: agent.ActionFSRead, Path: at("w")}, ""},
				{"path_unlink", "k", bpf.ReasonDeleteOutsideContract, row, 0, record.FSUnlink, 0,
					agent.Action{Kind: agent.ActionFSDelete, Path: at("k")}, ""},
				{"path_rmdir", "d", bpf.ReasonDeleteOutsideContract, row, 0, record.FSUnlink, 0,
					agent.Action{Kind: agent.ActionFSDelete, Path: at("d")}, ""},
				{"path_rename", "k", bpf.ReasonRenameOutsideContract, row, 0, record.FSRename, 0,
					agent.Action{Kind: agent.ActionFSRename, Path: at("k"), DestPath: filepath.Join(f.out, "k2")}, ""},
				{"path_mknod", "n", bpf.ReasonWriteOutsideContract, row, 0, record.FSOpen, unix.O_CREAT,
					agent.Action{Kind: agent.ActionFSWrite, Path: at("n")}, ""},
				{"path_mkdir", "m", bpf.ReasonMkdirOutsideContract, row, 0, record.FSMkdir, 0,
					agent.Action{Kind: agent.ActionFSMkdir, Path: at("m")}, ""},
				{"path_truncate", "k", bpf.ReasonWriteOutsideContract, row, 0, record.FSTruncate, 0,
					agent.Action{Kind: agent.ActionFSWrite, Path: at("k")}, ""},
				{"file_truncate", "k", bpf.ReasonWriteOutsideContract, row, 0, record.FSTruncate, 0,
					agent.Action{Kind: agent.ActionFSWrite, Path: at("k")}, ""},
				{"path_symlink", "l", bpf.ReasonIdentityMismatch, uint32(bpf.PlaneRuleNone), 0, record.FSSymlink, 0,
					agent.Action{}, record.PlaneReasonIdentityMismatch},
			}
			var samples [][]byte
			for i, c := range cases {
				samples = append(samples, planeFSSample(sample{PID: 50, TID: 50, MonoNS: uint64(i + 1), Start: 900,
					Reason: uint8(c.code)}, hookNumber(t, c.hook), c.rule, di.Dev, di.Ino, c.name, c.flags))
			}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneFmodRet}, samples...)
			fs := sink.byKind(record.KindFS)
			if len(fs) != len(cases) || len(sink.events) != len(cases) {
				t.Fatalf("%d fs lines of %d, want one per sample (%d): %+v", len(fs), len(sink.events), len(cases), sink.events)
			}
			for i, c := range cases {
				ev := fs[i]
				p := payload[record.FSPayload](t, ev)
				rule, reason := RuleUnmatched, record.ReasonPathUnresolved
				if c.action.Kind != "" {
					w := eval.Evaluate(c.action, decide.Env{})
					if w.Verdict != agent.VerdictRefused {
						t.Fatalf("%s %s: compile --test allows the action; the cell is not what it says", c.hook, c.name)
					}
					rule, reason = w.Rule, w.Reason
				}
				if ev.Verdict != record.VerdictRefused || ev.Rule != rule || ev.Reason != reason || p.Op != c.op ||
					p.Path != at(c.name) || p.Flags != c.wantFlags || p.Mechanism != record.MechanismPlane ||
					p.DecisionPlane != record.DecisionPlaneFmodRet || p.PlaneReason != c.planeWhy {
					t.Errorf("%s: %s rule %s reason %s %+v; want refused rule %s reason %s op %s at %s flags %#x "+
						"plane_reason %q", c.hook, ev.Verdict, ev.Rule, ev.Reason, p, rule, reason, c.op, at(c.name),
						c.wantFlags, c.planeWhy)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("%s: a fallback line the ledger would refuse: %v", c.hook, err)
				}
			}
		})
	}
}

// TestPlaneFSKindCoversTheFexitHooks: every hook a recorder fexit wraps (bpf.PlaneFexitPrograms) names the record
// kind of that fexit's line, and no other hook names one, so a KindPlaneFS sample of any of them is never a gap.
func TestPlaneFSKindCoversTheFexitHooks(t *testing.T) {
	for i, h := range bpf.PlaneHooks {
		_, fexit := bpf.PlaneFexitPrograms[h.Name]
		if _, ok := planeFSKind(uint16(i + 1)); ok != fexit {
			t.Errorf("hook %s: planeFSKind %v, has a recorder fexit %v", h.Name, ok, fexit)
		}
	}
	if _, ok := planeFSKind(0); ok {
		t.Error("hook 0 names a kind")
	}
	if _, ok := planeFSKind(uint16(len(bpf.PlaneHooks) + 1)); ok {
		t.Error("a hook past the last names a kind")
	}
}

// TestDecodePlaneFS: the fallback sample decodes into the file operation's fields and file_open's flags.
func TestDecodePlaneFS(t *testing.T) {
	var rec Record
	if err := DecodeInto(&rec, planeFSSample(sample{PID: 7, Start: 11}, 1, 3, 2049, 77, "cfg", unix.O_WRONLY)); err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindPlaneFS || rec.FS.Dev != 2049 || rec.FS.Ino != 77 || rec.FS.Path != "cfg" || rec.FS.PathTruncated ||
		rec.FS.Flags != unix.O_WRONLY || rec.Plane.Hook != 1 || rec.Plane.RuleIdx != 3 || rec.StartNS != 11 {
		t.Fatalf("fallback decoded %+v", rec)
	}
}
