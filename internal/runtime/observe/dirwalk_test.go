// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The recorder is a runtime.PathHookNamer: the runtime lets the plane's filter leave mutations unnotified only for a
// recorder that says it names them by path on its own (enforce-plane §2.13 condition 1, §2.15).
var _ runtime.PathHookNamer = (*Recorder)(nil)

// walked is fsSample with each side's parent directory walked in the kernel (struct tego_ev_fsop dir, dir2):
// state and the path, written right-aligned in the buffer as tego_dir_walk writes it.
func walked(t *testing.T, raw []byte, st bpf.DirState, dir string, st2 bpf.DirState, dir2 string) []byte {
	t.Helper()
	e, err := bpf.Decode[bpf.FSOpEvent](raw)
	if err != nil {
		t.Fatal(err)
	}
	put := func(buf *[bpf.PathMax]byte, state *uint8, off *uint16, s bpf.DirState, p string) {
		*state, *off = uint8(s), bpf.PathMax
		if s == bpf.DirOK {
			*off = uint16(bpf.PathMax - len(p))
			copy(buf[*off:], p)
		}
	}
	put(&e.Dir, &e.DirState, &e.DirOff, st, dir)
	put(&e.Dir2, &e.Dir2State, &e.Dir2Off, st2, dir2)
	return wire(&e)
}

// TestDirPath: a side's path is dir[off:] only when the walk says it is whole; the root is the empty string, and an
// offset past the buffer or any other state is no path.
func TestDirPath(t *testing.T) {
	var buf [bpf.PathMax]byte
	copy(buf[bpf.PathMax-4:], "/a/b")
	for _, tc := range []struct {
		state uint8
		off   uint16
		want  string
		ok    bool
	}{
		{uint8(bpf.DirOK), bpf.PathMax - 4, "/a/b", true},
		{uint8(bpf.DirOK), bpf.PathMax, "", true},
		{uint8(bpf.DirOK), bpf.PathMax + 1, "", false},
		{uint8(bpf.DirNone), bpf.PathMax - 4, "", false},
		{uint8(bpf.DirRaced), bpf.PathMax - 4, "", false},
		{uint8(bpf.DirLong), bpf.PathMax - 4, "", false},
		{uint8(bpf.DirUnreachable), bpf.PathMax - 4, "", false},
	} {
		if got, ok := bpf.DirPath(tc.state, tc.off, buf[:]); got != tc.want || ok != tc.ok {
			t.Errorf("DirPath(%d, %d) = %q %v, want %q %v", tc.state, tc.off, got, ok, tc.want, tc.ok)
		}
	}
}

// TestRecorderNamesWalkedPathHooks is enforce-plane §2.13's condition 1, lifted (§2.15): where a plane mode decides
// the run, the plane's filter no longer notifies the mutations it decides, so the fsop record is the action's one
// line and must name it by its full path and the contract's rule on its own. Each record here is in a directory the
// index does not hold (a subdirectory of the write entry, dirIno 999) and the supervisor has no naming for it, as
// with the notification gone: the kernel's walked directory names it. An allowed mutation is named by the entry
// whose grant allowed it, as compile --test names it, never unmatched; a plane refusal by its rule_idx's row; a
// rename's two ends by their own directories; a Landlock refusal of an end outside every entry is refused and
// unmatched, as compile --test answers it (the model called it observed, found by the conformance runner in lsm
// mode). A walk that could not prove its path is never used: the side is the marked dev:ino/name with a
// dir-unresolved gap, not a path.
func TestRecorderNamesWalkedPathHooks(t *testing.T) {
	f := newFixture(t)
	rt, rows := planeTable(f)
	f.rules = rt
	gitRow := planeRow(t, rows, filepath.Join(f.out, ".git"))
	sub, other := filepath.Join(f.out, "pkg", "a"), filepath.Join(f.out, "build")
	dev, ino := uint64(2049), uint32(999)
	allowed := func(k Kind, mono uint64) sample {
		return sample{Kind: k, PID: 50, TID: 50, MonoNS: mono, Start: 900, RetOK: true}
	}
	landlocked := func(k Kind, mono uint64) sample {
		return sample{Kind: k, PID: 50, TID: 50, MonoNS: mono, Start: 900, Ret: -13, RetOK: true}
	}
	refused := func(k Kind, mono uint64, reason bpf.ReasonCode, rule uint16) sample {
		return sample{Kind: k, PID: 50, TID: 50, MonoNS: mono, Start: 900, Verdict: KernelRefused,
			Reason: uint8(reason), RuleIdx: rule, Ret: -13, RetOK: true}
	}
	asked := 0
	opts := Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM,
		ContinuedFS: func(int, string, string, string, uint64) (string, string, string, record.Verdict, record.Reason, bool) {
			asked++ // the notification is gone: the supervisor named nothing
			return "", "", "", "", "", false
		}}
	r, sink := runRecorder(t, f, opts,
		walked(t, fsSample(allowed(KindUnlink, 1), 0, ino, dev, "f.pyc", ""), bpf.DirOK, sub, bpf.DirNone, ""),
		walked(t, fsSample(allowed(KindMkdir, 2), 0, ino, dev, "b", ""), bpf.DirOK, sub, bpf.DirNone, ""),
		walked(t, fsSample(allowed(KindRename, 3), 0, ino, dev, "t.tmp", "t"), bpf.DirOK, sub, bpf.DirOK, other),
		walked(t, fsSample(refused(KindRename, 4, bpf.ReasonDenyWriteAncestor, gitRow), 0, ino, dev, ".git", ".g"),
			bpf.DirOK, f.out, bpf.DirOK, f.out),
		walked(t, fsSample(allowed(KindUnlink, 5), 0, ino, dev, "raced", ""), bpf.DirRaced, "", bpf.DirNone, ""),
		walked(t, fsSample(allowed(KindUnlink, 6), 0, ino, dev, "rootfile", ""), bpf.DirOK, "", bpf.DirNone, ""),
		// Refused by the Landlock ruleset before the plane ran (lsm mode: landlock comes first in lsm=), so no
		// plane stamp: a create outside every entry, and a rename out of the write entry.
		walked(t, fsSample(landlocked(KindMknod, 7), 0, ino, dev, "new", ""), bpf.DirOK, f.dir, bpf.DirNone, ""),
		walked(t, fsSample(landlocked(KindRename, 8), 0, ino, dev, "t", "t"), bpf.DirOK, sub, bpf.DirOK, f.dir),
	)
	fs := sink.byKind(record.KindFS)
	if len(fs) != 8 {
		t.Fatalf("%d fs lines, want one per action (8): %+v", len(fs), fs)
	}
	write := rt.FS[0].RuleName()
	for i, want := range []struct {
		op, path, path2, rule string
		verdict               record.Verdict
		reason                record.Reason
	}{
		{record.FSUnlink, filepath.Join(sub, "f.pyc"), "", write, record.VerdictAllow, ""},
		{record.FSMkdir, filepath.Join(sub, "b"), "", write, record.VerdictAllow, ""},
		{record.FSRename, filepath.Join(sub, "t.tmp"), filepath.Join(other, "t"), write, record.VerdictAllow, ""},
		{record.FSRename, filepath.Join(f.out, ".git"), filepath.Join(f.out, ".g"), rt.DenyWrite[0].RuleName(),
			record.VerdictRefused, record.ReasonRenameOutsideContract},
		{record.FSUnlink, "2049:999/raced", "", RuleUnmatched, record.VerdictAllow, ""},
		{record.FSUnlink, "/rootfile", "", RuleUnmatched, record.VerdictAllow, ""},
		{record.FSOpen, filepath.Join(f.dir, "new"), "", RuleUnmatched, record.VerdictRefused,
			record.ReasonWriteOutsideContract},
		{record.FSRename, filepath.Join(sub, "t"), filepath.Join(f.dir, "t"), RuleUnmatched, record.VerdictRefused,
			record.ReasonRenameOutsideContract},
	} {
		ev := fs[i]
		p := payload[record.FSPayload](t, ev)
		if p.Op != want.op || p.Path != want.path || p.Path2 != want.path2 || ev.Rule != want.rule ||
			ev.Verdict != want.verdict || ev.Reason != want.reason {
			t.Errorf("line %d: %s %q %q %s %s %s, want %s %q %q %s %s %s", i, p.Op, p.Path, p.Path2, ev.Rule,
				ev.Verdict, ev.Reason, want.op, want.path, want.path2, want.rule, want.verdict, want.reason)
		}
	}
	if p := payload[record.FSPayload](t, fs[4]); strings.HasPrefix(p.Path, "/") {
		t.Errorf("an unproven walk named %q, a path", p.Path)
	}
	if n := gapCount(r.Gaps())[GapDirUnresolved]; n != 1 {
		t.Errorf("dir-unresolved %d, want the one raced walk the index cannot name: %+v", n, r.Gaps())
	}
	// Only the raced record, which the kernel could not name, asks for the supervisor's naming, which a run with the
	// notification dropped does not have; the walked ones never do.
	if asked != 1 {
		t.Errorf("the supervisor's naming was asked %d times, want only for the raced walk", asked)
	}
}

// TestDecodeWalkedFSOp: decodeFSOp carries each side's walked directory and its state; a symlink's or an unlink's
// second directory is none.
func TestDecodeWalkedFSOp(t *testing.T) {
	raw := walked(t, fsSample(sample{Kind: KindRename, PID: 1, TID: 1}, 0, 5, 2049, "a", "b"), bpf.DirOK, "/w/x",
		bpf.DirLong, "")
	var rec Record
	if err := DecodeInto(&rec, raw); err != nil {
		t.Fatal(err)
	}
	if rec.FS.Dir != "/w/x" || rec.FS.DirWalk != bpf.DirOK || rec.FS.Dir2 != "" || rec.FS.Dir2Walk != bpf.DirLong {
		t.Errorf("decoded %+v", rec.FS)
	}
	raw = walked(t, fsSample(sample{Kind: KindSymlink, PID: 1, TID: 1}, 0, 5, 2049, "a", "/t"), bpf.DirOK, "/w",
		bpf.DirOK, "/never")
	rec = Record{}
	if err := DecodeInto(&rec, raw); err != nil {
		t.Fatal(err)
	}
	if rec.FS.Dir != "/w" || rec.FS.Dir2 != "" || rec.FS.Dir2Walk != bpf.DirNone {
		t.Errorf("a symlink's second side was decoded: %+v", rec.FS)
	}
	var r Recorder
	if !r.NamesPathHooks() {
		t.Error("the recorder does not say it names path hooks")
	}
}
