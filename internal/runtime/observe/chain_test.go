// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ADR 0016 step 2: the fs programs are fexit programs, and every fs record carries the return of the kernel's
// LSM chain (ret, ret_ok). These tests hold the decoder to the wire and the recorder to "the verdict is the
// chain's, the model only explains a refusal or stands in where there is no return".

// TestDecodeCarriesTheChainReturn: ret, ret_ok and created come off the wire for an open, and ret for every
// file operation, the five ADR 0016 added included; a link's second end has its own directory and a symlink's
// is its target, with none.
func TestDecodeCarriesTheChainReturn(t *testing.T) {
	var rec Record
	open := sample{Kind: KindOpen, PID: 7, Ret: -int32(unix.EACCES), RetOK: true, Created: true}
	if err := DecodeInto(&rec, fsSample(open, unix.O_CREAT|unix.O_WRONLY, 3, 2049, "/work/x", "")); err != nil {
		t.Fatal(err)
	}
	if !rec.FS.RetOK || rec.FS.Ret != -int32(unix.EACCES) || !rec.FS.Created {
		t.Fatalf("open decoded ret %d ret_ok %v created %v", rec.FS.Ret, rec.FS.RetOK, rec.FS.Created)
	}
	if err := DecodeInto(&rec, fsSample(sample{Kind: KindOpen, PID: 7}, 0, 3, 2049, "/work/x", "")); err != nil {
		t.Fatal(err)
	}
	if rec.FS.RetOK || rec.FS.Ret != 0 || rec.FS.Created {
		t.Fatalf("a record without a return decoded as one: %+v", rec.FS)
	}
	for _, k := range []Kind{KindUnlink, KindRename, KindMkdir, KindMknod, KindRmdir, KindLink, KindSymlink, KindTruncate} {
		t.Run(k.String(), func(t *testing.T) {
			h := sample{Kind: k, PID: 7, Ret: -int32(unix.EXDEV), RetOK: true}
			if err := DecodeInto(&rec, fsSample(h, 0, 11, 2049, "a", "b")); err != nil {
				t.Fatal(err)
			}
			if rec.Kind != k || !rec.FS.RetOK || rec.FS.Ret != -int32(unix.EXDEV) {
				t.Fatalf("decoded %s ret %d ret_ok %v", rec.Kind, rec.FS.Ret, rec.FS.RetOK)
			}
			switch k {
			case KindRename, KindLink:
				if rec.FS.Path2 != "b" || rec.FS.Ino2 != 11 {
					t.Errorf("%s's second end %q ino %d", k, rec.FS.Path2, rec.FS.Ino2)
				}
			case KindSymlink:
				if rec.FS.Path2 != "b" || rec.FS.Ino2 != 0 {
					t.Errorf("symlink target %q, directory %d: a target has no directory", rec.FS.Path2, rec.FS.Ino2)
				}
			default:
				if rec.FS.Path2 != "" {
					t.Errorf("%s carries a second name %q", k, rec.FS.Path2)
				}
			}
		})
	}
}

// fsLines runs the recorder over samples and returns its fs lines by path.
func fsLines(t *testing.T, f *fixture, samples ...[]byte) map[string]*record.Event {
	t.Helper()
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, samples...)
	out := map[string]*record.Event{}
	for _, ev := range sink.byKind(record.KindFS) {
		out[payload[record.FSPayload](t, ev).Path] = ev
	}
	return out
}

// TestRecorderVerdictIsTheChainsReturn: an open's line says what the chain answered. The model's prediction
// neither turns an allowed open into a refusal nor claims a refusal it does not explain.
func TestRecorderVerdictIsTheChainsReturn(t *testing.T) {
	f := newFixture(t)
	key := filepath.Join(f.secrets, "key.pem")
	chain := func(mono uint64, ret int32) sample {
		return sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: mono, Ret: ret, RetOK: true}
	}
	eacces := -int32(unix.EACCES)
	lines := fsLines(t, f,
		fsSample(chain(1, 0), unix.O_WRONLY, 1, 2049, filepath.Join(f.out, "allowed.md"), ""),
		fsSample(chain(2, eacces), 0, 1, 2049, key, ""),
		fsSample(chain(3, eacces), unix.O_WRONLY, 1, 2049, filepath.Join(f.dir, "outside.txt"), ""),
		fsSample(chain(4, eacces), unix.O_WRONLY, 1, 2049, filepath.Join(f.out, "other-lsm.md"), ""),
		fsSample(chain(5, -int32(unix.EPERM)), unix.O_WRONLY, 1, 2049, filepath.Join(f.out, "eperm.md"), ""),
	)
	cases := []struct {
		path    string
		verdict record.Verdict
		reason  record.Reason
		from    string
		errno   int
	}{
		{filepath.Join(f.out, "allowed.md"), record.VerdictAllow, "", record.FSVerdictChain, 0},
		{key, record.VerdictRefused, record.ReasonReadDenied, record.FSVerdictChain, 0},
		{filepath.Join(f.dir, "outside.txt"), record.VerdictRefused, record.ReasonWriteOutsideContract, record.FSVerdictChain, 0},
		// The contract grants this write: whatever refused it, it was not Tego.
		{filepath.Join(f.out, "other-lsm.md"), record.VerdictObserved, "", record.FSVerdictChain, int(unix.EACCES)},
		{filepath.Join(f.out, "eperm.md"), record.VerdictObserved, "", record.FSVerdictChain, int(unix.EPERM)},
	}
	for _, tc := range cases {
		ev := lines[tc.path]
		if ev == nil {
			t.Errorf("%s: no line", tc.path)
			continue
		}
		p := payload[record.FSPayload](t, ev)
		if ev.Verdict != tc.verdict || ev.Reason != tc.reason || p.VerdictFrom != tc.from || p.Errno != tc.errno {
			t.Errorf("%s: %s %q from %q errno %d, want %s %q from %q errno %d", tc.path, ev.Verdict, ev.Reason,
				p.VerdictFrom, p.Errno, tc.verdict, tc.reason, tc.from, tc.errno)
		}
		if wantBy := map[bool]string{true: record.FSByOther}[tc.errno != 0]; p.By != wantBy {
			t.Errorf("%s: by %q, want %q", tc.path, p.By, wantBy)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: %v", tc.path, err)
		}
	}
}

// TestRecorderChainAllowsWhatTheModelWouldRefuse is the case ADR 0016 was measured on: the model predicted a
// refusal for an action the kernel let through (66 of 768 tier-2 actions in the 6.17 guest). The line is allow.
func TestRecorderChainAllowsWhatTheModelWouldRefuse(t *testing.T) {
	f := newFixture(t)
	addSyntheticParentIndex(f)
	key := filepath.Join(f.secrets, "key.pem")
	lines := fsLines(t, f,
		fsSample(sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 1, RetOK: true}, 0, 1, 2049, key, ""),
		fsSample(sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 2}, unix.O_WRONLY, 1, 2049,
			filepath.Join(f.dir, "model.txt"), ""),
	)
	ev := lines[key]
	if ev == nil || ev.Verdict != record.VerdictAllow || ev.Rule != "fs.deny_read[./secrets/key.pem]" {
		t.Fatalf("a read the chain allowed under a deny_read entry: %+v", ev)
	}
	// Without a return, the model decides, as before, and the line says it did.
	ev = lines[filepath.Join(f.dir, "model.txt")]
	if ev == nil || ev.Verdict != record.VerdictRefused ||
		payload[record.FSPayload](t, ev).VerdictFrom != record.FSVerdictModel {
		t.Fatalf("a write with no return: %+v", ev)
	}
}

// TestRecorderListenerReadKeepsTheModel: a read under an unenforced deny_read entry is the fanotify listener's
// to answer, and the listener's answer is in the chain's return only up to 6.12. Where the listener refused it
// (a mount it marked, the chain's 0 from 6.13 or the listener's EPERM up to 6.12) its own line is the action's and
// the recorder writes none (supervisor R7a); where the recorder writes the line (Landlock's EACCES came first, or a
// mount made beneath the entry after Prepare, which the listener never marked, E24), the line keeps the model's
// verdict on every kernel, and says the model produced it.
//
// The mount table is the test's own: which device the listener marked is the case under test, not the host's disk
// layout. The device a sample names was once a constant, 2049 (8:1): a mount the listener never marked wherever the
// temporary directory is not on /dev/sda1, and the one it marked on GitHub's runners, where it is.
func TestRecorderListenerReadKeepsTheModel(t *testing.T) {
	f := newFixture(t)
	f.rules = &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Path: f.dir, Kind: agent.FSWrite, Raw: "."},
		{Path: f.secrets, Kind: agent.FSDenyRead, Raw: "./secrets", Unenforced: true},
	}}
	di, ok := statDevIno(f.secrets)
	if !ok {
		t.Fatal("could not stat the deny_read entry")
	}
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	line := fmt.Sprintf("1 0 %d:%d / / rw - fs dev rw\n", unix.Major(di.Dev), unix.Minor(di.Dev))
	if err := os.WriteFile(mountinfo, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	marked, later := di.Dev, unix.Mkdev(0, 4242)
	read := func(mono uint64, ret int32) sample {
		return sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: mono, Ret: ret, RetOK: true}
	}
	key := filepath.Join(f.secrets, "key.pem")
	eperm := filepath.Join(f.secrets, "eperm.pem")
	landlock := filepath.Join(f.secrets, "landlock.pem")
	late := filepath.Join(f.secrets, "late", "key.pem")
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, mountinfo: mountinfo},
		fsSample(read(1, 0), 0, 1, marked, key, ""),
		fsSample(read(2, -int32(unix.EPERM)), 0, 2, marked, eperm, ""),
		fsSample(read(3, -int32(unix.EACCES)), 0, 3, marked, landlock, ""),
		fsSample(read(4, 0), 0, 4, later, late, ""),
	)
	lines := map[string]*record.Event{}
	for _, ev := range sink.byKind(record.KindFS) {
		lines[payload[record.FSPayload](t, ev).Path] = ev
	}
	for _, tc := range []struct{ path, kernel string }{
		{key, "from 6.13, the chain returned 0"},
		{eperm, "up to 6.12, the chain returned the listener's EPERM"},
	} {
		if ev := lines[tc.path]; ev != nil {
			t.Errorf("the listener's refusal (%s) has a recorder line too: %+v", tc.kernel, ev)
		}
	}
	for _, tc := range []struct {
		path    string
		verdict record.Verdict
		reason  record.Reason
	}{
		{landlock, record.VerdictRefused, record.ReasonReadDenied},
		{late, record.VerdictObserved, ""},
	} {
		ev := lines[tc.path]
		if ev == nil {
			t.Errorf("%s: no line for the read", tc.path)
			continue
		}
		if ev.Verdict != tc.verdict || ev.Reason != tc.reason {
			t.Errorf("%s: %s %q, want %s %q", tc.path, ev.Verdict, ev.Reason, tc.verdict, tc.reason)
		}
		if p := payload[record.FSPayload](t, ev); p.VerdictFrom != record.FSVerdictModel {
			t.Errorf("%s: the listener's read says its verdict came from %q", tc.path, p.VerdictFrom)
		}
	}
}

// TestRecorderFileOperationsCarryTheChainReturn covers the five operations ADR 0016 added beside unlink,
// rename and mkdir: each is resolved through the directory index like them, named by the op the supervisor's
// line has, and has the chain's verdict.
func TestRecorderFileOperationsCarryTheChainReturn(t *testing.T) {
	f := newFixture(t)
	addSyntheticParentIndex(f)
	out, ok := statDevIno(f.out)
	top, ok2 := statDevIno(f.dir)
	if !ok || !ok2 {
		t.Fatal("could not stat the fixture's directories")
	}
	op := func(k Kind, mono uint64, ret int32) sample {
		return sample{Kind: k, PID: 50, TID: 50, MonoNS: mono, Ret: ret, RetOK: true}
	}
	eacces := -int32(unix.EACCES)
	link := op(KindLink, 6, -int32(unix.EXDEV))
	linkRec := fsSample(link, 0, uint32(out.Ino), out.Dev, "a.txt", "b.txt")
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		fsSample(op(KindRmdir, 1, 0), 0, uint32(out.Ino), out.Dev, "old", ""),
		fsSample(op(KindMknod, 2, eacces), 0, uint32(top.Ino), top.Dev, "new.txt", ""),
		fsSample(op(KindSymlink, 3, 0), 0, uint32(out.Ino), out.Dev, "ln", "../elsewhere"),
		fsSample(op(KindTruncate, 4, 0), 0, uint32(out.Ino), out.Dev, "log.txt", ""),
		fsSample(op(KindTruncate, 5, eacces), 0, uint32(top.Ino), top.Dev, "top.txt", ""),
		linkRec,
	)
	fs := sink.byKind(record.KindFS)
	if len(fs) != 6 {
		t.Fatalf("%d fs lines, want 6", len(fs))
	}
	want := []struct {
		op      string
		path    string
		path2   string
		flags   int
		verdict record.Verdict
		reason  record.Reason
	}{
		{record.FSUnlink, filepath.Join(f.out, "old"), "", 0, record.VerdictAllow, ""},
		{record.FSOpen, filepath.Join(f.dir, "new.txt"), "", unix.O_CREAT, record.VerdictRefused, record.ReasonWriteOutsideContract},
		{record.FSSymlink, filepath.Join(f.out, "ln"), "../elsewhere", 0, record.VerdictAllow, ""},
		{record.FSTruncate, filepath.Join(f.out, "log.txt"), "", 0, record.VerdictAllow, ""},
		{record.FSTruncate, filepath.Join(f.dir, "top.txt"), "", 0, record.VerdictRefused, record.ReasonWriteOutsideContract},
		// The fixture's link has both ends in ./out, which grants them: -EXDEV is no refusal of Tego's.
		{record.FSLink, filepath.Join(f.out, "a.txt"), filepath.Join(f.out, "b.txt"), 0, record.VerdictObserved, ""},
	}
	for i, w := range want {
		ev := fs[i]
		p := payload[record.FSPayload](t, ev)
		if p.Op != w.op || p.Path != w.path || p.Path2 != w.path2 || p.Flags != w.flags || ev.Verdict != w.verdict ||
			ev.Reason != w.reason || p.VerdictFrom != record.FSVerdictChain {
			t.Errorf("line %d: %s %s %q %q flags %#x from %q, want %s %s %q %q flags %#x", i, ev.Verdict, p.Op, p.Path,
				p.Path2, p.Flags, p.VerdictFrom, w.verdict, w.op, w.path, w.path2, w.flags)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("line %d: %v", i, err)
		}
	}
	if p := payload[record.FSPayload](t, fs[5]); p.By != record.FSByOther || p.Errno != int(unix.EXDEV) {
		t.Errorf("the unexplained -EXDEV: by %q errno %d", p.By, p.Errno)
	}
}

// TestRecordOffRecordsTheChainsRefusals is ADR 0016 (3)'s "refusals are emitted under record: off too": the
// kernel sends an fs record under off only when the chain refused, and the recorder keeps Tego's refusals of
// them. A refusal no Tego mechanism explains is not one the reason channel reports, and stays out, as does
// everything the chain allowed.
func TestRecordOffRecordsTheChainsRefusals(t *testing.T) {
	f := newFixture(t)
	addSyntheticParentIndex(f)
	f.rules.Record = agent.RecordOff
	out, ok := statDevIno(f.dir)
	if !ok {
		t.Fatal("could not stat the project")
	}
	key := filepath.Join(f.secrets, "key.pem")
	eacces := -int32(unix.EACCES)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1, Ret: eacces, RetOK: true}, 0, 1, 2049, key, ""),
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 2, RetOK: true}, unix.O_WRONLY, 1, 2049, filepath.Join(f.out, "a"), ""),
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 3, Ret: eacces, RetOK: true}, unix.O_WRONLY, 1, 2049,
			filepath.Join(f.out, "other-lsm"), ""),
		fsSample(sample{Kind: KindUnlink, PID: 50, MonoNS: 4, Ret: eacces, RetOK: true}, 0, uint32(out.Ino), out.Dev, "x", ""),
	)
	fs := sink.byKind(record.KindFS)
	if len(fs) != 2 {
		t.Fatalf("record: off kept %d fs lines, want the two refusals: %+v", len(fs), fs)
	}
	if fs[0].Verdict != record.VerdictRefused || fs[0].Reason != record.ReasonReadDenied {
		t.Errorf("the refused read: %+v", fs[0])
	}
	if fs[1].Verdict != record.VerdictRefused || fs[1].Reason != record.ReasonDeleteOutsideContract {
		t.Errorf("the refused unlink: %+v", fs[1])
	}
	if len(sink.all()) != 2 {
		t.Errorf("record: off emitted %d lines: %+v", len(sink.all()), sink.all())
	}
}
