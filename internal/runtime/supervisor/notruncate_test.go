// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// noTruncateRun is a loop for a run on a kernel whose Landlock has no truncate right (Options.LandlockTruncate false):
// the filter notifies every truncate(2) and every open that truncates without a write access mode, and this loop answers
// them.
func noTruncateRun(t *testing.T, f *fakeKernel, mode agent.RecordMode, observe bool) (*Loop, *testSink) {
	t.Helper()
	const work = "/work/proj"
	pol := testPolicy(nil, []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/"}}, nil)
	pol.Rules.Tier = backend.TierLandlock
	pol.Rules.Record = mode
	pol.Observe = observe
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 1}) // no LandlockTruncate: the zero value
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, sink
}

// TestNoTruncateRightRefusesWithALine is the supervisor half of the truncation arms below Landlock ABI 3 (public
// issue 66). The filter used to answer EPERM to truncate(2), and to an open that truncates through O_RDONLY or access
// mode 3, with no notification, so the record held no line for a refusal. It notifies them now, and this loop answers the
// same EPERM, whatever the path (one inside a declared write entry too: the filter cannot read a path safely and the arm
// was always coarser than the contract), and writes the action's line: refused, write-outside-contract, rule
// landlock-no-truncate, under every record mode.
func TestNoTruncateRightRefusesWithALine(t *testing.T) {
	const work = "/work/proj"
	const pathAddr = 0x10000
	rdonlyTrunc := uint64(unix.O_RDONLY | unix.O_TRUNC)
	accmodeTrunc := uint64(unix.O_ACCMODE | unix.O_TRUNC)
	for _, mode := range []agent.RecordMode{agent.RecordOff, agent.RecordSummary, agent.RecordFull} {
		for _, tc := range []struct {
			name, syscall, path string
			args                func(nr int32) *notif
			op                  string
			flags               int
		}{
			{name: "truncate in the write entry", syscall: "truncate", path: work + "/a.txt",
				args: func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0) }, op: record.FSTruncate},
			{name: "truncate outside every entry", syscall: "truncate", path: "/etc/passwd",
				args: func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0) }, op: record.FSTruncate},
			{name: "openat O_RDONLY|O_TRUNC", syscall: "openat", path: work + "/a.txt",
				args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, rdonlyTrunc) }, op: record.FSOpen,
				flags: unix.O_RDONLY | unix.O_TRUNC},
			{name: "openat O_ACCMODE|O_TRUNC", syscall: "openat", path: work + "/a.txt",
				args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, accmodeTrunc) }, op: record.FSOpen,
				flags: unix.O_ACCMODE | unix.O_TRUNC},
		} {
			t.Run(tc.name+"/"+string(mode), func(t *testing.T) {
				f := newFake()
				f.put(pathAddr, cstr(tc.path))
				l, sink := noTruncateRun(t, f, mode, false)
				l.handle(tc.args(nrFor(t, tc.syscall)))
				got, _ := f.lastResp()
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.EPERM) || got.Val != -1 {
					t.Fatalf("response = %+v, want EPERM and no continue: the call must be refused with the errno the filter answered before", got)
				}
				ev := sink.one(t)
				if ev.Verdict != record.VerdictRefused || ev.Rule != ruleNoTruncateRight || ev.Reason != record.ReasonWriteOutsideContract {
					t.Errorf("line = %s/%s/%s, want refused/%s/write-outside-contract", ev.Verdict, ev.Rule, ev.Reason, ruleNoTruncateRight)
				}
				var p record.FSPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.Op != tc.op || p.Path != tc.path || p.Flags != tc.flags {
					t.Errorf("payload = %+v, want op %s path %s flags %#x", p, tc.op, tc.path, tc.flags)
				}
			})
		}
	}
}

// TestNoTruncateRightRefusesAnUnreadablePath: the refusal rests on no path, so a pathname the loop cannot read (a bad
// pointer) is refused with EPERM all the same, and its line says refused under the same rule with no path to name.
func TestNoTruncateRightRefusesAnUnreadablePath(t *testing.T) {
	f := newFake() // nothing is mapped at the pointer
	l, sink := noTruncateRun(t, f, agent.RecordOff, false)
	l.handle(notifFor(nrFor(t, "truncate"), 42, 0x7f0000, 0))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.EPERM) {
		t.Fatalf("response = %+v, want EPERM and no continue", got)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleNoTruncateRight {
		t.Errorf("line = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleNoTruncateRight)
	}
}

// TestNoTruncateRightLeavesOtherOpensAlone: a write-mode truncating open and a plain read are Landlock's below ABI 3 as
// they are above it (the write right is asked of the first, nothing of the second): this loop continues them with the
// line it always wrote, and refuses nothing it did not refuse before.
func TestNoTruncateRightLeavesOtherOpensAlone(t *testing.T) {
	const work = "/work/proj"
	const pathAddr = 0x10000
	for name, flags := range map[string]uint64{
		"O_WRONLY|O_TRUNC": unix.O_WRONLY | unix.O_TRUNC, "O_RDWR|O_TRUNC": unix.O_RDWR | unix.O_TRUNC,
		"O_WRONLY|O_CREAT": unix.O_WRONLY | unix.O_CREAT, "O_RDONLY": unix.O_RDONLY, "O_ACCMODE alone": unix.O_ACCMODE,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(work+"/a.txt"))
			l, sink := noTruncateRun(t, f, agent.RecordFull, false)
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, flags))
			got, _ := f.lastResp()
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want the open continued", got)
			}
			if ev := sink.one(t); ev.Rule == ruleNoTruncateRight {
				t.Errorf("line carries the no-truncate rule: %+v", ev)
			}
		})
	}
}

// TestNoTruncateRightIsFailClosedAndObserveContinues: the zero value of Options.LandlockTruncate refuses (a run whose
// handle never said its ruleset decides truncate must not have a file emptied), the word true has the call recorded and
// continued, and an observe run, which refuses nothing, continues the call with no refused line.
func TestNoTruncateRightIsFailClosedAndObserveContinues(t *testing.T) {
	const pathAddr = 0x10000
	truncateNR := nrFor(t, "truncate")
	t.Run("zero value refuses", func(t *testing.T) {
		f := newFake()
		f.put(pathAddr, cstr("/work/proj/a.txt"))
		l, _ := noTruncateRun(t, f, agent.RecordSummary, false)
		l.handle(notifFor(truncateNR, 42, pathAddr, 0))
		if got, _ := f.lastResp(); got.Error != -int32(unix.EPERM) {
			t.Errorf("response = %+v, want EPERM", got)
		}
	})
	t.Run("the kernel's right continues it", func(t *testing.T) {
		f := newFake()
		f.put(pathAddr, cstr("/work/proj/a.txt"))
		l, sink := newTestLoop(t, f, noTruncateRunPolicy())
		l.handle(notifFor(truncateNR, 42, pathAddr, 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Errorf("response = %+v, want continued", got)
		}
		if ev := sink.one(t); ev.Verdict == record.VerdictRefused || ev.Rule == ruleNoTruncateRight {
			t.Errorf("line = %+v, want the ordinary allowed line", ev)
		}
	})
	t.Run("observe continues and refuses nothing", func(t *testing.T) {
		f := newFake()
		f.put(pathAddr, cstr("/work/proj/a.txt"))
		l, sink := noTruncateRun(t, f, agent.RecordSummary, true)
		l.handle(notifFor(truncateNR, 42, pathAddr, 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Errorf("response = %+v, want continued", got)
		}
		for _, ev := range sink.all() {
			if ev.Verdict == record.VerdictRefused || ev.Rule == ruleNoTruncateRight {
				t.Errorf("an observe run wrote %+v", ev)
			}
		}
	})
}

func noTruncateRunPolicy() *Policy {
	pol := testPolicy(nil, []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite, Raw: "./proj/"}}, nil)
	pol.Rules.Tier = backend.TierLandlock
	pol.Rules.Record = agent.RecordFull
	return pol
}

// TestOpensTruncatingWithoutWriteMatchesTheFilter keeps this loop's test of an open in step with the filter's second
// truncation arm (landlock.readOnlyTruncateTest: O_TRUNC set, access mode neither O_WRONLY nor O_RDWR), written here
// again from the arm's own description over every access mode and a set of other flags, with bits above the low 32 never
// steering it. The filter's own side is TestTruncationArmsRefuseWhatTheyAlwaysDid, over the same grid.
func TestOpensTruncatingWithoutWriteMatchesTheFilter(t *testing.T) {
	others := []int{0, unix.O_CREAT, unix.O_APPEND, unix.O_DIRECTORY, unix.O_NOFOLLOW, unix.O_CLOEXEC, unix.O_PATH, unix.O_EXCL}
	for acc := 0; acc <= unix.O_ACCMODE; acc++ {
		for _, o := range others {
			for _, trunc := range []int{0, unix.O_TRUNC} {
				flags := acc | o | trunc
				want := trunc != 0 && (acc == unix.O_RDONLY || acc == unix.O_ACCMODE)
				if got := opensTruncatingWithoutWrite(flags); got != want {
					t.Errorf("flags %#x: opensTruncatingWithoutWrite = %v, want %v", flags, got, want)
				}
			}
		}
	}
}
