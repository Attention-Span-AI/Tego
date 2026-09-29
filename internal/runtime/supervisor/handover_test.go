// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestKernelRecordOwnsTheContinuedFSLine is R7a at tier 2 while the kernel recorder reads the run (KernelFS): a
// filesystem action this loop continues and the recorder's hooks see is the recorder's line, with the LSM
// chain's verdict, so this loop writes none and hands the recorder its naming instead (ContinuedFS, keyed by the
// thread and the record's stamp, checked by the operation and each end's final component where it lands). A refusal this loop answers itself never
// reaches the kernel, and a mode change reaches no hook of the recorder: both keep this loop's line, and so does
// every action when no recorder reads. ADR 0017's tier-cgroup cells held two or three lines for one action.
//
// Spec: docs/p0/supervisor.md R7a.
func TestKernelRecordOwnsTheContinuedFSLine(t *testing.T) {
	const work = "/work/proj"
	fs := []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/", Access: agent.AccessWriteSet}}
	deny := []agent.FSRule{{Path: work + "/.git/config", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git/config"}}
	const pathAddr, path2Addr = 0x10000, 0x11000
	for _, tc := range []struct {
		name, syscall string
		args          []uint64
		from, to      string
		kernel        bool // the recorder reads the run
		line          bool // this loop writes the action's line
		op            string
		name1, name2  string
		rule          string
	}{
		{name: "a write-open", syscall: "openat", args: []uint64{argCWD, pathAddr, 0x241}, from: work + "/a.txt", kernel: true,
			op: record.FSOpen, name1: "a.txt", rule: "fs.write[./proj/]"},
		{name: "a rename out of the entry", syscall: "renameat", args: []uint64{argCWD, pathAddr, argCWD, path2Addr},
			from: work + "/b.txt", to: "/elsewhere/b.txt", kernel: true, line: true, op: record.FSRename, name1: "b.txt", name2: "b.txt",
			rule: ruleUnmatched},
		{name: "an unlink", syscall: "unlinkat", args: []uint64{argCWD, pathAddr, 0}, from: work + "/c.txt", kernel: true,
			op: record.FSUnlink, name1: "c.txt", rule: "fs.write[./proj/]"},
		{name: "a mode change reaches no hook", syscall: "fchmodat", args: []uint64{argCWD, pathAddr, 0o755},
			from: work + "/d.txt", kernel: true, line: true},
		{name: "a refusal this loop answers", syscall: "openat", args: []uint64{argCWD, pathAddr, 0x241},
			from: work + "/.git/config", kernel: true, line: true},
		{name: "no recorder reads", syscall: "openat", args: []uint64{argCWD, pathAddr, 0x241}, from: work + "/e.txt", line: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.from))
			if tc.to != "" {
				f.put(path2Addr, cstr(tc.to))
			}
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = backend.TierCgroup
			pol.Rules.Record = agent.RecordFull
			pol.Rules.DenyWrite = deny
			l, sink := newTestLoop(t, f, pol)
			kernel := tc.kernel
			l.kernelFS = func() bool { return kernel }
			l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args...))
			if got := len(sink.all()); (got == 1) != tc.line || got > 1 {
				t.Fatalf("%d lines from this loop, want a line: %v", got, tc.line)
			}
			if tc.line {
				return
			}
			n, ok := l.ContinuedFS(42, tc.op, tc.name1, tc.name2, monotonicNS())
			if !ok || n.Path != tc.from || n.Path2 != tc.to || n.Rule != tc.rule {
				t.Errorf("ContinuedFS = %+v, %v; want path %q path2 %q rule %q", n, ok, tc.from, tc.to, tc.rule)
			}
			if _, ok := l.ContinuedFS(43, tc.op, tc.name1, tc.name2, monotonicNS()); ok {
				t.Error("another thread's record was named by this one's action")
			}
		})
	}
	// The response is sent after the naming is kept, and is still CONTINUE for what the kernel decides.
	f := newFake()
	f.put(pathAddr, cstr(work+"/z.txt"))
	pol := testPolicy(nil, fs, nil)
	pol.Rules.Tier = backend.TierCgroup
	l, _ := newTestLoop(t, f, pol)
	l.kernelFS = func() bool { return true }
	l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, 0x241))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Errorf("response = %+v, want CONTINUE", got)
	}
}

// TestContinuedFSIsKeyedByTheRecordsStamp is R7a's hand-over under a recorder that has fallen behind: one thread
// makes the same operation on the same final name in two directories before the recorder reads the first
// record, and each record is named by the action it is of — its thread's last one handed over before the
// record's stamp — not by the thread's most recent one. A record older than every action of its thread, one
// whose action went unnamed (its path unread), and one whose operation or name is not that action's are named
// by nothing.
//
// Spec: docs/p0/supervisor.md R7a.
func TestContinuedFSIsKeyedByTheRecordsStamp(t *testing.T) {
	const work = "/work/proj"
	f := newFake()
	pol := testPolicy(nil, []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/"}}, nil)
	pol.Rules.Tier = backend.TierCgroup
	l, _ := newTestLoop(t, f, pol)
	l.kernelFS = func() bool { return true }
	var clock uint64
	l.mono = func() uint64 { return clock }
	mkdirat := nrFor(t, "mkdirat")
	mkdir := func(tid int, addr uint64, p string, at uint64) {
		f.put(addr, cstr(p))
		clock = at
		l.handle(notifFor(mkdirat, tid, argCWD, addr, 0o755))
	}
	mkdir(42, 0x10000, work+"/a/x", 10)
	mkdir(43, 0x11000, work+"/c/x", 12) // another thread, between the two
	mkdir(42, 0x12000, work+"/b/x", 20)
	clock = 30
	l.handle(notifFor(mkdirat, 42, argCWD, 0, 0o755)) // an unreadable path: continued, named by nothing

	for _, tc := range []struct {
		tid  int
		op   string
		name string
		at   uint64
		want string // "" names nothing
	}{
		{42, record.FSMkdir, "x", 15, work + "/a/x"},
		{42, record.FSMkdir, "x", 25, work + "/b/x"},
		{43, record.FSMkdir, "x", 13, work + "/c/x"},
		{42, record.FSMkdir, "x", 5, ""},
		{42, record.FSMkdir, "x", 35, ""},
		{42, record.FSUnlink, "x", 15, ""},
		{42, record.FSMkdir, "y", 15, ""},
	} {
		n, ok := l.ContinuedFS(tc.tid, tc.op, tc.name, "", tc.at)
		if (tc.want == "") == ok || n.Path != tc.want {
			t.Errorf("ContinuedFS(%d, %s, %s, @%d) = %q, %v; want %q", tc.tid, tc.op, tc.name, tc.at, n.Path, ok, tc.want)
		}
	}
}

// TestContinuedFSUnderConcurrentThreads races the hand-over the way a run does: several threads hand over the
// same operation on the same final name at once, each in its own directory, and the recorder, reading every
// record afterwards, names each by its own thread's action at that record's stamp.
func TestContinuedFSUnderConcurrentThreads(t *testing.T) {
	const work, threads, each = "/work/proj", 8, 40
	f := newFake()
	pol := testPolicy(nil, []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/"}}, nil)
	pol.Rules.Tier = backend.TierCgroup
	l, _ := newTestLoop(t, f, pol)
	l.kernelFS = func() bool { return true }
	mkdirat := nrFor(t, "mkdirat")
	type rec struct {
		tid  int
		at   uint64
		path string
	}
	records := make([][]rec, threads)
	var wg sync.WaitGroup
	for g := 0; g < threads; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			tid := 100 + g
			for i := 0; i < each; i++ {
				p := fmt.Sprintf("%s/t%d/d%d/x", work, g, i)
				addr := uint64(0x100000 + (g*each+i)*0x1000)
				f.put(addr, cstr(p))
				l.handle(notifFor(mkdirat, tid, argCWD, addr, 0o755))
				// The kernel runs the continued mkdir, and its hook stamps the record, after the answer.
				records[g] = append(records[g], rec{tid: tid, at: monotonicNS() + 1, path: p})
			}
		}(g)
	}
	wg.Wait()
	for _, rs := range records {
		for _, r := range rs {
			n, ok := l.ContinuedFS(r.tid, record.FSMkdir, "x", "", r.at)
			if !ok || n.Path != r.path {
				t.Fatalf("thread %d's record @%d named %q, %v; want %q", r.tid, r.at, n.Path, ok, r.path)
			}
		}
	}
}
