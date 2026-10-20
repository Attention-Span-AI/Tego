// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGateReadScoresAnOpenThatReads is gate.md R1's 2026-10-16 amendment: an
// open whose access mode is not O_WRONLY reads the file it opens, whatever write bit it also carries. gateOpen and
// gateFS took any open with a write bit (O_RDWR, O_CREAT, O_TRUNC) as a write and scored it with the fs.write
// predicates only, returning early when the gate had none, so under `fs.read matches "*.env"` alone
// `exec 3<>a.env; cat <&3` read the secret the plain read-open of the same file was refused: a deterministic
// bypass, no race needed. Such an open is now scored with the read predicates as well (since 2026-10-20 the two
// kinds' scores summed, ADR 0007); an O_WRONLY open reads nothing and stays the write it is.
func TestGateReadScoresAnOpenThatReads(t *testing.T) {
	const pathAddr = 0x10000
	fs := []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}
	for _, tc := range []struct {
		name    string
		path    string
		flags   uint64
		refused bool
	}{
		{"read-only open of the secret", "/work/a.env", unix.O_RDONLY, true},
		{"read-write open of the secret", "/work/a.env", unix.O_RDWR, true},
		{"read-write truncating open of the secret", "/work/a.env", unix.O_RDWR | unix.O_TRUNC, true},
		{"read-only creating open of the secret", "/work/a.env", unix.O_RDONLY | unix.O_CREAT, true},
		{"write-only open of the secret", "/work/a.env", unix.O_WRONLY | unix.O_TRUNC, false},
		{"read-write open of an unmatched name", "/work/a.txt", unix.O_RDWR, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Workdir = "/work"
			pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 95)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, tc.flags))
			got, _ := f.lastResp()
			if !tc.refused {
				if got.Flags == 0 {
					t.Fatalf("response %+v; want continued", got)
				}
				for _, ev := range sink.all() {
					if ev.Verdict == record.VerdictRefused {
						t.Fatalf("line %+v; want no refusal", ev)
					}
				}
				return
			}
			if got.Flags != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response %+v; want the gate's refusal", got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate || ev.Authority != record.AuthorityGate {
				t.Fatalf("line %+v; want refused fs-gate under the gate's authority", ev)
			}
		})
	}
}

// TestGateReadLeavesAMknodToTheWritePredicates of GATE-STEP2-ROWS: a mknod is recorded as the
// open that creates its name, op open with O_CREAT|O_EXCL (mknodFlags), whose access mode reads O_RDONLY, so F1's
// reading scored it with the read predicates and `fs.read matches "*.env"` refused `mkfifo fifo.env` and
// `mknod reg.env` fs-gate, though a mknod opens and reads nothing. It is scored with the write predicates only, as
// every other non-open mutation that leaves its name in place: under a read gate alone it is continued, and an
// O_RDONLY|O_CREAT|O_EXCL open of the same name, which reads, is still refused.
func TestGateReadLeavesAMknodToTheWritePredicates(t *testing.T) {
	const pathAddr = 0x10000
	fs := []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}
	for _, tc := range []struct {
		name    string
		syscall string
		args    []uint64
		refused bool
	}{
		{"mknodat of a matched name", "mknodat", []uint64{argCWD, pathAddr, unix.S_IFIFO | 0o600, 0}, false},
		{"creating read-only open of a matched name", "openat",
			[]uint64{argCWD, pathAddr, unix.O_RDONLY | unix.O_CREAT | unix.O_EXCL}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr("/work/fifo.env"))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Workdir = "/work"
			pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 95)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args...))
			got, _ := f.lastResp()
			refused := got.Flags == 0 && got.Error == -int32(refusalErrno)
			if refused != tc.refused {
				t.Fatalf("response %+v; want refused %v", got, tc.refused)
			}
			for _, ev := range sink.all() {
				if (ev.Verdict == record.VerdictRefused) != tc.refused {
					t.Fatalf("line %s/%s/%s; want refused %v", ev.Verdict, ev.Reason, ev.Rule, tc.refused)
				}
			}
		})
	}
	// gateFS itself, as the review's probe called it: a mknod's decision carries the mark recordOpen sets.
	pol := testPolicy(nil, fs, nil)
	pol.Rules.Workdir = "/work"
	pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 95)
	l, _ := newTestLoop(t, newFake(), pol)
	allow := fsDecided{rule: "/work", verdict: record.VerdictAllow}
	mk := allow
	mk.mknod = true
	if d := l.table.Load().gateFS(record.FSOpen, "/work/x.env", "", mknodFlags, mk, true); d.verdict != record.VerdictAllow {
		t.Errorf("gateFS of a mknod = %s/%s, want allow", d.verdict, d.reason)
	}
	if d := l.table.Load().gateFS(record.FSOpen, "/work/x.env", "", mknodFlags, allow, true); d.reason != record.ReasonFSGate {
		t.Errorf("gateFS of an O_RDONLY|O_CREAT|O_EXCL open = %s/%s, want refused fs-gate", d.verdict, d.reason)
	}
}

// TestGateReadGuardsAFailedHandlerForAnOpenThatReads: a handler that cannot finish is refused, an O_RDWR open under a
// read gate alone as the read-only open is, and the source of a rename or hard link, which the read predicates score
// too (gateFS, ADR 0041 Step 4), so a failed handler never continues the rename of a secret out of its name.
func TestGateReadGuardsAFailedHandlerForAnOpenThatReads(t *testing.T) {
	pol := testPolicy(nil, []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}, nil)
	pol.Rules.Workdir = "/work"
	pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 95)
	failed := func(t *testing.T, name string, n *notif) {
		t.Helper()
		f := newFake()
		l, _ := newTestLoop(t, f, pol)
		l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: n.nr}] = entry{name: name, fn: func(*Loop, *notif) {}}
		l.handle(n)
		if got, ok := f.lastResp(); !ok || got.Flags != 0 || got.Error != -int32(refusalErrno) {
			t.Errorf("%s: answered %+v (%v), want a refusal", name, got, ok)
		}
	}
	for _, flags := range []uint64{unix.O_RDONLY, unix.O_RDWR, unix.O_RDONLY | unix.O_CREAT, unix.O_WRONLY | unix.O_CREAT} {
		failed(t, "openat", notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000, flags))
	}
	for _, name := range []string{"renameat", "renameat2", "linkat", "mknodat", "unlinkat", "mkdirat"} {
		failed(t, name, notifFor(nrFor(t, name), 42, argCWD, 0x10000, argCWD, 0x20000, 0))
	}
}

// TestGateReadScoresAHeldOpenThatReads: the held paths take the same reading. An O_RDWR open the read gate raises to
// ask is held and asked as a gate-raised read is (gateOpen), and an O_RDWR open an fs.ask scope holds is refused
// fs-gate, no person asked, when the read predicates refuse the held file (askOpen), as a read-only open of it is.
func TestGateReadScoresAHeldOpenThatReads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.env")
	if e := os.WriteFile(p, []byte("SECRET=1"), 0o600); e != nil {
		t.Fatal(e)
	}
	h, e := (sysKernel{}).PrepareAskOpen(pathQuery{tid: selfTask(t), dirfd: atFDCWD, path: p, joined: p}, unix.O_RDWR)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(h.fd)
	for _, tc := range []struct {
		name    string
		fsAsk   bool
		score   int
		asked   bool
		refused bool
	}{
		{"read gate raises an O_RDWR open to ask", false, 70, true, false},
		{"read gate refuses an O_RDWR open an fs.ask scope holds", true, 95, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			k := &heldTestKernel{fakeKernel: f, held: h}
			pol := testPolicy(nil, nil, nil)
			pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
			pol.Rules.Workdir = dir
			pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", tc.score)
			if tc.fsAsk {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			} else {
				pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Path: dir, Resolved: dir, Kind: agent.FSWrite})
			}
			var requests []ask.Request
			sink := &testSink{}
			l, e := New(testListener(), pol, sink, Options{kernel: k, Ask: func(_ context.Context, req ask.Request) (ask.Decision, error) {
				requests = append(requests, req)
				return ask.Decision{Approved: true}, nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer l.closeAskScopes()
			f.put(0x10000, cstr(p))
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000, unix.O_RDWR))
			if tc.asked != (len(requests) == 1 && k.completed == 1) {
				t.Fatalf("asks %+v completed %d, want asked %v", requests, k.completed, tc.asked)
			}
			if !tc.refused {
				return
			}
			got, _ := f.lastResp()
			if len(requests) != 0 || got.Flags != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("asks %+v response %+v; want the gate's refusal and no person asked", requests, got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate || ev.Authority != record.AuthorityGate {
				t.Fatalf("line %+v; want refused fs-gate under the gate's authority", ev)
			}
		})
	}
}
