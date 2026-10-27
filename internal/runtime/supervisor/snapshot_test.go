// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSnapshotRefusalOfAContinuedRead on the path this loop continues: a read-capable open the contract
// allows, where it lands, of a name the run's Landlock ruleset refuses because its deny_read enumeration froze at
// launch (Options.DenyReadSnapshot), is refused here with EACCES and recorded refused, read-denied, deny-read-snapshot.
// Continued, the kernel refused it all the same and the line said allow. A read the snapshot does not refuse is
// continued and recorded allow; an O_PATH open never asks it; a refusal the contract makes keeps its own rule and is
// continued for Landlock to answer, as before.
//
// Spec: docs/p0/supervisor.md R15e.
func TestSnapshotRefusalOfAContinuedRead(t *testing.T) {
	const pathAddr = 0x10000
	fs := []agent.FSRule{{Path: "/work/secret", Kind: agent.FSDenyRead, Raw: "./secret/"}}
	late := map[string]bool{"/work/late/f.txt": true, "/work/secret/key": true}
	for _, tc := range []struct {
		name    string
		path    string
		lands   string
		flags   uint64
		refused bool // the line's verdict
		answers bool // this loop answers EACCES itself
		rule    string
		reason  record.Reason
	}{
		{"a file in a directory made after launch", "/work/late/f.txt", "/work/late/f.txt", unix.O_RDONLY, true, true, ruleDenyReadSnapshot, record.ReasonReadDenied},
		{"a read-write open of it", "/work/late/f.txt", "/work/late/f.txt", unix.O_RDWR, true, false, ruleUnmatched, record.ReasonWriteOutsideContract},
		{"a symlink that lands there", "/work/old/link", "/work/late/f.txt", unix.O_RDONLY, true, true, ruleDenyReadSnapshot, record.ReasonReadDenied},
		{"a file the listing granted", "/work/old/g.txt", "/work/old/g.txt", unix.O_RDONLY, false, false, ruleUnmatched, ""},
		{"an O_PATH open", "/work/late/f.txt", "/work/late/f.txt", unix.O_PATH, false, false, ruleUnmatched, ""},
		{"the target itself keeps its rule", "/work/secret/key", "/work/secret/key", unix.O_RDONLY, true, false, "fs.deny_read[./secret/]", record.ReasonReadDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			f.fsTargets[tc.path] = tc.lands
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Record = agent.RecordFull
			pol.Rules.Tier = backend.TierLandlock
			var asked []string
			l, sink := newTestLoopOpts(t, f, pol, Options{DenyReadSnapshot: func(p string) bool {
				asked = append(asked, p)
				return late[p]
			}})
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, tc.flags))
			got, _ := f.lastResp()
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; tc.answers == cont {
				t.Fatalf("response = %+v, want answered here %v", got, tc.answers)
			}
			if tc.answers && got.Error != -int32(unix.EACCES) {
				t.Fatalf("response = %+v, want EACCES, the kernel's own answer", got)
			}
			ev := sink.one(t)
			want := record.VerdictAllow
			if tc.refused {
				want = record.VerdictRefused
			}
			if ev.Verdict != want || ev.Rule != tc.rule || ev.Reason != tc.reason {
				t.Errorf("line %s %s %s, want %s %s %s", ev.Verdict, ev.Rule, ev.Reason, want, tc.rule, tc.reason)
			}
			if tc.flags == unix.O_PATH && len(asked) != 0 {
				t.Errorf("an O_PATH open asked the snapshot about %q", asked)
			}
		})
	}
}

// TestSnapshotRefusalOfAnExec: the kernel's exec open needs READ_FILE, so an image in a directory made after launch
// beside a deny_read ancestor is one the ruleset refuses. A deny-list run allowed it on the contract's paths and
// recorded allow; it is refused here, read-denied, deny-read-snapshot, and an image the listing granted still runs.
func TestSnapshotRefusalOfAnExec(t *testing.T) {
	nr := nrFor(t, "execve")
	images := map[string]execImage{
		"/work/late/tool": fakeImage("/work/late/tool"),
		"/usr/bin/true":   fakeImage("/usr/bin/true"),
	}
	for _, c := range []struct {
		path    string
		verdict record.Verdict
		rule    string
	}{
		{"/work/late/tool", record.VerdictRefused, ruleDenyReadSnapshot},
		{"/usr/bin/true", record.VerdictAllow, ruleUnmatched},
	} {
		f := newFake()
		f.images = images
		pol := testPolicy(nil, []agent.FSRule{{Path: "/work/secret", Kind: agent.FSDenyRead, Raw: "./secret/"}}, nil)
		pol.Rules.Contract = &agent.Contract{}
		l, sink := newTestLoopOpts(t, f, pol, Options{DenyReadSnapshot: func(p string) bool { return p == "/work/late/tool" }})
		execAt(l, f, nr, 42, 0, c.path, filepath.Base(c.path))
		ev := sink.one(t)
		if ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want %s %s", c.path, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		wantExecAnswer(t, f, c.verdict)
	}
}

// TestSnapshotExplainsAHeldReadsEACCES: a held read is opened by the open deputy in the run's own domain, so the
// ruleset refuses it the same name it refuses the task; the deputy's EACCES is then the snapshot's, and the line says
// refused, read-denied, deny-read-snapshot, where it said allow with syscall_ret -13 (and under record: summary had no
// line at all). An EACCES the snapshot does not explain (the file's own mode bits, a host LSM) keeps the floor's
// verdict, as before.
func TestSnapshotExplainsAHeldReadsEACCES(t *testing.T) {
	for _, explained := range []bool{true, false} {
		x, _ := heldReadsFixture(t, agent.RecordFull)
		late := filepath.Join(x.dir, "src", "a.txt")
		x.snapshot = func(p string) bool { return explained && p == late }
		x.dep.openErr = unix.EACCES
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		x.open(t, l, late, os.O_RDONLY)
		res, _ := x.f.lastResp()
		if res.Error != -int32(unix.EACCES) {
			t.Fatalf("answer %+v, want the kernel's EACCES", res)
		}
		ev := sink.one(t)
		p := decodeHeldOutcome(t, ev)
		if p.SyscallRet == nil || *p.SyscallRet != -int64(unix.EACCES) {
			t.Errorf("syscall_ret %v, want -13", p.SyscallRet)
		}
		switch {
		case explained && (ev.Verdict != record.VerdictRefused || ev.Rule != ruleDenyReadSnapshot || ev.Reason != record.ReasonReadDenied):
			t.Errorf("explained: line %s %s %s, want refused %s read-denied", ev.Verdict, ev.Rule, ev.Reason, ruleDenyReadSnapshot)
		case !explained && ev.Verdict == record.VerdictRefused:
			t.Errorf("unexplained: line %s %s %s, want the floor's allow", ev.Verdict, ev.Rule, ev.Reason)
		}
	}
}
