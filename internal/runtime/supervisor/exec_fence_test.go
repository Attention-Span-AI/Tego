// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLiftedExecFenceNamesTheEntry is ADR 0125 decision 9 for exec: a program an Adjustable run's exec fence entry
// took out of exec.deny, run under the contract's exec.allow folder once the entry is lifted (no refusal in the live
// Set), is recorded under live.fence[exec:<value>]: the program itself, and a program of the denied name in another
// exec.allow folder, which the kernel layers let run only because the fence took exec.deny's name out, and which the
// folder rule matched before; another
// program in the folder keeps the folder rule, and a Locked run names the folder rule as before.
func TestLiftedExecFenceNamesTheEntry(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	nr := nrFor(t, "execve")
	fence := &agent.LiveTable{Mode: agent.LiveAdjustable,
		Entries: []agent.LiveEntry{{Kind: agent.LiveKindExec, Value: "/usr/bin/curl", Source: agent.LiveSourceDeny, Name: "curl"}}}
	for _, c := range []struct {
		name, path string
		live       *agent.LiveTable
		want       string
	}{
		{"lifted fence entry", "/usr/bin/curl", fence, "live.fence[exec:/usr/bin/curl]"},
		{"lifted, the denied name in another folder", "/opt/tools/curl", fence, "live.fence[exec:/usr/bin/curl]"},
		{"outside the fence", "/opt/tools/wget", fence, "exec[/opt/tools/]"},
		{"locked", "/opt/tools/curl", nil, "exec[/opt/tools/]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(c.path))
			execFixture(f, argvAddr, []string{"x"})
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/opt/tools/", IsDir: true, Source: agent.ExecSourceAllow}}
			if c.live != nil {
				// As compile appends it (compileLive). exec.deny: [curl] refused every curl, so a lifted entry lets a curl
				// in /opt/tools run too, under the folder rule, while only /usr/bin/curl has a rule of its own.
				pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Path: "/usr/bin/curl", Fence: true, FenceEntry: "/usr/bin/curl"})
			}
			pol.Rules.Live = c.live
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return nil }})
			l.handle(notifFor(nr, 4242, pathAddr, argvAddr, 0))
			wantExecAnswer(t, f, record.VerdictAllow)
			if ev := sink.one(t); ev.Rule != c.want || ev.Verdict != record.VerdictAllow {
				t.Errorf("rule/verdict = %s/%s, want %s/allow", ev.Rule, ev.Verdict, c.want)
			}
		})
	}
}

// TestFenceHasExecKeepsTheExecHere: an Adjustable run with an exec fence entry decides every exec in this loop even
// once nothing in the live Set refuses one, so a plane's handover never names a lifted exec by a contract rule.
func TestFenceHasExecKeepsTheExecHere(t *testing.T) {
	pol := testPolicy(nil, nil, nil)
	c := &compiled{pol: pol}
	if c.fenceHasExec() {
		t.Fatal("a Locked run has an exec fence entry")
	}
	pol.Rules.Live = &agent.LiveTable{Mode: agent.LiveAdjustable,
		Entries: []agent.LiveEntry{{Kind: agent.LiveKindNet, Value: "api.stripe.com:443", Source: agent.LiveSourceNew}}}
	if c.fenceHasExec() {
		t.Fatal("a net-only fence has an exec fence entry")
	}
	pol.Rules.Live.Entries = append(pol.Rules.Live.Entries, agent.LiveEntry{Kind: agent.LiveKindExec, Value: "/usr/bin/curl"})
	if !c.fenceHasExec() {
		t.Fatal("an exec fence entry was not seen")
	}
	pol.Rules.Live.Entries = []agent.LiveEntry{{Kind: agent.LiveKindRead, Value: "/opt/tools/sec", Source: agent.LiveSourceDeny}}
	if !c.fenceHasExec() {
		t.Fatal("a read fence entry lets an exec be handed over undecided")
	}
}

// TestExecUnderAReadFenceEntry: in an Adjustable run, a program under a read fence entry that is
// not lifted is refused read-denied under live.fence[read:<value>], though an exec.allow folder grants it: running a
// program reads it, and its bytes can be read back through /proc/<child>/mem. Once the entry is lifted (nothing in
// the live Set), the exec is allowed under the folder rule; a program outside the entry is allowed; a Locked run's
// live read block leaves the exec as it was (fanotify's exec open decides that at cgroup and bpflsm). Every exec of
// such a run is decided here (fenceHasExec), never handed to a plane undecided.
func TestExecUnderAReadFenceEntry(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	nr := nrFor(t, "execve")
	fence := &agent.LiveTable{Mode: agent.LiveAdjustable,
		Entries: []agent.LiveEntry{{Kind: agent.LiveKindRead, Value: "/opt/tools/sec", Source: agent.LiveSourceDeny}}}
	refusing := func() *liveblock.Set {
		return liveblock.CompileEntries([]liveblock.Entry{{Kind: liveblock.KindRead, Value: "/opt/tools/sec", By: "contract", At: time.Now(), Fence: true}}, 1, liveblock.Resolved{})
	}
	for _, c := range []struct {
		name, path string
		live       *agent.LiveTable
		set        *liveblock.Set
		want       string
		verdict    record.Verdict
	}{
		{"not lifted", "/opt/tools/sec/elfbin", fence, refusing(), "live.fence[read:/opt/tools/sec]", record.VerdictRefused},
		{"not lifted, by a .. spelling", "/opt/tools/x/../sec/elfbin", fence, refusing(), "live.fence[read:/opt/tools/sec]", record.VerdictRefused},
		{"lifted", "/opt/tools/sec/elfbin", fence, nil, "exec[/opt/tools/]", record.VerdictAllow},
		{"outside the entry", "/opt/tools/other", fence, refusing(), "exec[/opt/tools/]", record.VerdictAllow},
		{"locked read block", "/opt/tools/sec/elfbin", nil, liveSet(t, "read", "/opt/tools/sec"), "exec[/opt/tools/]", record.VerdictAllow},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(c.path))
			execFixture(f, argvAddr, []string{"x"})
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/opt/tools/", IsDir: true, Source: agent.ExecSourceAllow}}
			pol.Rules.Live = c.live
			set := c.set
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
			if c.live != nil && !(&compiled{pol: pol}).fenceHasExec() {
				t.Fatal("a read fence entry lets an exec be handed over undecided")
			}
			l.handle(notifFor(nr, 4242, pathAddr, argvAddr, 0))
			wantExecAnswer(t, f, c.verdict)
			ev := sink.one(t)
			if ev.Rule != c.want || ev.Verdict != c.verdict {
				t.Errorf("rule/verdict = %s/%s, want %s/%s", ev.Rule, ev.Verdict, c.want, c.verdict)
			}
			if c.verdict == record.VerdictRefused && ev.Reason != record.ReasonReadDenied {
				t.Errorf("reason = %s, want read-denied", ev.Reason)
			}
		})
	}
}

// TestLiftedExecFenceLineStaysHereUnderThePlane, seen at tier bpflsm in a root guest: where the
// kernel plane writes a continued exec's line (KernelExecs), an exec allowed only because its fence entry is lifted
// keeps this loop's line, under live.fence[exec:<value>], since the plane's recorder names it by the plane's rule (the
// #! interpreter's exec[/bin/sh] there). Another allowed exec stays the kernel's, with no line here.
func TestLiftedExecFenceLineStaysHereUnderThePlane(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	nr := nrFor(t, "execve")
	fence := &agent.LiveTable{Mode: agent.LiveAdjustable,
		Entries: []agent.LiveEntry{{Kind: agent.LiveKindExec, Value: "/usr/bin/curl", Source: agent.LiveSourceDeny, Name: "curl"}}}
	for _, c := range []struct {
		path, want string
		lines      int
	}{
		{"/usr/bin/curl", "live.fence[exec:/usr/bin/curl]", 1},
		{"/opt/tools/wget", "", 0},
	} {
		t.Run(c.path, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(c.path))
			execFixture(f, argvAddr, []string{"x"})
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/opt/tools/", IsDir: true, Source: agent.ExecSourceAllow},
				{Path: "/usr/bin/curl", Fence: true, FenceEntry: "/usr/bin/curl"}}
			pol.Rules.Live = fence
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return nil }})
			l.kernelExecs = func() bool { return true }
			l.handle(notifFor(nr, 4242, pathAddr, argvAddr, 0))
			wantExecAnswer(t, f, record.VerdictAllow)
			evs := sink.all()
			if len(evs) != c.lines {
				t.Fatalf("%d supervisor lines, want %d: %+v", len(evs), c.lines, evs)
			}
			if c.lines == 1 && (evs[0].Rule != c.want || evs[0].Verdict != record.VerdictAllow) {
				t.Errorf("rule/verdict = %s/%s, want %s/allow", evs[0].Rule, evs[0].Verdict, c.want)
			}
		})
	}
}
