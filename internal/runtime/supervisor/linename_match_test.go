// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestADotDotEndIsDecidedWhereItIsNamed: an end the line names by its walk (a ".." component) is decided on that walk
// too, R15c's deny_write match included, never on R6's lexical clean, which names a file no mechanism decides on: the
// kernel, Landlock, the listener and the plane all reach the physical file. With out/lk -> ../b/sub and the target
// out/f, a write-open of out/lk/../f reaches b/f, outside every write entry. R15c matched every end as spelled first,
// and the line named the walk's file, so the run wrote "refused b/f, rule fs.deny_write[out/f]": a refusal under a rule
// that never covered the file it names, where compile --test lands the path on b/f and answers it unmatched. The
// held open (gate.completion: held) matched its copied name as
// spelled the same way; a walk-named spelling now takes this loop's walk before the pin. A target the walk reaches is
// refused under its own rule, and a walk that fails past the final component's directory decides where it names the
// end, not on the clean. Real walks of a real tree, as a run makes them.
//
// Spec: docs/p0/supervisor.md R15b, R15c.
func TestADotDotEndIsDecidedWhereItIsNamed(t *testing.T) {
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name, link, spelled string
		// reached is the file the open reaches, which the line names, and rule the line's rule there.
		reached, rule string
		verdict       record.Verdict
		// heldErrno is the held open's answer when it is the deputy's pin's, the task's own lookup's errno.
		heldErrno unix.Errno
	}{
		{name: "a target the clean names, the walk does not", link: "../b/sub", spelled: "out/lk/../f",
			reached: "b/f", rule: ruleUnmatched, verdict: record.VerdictRefused},
		{name: "a target the walk reaches is refused under its own rule", link: "x/sub", spelled: "out/lk/../f",
			reached: "out/x/f", rule: "fs.deny_write[out/x/f]", verdict: record.VerdictRefused},
		{name: "a walk that fails past the directory decides where it names the end", link: "../b/sub", spelled: "out/lk/../loop",
			reached: "b/loop", rule: ruleUnmatched, verdict: record.VerdictRefused, heldErrno: unix.ELOOP},
	} {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, "held"} {
			t.Run(fmt.Sprintf("%s/%s", tc.name, tier), func(t *testing.T) {
				var x *heldAskFixture
				var w string
				if tier == "held" {
					x = newHeldAskFixture(t)
					w = x.dir
				} else {
					var err error
					if w, err = filepath.EvalSymlinks(t.TempDir()); err != nil {
						t.Fatal(err)
					}
				}
				for _, d := range []string{"out/x/sub", "b/sub"} {
					if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				for link, target := range map[string]string{"out/lk": tc.link, "b/loop": "loop"} {
					if err := os.Symlink(target, filepath.Join(w, link)); err != nil {
						t.Fatal(err)
					}
				}
				write := agent.FSRule{Path: w + "/out", Resolved: w + "/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}
				var deny []agent.FSRule
				for _, p := range []string{"out/f", "out/x/f"} {
					deny = append(deny, agent.FSRule{Path: filepath.Join(w, p), Resolved: filepath.Join(w, p), Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true})
				}
				var l *Loop
				var f *fakeKernel
				var sink *testSink
				if x != nil {
					x.f.realWalks, x.f.goneOnSend = true, true
					x.pol.Rules.FS = append(x.pol.Rules.FS, write)
					x.pol.Rules.DenyWrite = deny
					x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90).WithHeldCompletion()
					l, sink, _ = x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
					f = x.f
					x.openAs(t, l, w+"/"+tc.spelled, unix.O_WRONLY|unix.O_CREAT, 0o600)
				} else {
					f = newFake()
					f.realWalks, f.goneOnSend = true, true
					pol := testPolicy(nil, []agent.FSRule{write}, nil)
					pol.Rules.Tier = tier
					pol.Rules.DenyWrite = deny
					pol.Record = agent.RecordFull
					l, sink = newTestLoop(t, f, pol)
					f.put(pathAddr, cstr(w+"/"+tc.spelled))
					l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT, 0o600))
				}
				var lines []*record.Event
				for _, ev := range sink.all() {
					if ev.Kind == record.KindFS {
						lines = append(lines, ev)
					}
				}
				if len(lines) != 1 {
					t.Fatalf("%d fs lines, want one", len(lines))
				}
				ev := lines[0]
				var p record.FSPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				rule := tc.rule
				if rule != ruleUnmatched {
					rule = "fs.deny_write[" + filepath.Join(w, tc.reached) + "]"
				}
				reached := filepath.Join(w, tc.reached)
				if p.Path != reached || ev.Verdict != tc.verdict || ev.Rule != rule {
					t.Errorf("line: %s %q rule %s (%s); want %s %q rule %s: the file the open reaches, decided there",
						ev.Verdict, p.Path, ev.Rule, ev.Reason, tc.verdict, reached, rule)
				}
				res, _ := f.lastResp()
				// The loop refuses a deny_write target itself, and at tier cgroup with no plane every refused
				// mutation (fallbackMutation); a held open is answered by this loop whatever it decides.
				selfRefused := rule != ruleUnmatched || tier != backend.TierLandlock
				switch {
				case tier == "held" && tc.heldErrno != 0 && rule == ruleUnmatched:
					if res.Error != -int32(tc.heldErrno) {
						t.Errorf("answered %+v, want the pin's %v", res, tc.heldErrno)
					}
				case selfRefused:
					if res.Error != -int32(unix.EACCES) {
						t.Errorf("answered %+v, want EACCES from this loop", res)
					}
				default:
					if res.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
						t.Errorf("answered %+v, want CONTINUE: Landlock decides the continued open", res)
					}
				}
			})
		}
	}
	// An fs.ask scope with no held object to match is matched where the end is named: out/lk/../q/f reaches b/q/f, which
	// no scope covers, though its lexical clean out/q/f lies in out/q's. askOpen has two such matches: a kernel that
	// cannot hold an open (no askOpenKernel), and the one every real run reaches, PrepareAskOpen failing: here the real
	// pin of a write-only open of a missing f, ENOENT. The second was switched with no test (-3s4-2): matched on the
	// clean, it refused the open ask-unreadable under fs.ask
	// on a line naming b/q/f, a file that scope does not cover.
	for _, kc := range []struct {
		name  string
		flags int
		pin   bool // the kernel holds opens (askOpenKernel), and its pin fails
	}{
		{"with no kernel to hold the open", unix.O_WRONLY | unix.O_CREAT, false},
		{"when the pin fails", unix.O_WRONLY, true},
	} {
		t.Run("an fs.ask scope is matched where the end is named "+kc.name, func(t *testing.T) {
			w, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{"out/q", "b/sub", "b/q"} {
				if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("../b/sub", filepath.Join(w, "out/lk")); err != nil {
				t.Fatal(err)
			}
			f := newFake()
			f.realWalks, f.goneOnSend = true, true
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Tier = backend.TierLandlock
			pol.Rules.Workdir = w
			pol.Rules.FSAsk = []agent.FSRule{{Path: w + "/out/q", Resolved: w + "/out/q", Kind: agent.FSAsk, Raw: "./out/q/"}}
			pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
			pol.Record = agent.RecordFull
			var l *Loop
			var sink *testSink
			if kc.pin {
				sink = &testSink{}
				var err error
				if l, err = New(testListener(), pol, sink, Options{kernel: &askReadKernel{fakeKernel: f, tid: selfTask(t)}, Workers: 1}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(l.closeAskScopes)
			} else {
				l, sink = newTestLoop(t, f, pol)
			}
			f.put(pathAddr, cstr(w+"/out/lk/../q/f"))
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, uint64(kc.flags), 0o600))
			ev := sink.one(t)
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if res, _ := f.lastResp(); p.Path != w+"/b/q/f" || ev.Rule != ruleUnmatched || res.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Errorf("line: %s %q rule %s (%s), answered %+v; want a continued refusal of %q, rule %s: no scope covers it",
					ev.Verdict, p.Path, ev.Rule, ev.Reason, res, w+"/b/q/f", ruleUnmatched)
			}
		})
	}
	// The gate scores such an end where it is named too (landed): out/lk/../loop, whose walk loops past b, is a write
	// outside the worktree out, which its lexical clean out/loop is not.
	t.Run("the gate scores a failed walk where it names the end", func(t *testing.T) {
		w, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(w, "out"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(w, "b/sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		for link, target := range map[string]string{"out/lk": "../b/sub", "b/loop": "loop"} {
			if err := os.Symlink(target, filepath.Join(w, link)); err != nil {
				t.Fatal(err)
			}
		}
		f := newFake()
		f.realWalks, f.goneOnSend = true, true
		pol := testPolicy(nil, []agent.FSRule{{Path: w, Resolved: w, Kind: agent.FSWrite, Raw: "./", Access: agent.AccessWriteSet}}, nil)
		pol.Rules.Tier = backend.TierLandlock
		pol.Rules.Workdir = w + "/out"
		pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90)
		l, sink := newTestLoop(t, f, pol)
		f.put(pathAddr, cstr(w+"/out/lk/../loop"))
		l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT, 0o600))
		ev := sink.one(t)
		var p record.FSPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Path != w+"/b/loop" || ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate {
			t.Errorf("line: %s %q rule %s (%s); want refused %q by the gate: a write outside the worktree",
				ev.Verdict, p.Path, ev.Rule, ev.Reason, w+"/b/loop")
		}
	})
}
