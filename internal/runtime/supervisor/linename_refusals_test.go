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
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRefusalLinesNameWhereADotDotSpellingLands: every open this loop refuses itself on the ask and gate paths names
// the file the open reached, as settleFS's lines do (lineName), and not R6's lexical clean of its spelling. With lk ->
// real/sub, an open of lk/../x.env reaches real/x.env, and its spelling cleans to x.env, a file that does not exist.
// One case per refusal site that names the copied open: askOpen's refusals (here an ask with no ask kernel to hold
// it) and its gate refusal of the held file, completeHeldAskOpen's refusal (the person denies), completeAlternate's
// (an alternate with no file), askReadOpen's (the entry's scope was replaced), gateOpen's (a gate ask with no ask
// kernel), and a held open's refusal before its pin (heldRefuse: the gate refuses the copied name). Each once named the
// cleaned spelling. The
// fake reads an answered notification gone, as the kernel does, so each name must be walked before the answer. The two
// refusals made after a person's wait are also tried with lk moved during the wait: the name is the decision's walk,
// made before the wait, and a second walk at refusal time named the file lk led to then. And a refusal decided on
// the held object, once the open is pinned, names it by
// the pin's own walk: with lk moved between the decision's walk and the pin, the gate scored, and the person was
// asked about, other/x.env, which the line names (askLineName).
//
// Spec: docs/p0/supervisor.md R15b.
func TestRefusalLinesNameWhereADotDotSpellingLands(t *testing.T) {
	askConfig := &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
	// tree makes dir/real/sub, dir/real/x.env and dir/lk -> real/sub in dir, and answers the open's spelling and the
	// file it reaches.
	tree := func(t *testing.T, dir string) (spelled, reached string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "real/sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		reached = filepath.Join(dir, "real/x.env")
		if err := os.WriteFile(reached, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real/sub", filepath.Join(dir, "lk")); err != nil {
			t.Fatal(err)
		}
		return dir + "/lk/../x.env", reached
	}
	for _, tc := range []struct {
		name   string
		flags  int
		reason record.Reason
		// ask kernel: the real held-open walk (askReadKernel); without it the fake kernel holds no open.
		askKernel bool
		setup     func(t *testing.T, dir string, pol *Policy)
		// answer is the person's answer to an ask, given the test's directory.
		answer func(dir string) ask.Decision
		// after runs once the loop is built, before the open.
		after func(t *testing.T, dir string)
		// movedBeforePin moves lk between the decision's walk and the pin (relinkDuringTheWait): the refusal is decided
		// on the held object, other/x.env, and names it.
		movedBeforePin bool
	}{
		{name: "askOpen: an fs.ask with no ask kernel to hold it", flags: unix.O_WRONLY, reason: record.ReasonAskUnavailable,
			setup: func(_ *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			}},
		{name: "askOpen: the gate refuses the held file", flags: unix.O_RDWR, reason: record.ReasonFSGate, askKernel: true,
			setup: func(t *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
				pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 95)
			}},
		{name: "completeHeldAskOpen: the person denies", flags: unix.O_WRONLY, reason: record.ReasonAskDenied, askKernel: true,
			answer: func(string) ask.Decision { return ask.Decision{Reason: ask.ReasonDenied, By: "uid:1 pid:2"} },
			setup: func(_ *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			}},
		{name: "completeAlternate: an alternate with no file", flags: unix.O_WRONLY, reason: record.ReasonAskUnavailable, askKernel: true,
			answer: func(dir string) ask.Decision {
				return ask.Decision{Alternate: filepath.Join(dir, "stand-in"), By: "uid:1 pid:2"}
			},
			setup: func(_ *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			}},
		{name: "completeHeldAskOpen: the person denies after the link moved", flags: unix.O_WRONLY, reason: record.ReasonAskDenied, askKernel: true,
			answer: func(dir string) ask.Decision {
				if relinkDuringTheWait(dir) != nil {
					return ask.Decision{Approved: true} // no refusal: the test fails
				}
				return ask.Decision{Reason: ask.ReasonDenied, By: "uid:1 pid:2"}
			},
			setup: func(_ *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			}},
		{name: "completeAlternate: an alternate with no file, after the link moved", flags: unix.O_WRONLY, reason: record.ReasonAskUnavailable, askKernel: true,
			answer: func(dir string) ask.Decision {
				if relinkDuringTheWait(dir) != nil {
					return ask.Decision{Approved: true} // no refusal: the test fails
				}
				return ask.Decision{Alternate: filepath.Join(dir, "stand-in"), By: "uid:1 pid:2"}
			},
			setup: func(_ *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			}},
		{name: "askOpen: the gate refuses the held file the link moved to before the pin", flags: unix.O_RDWR,
			reason: record.ReasonFSGate, askKernel: true, movedBeforePin: true,
			setup: func(t *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
				pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 95)
			}},
		{name: "completeHeldAskOpen: the person denies the held file the link moved to before the pin", flags: unix.O_WRONLY,
			reason: record.ReasonAskDenied, askKernel: true, movedBeforePin: true,
			answer: func(string) ask.Decision { return ask.Decision{Reason: ask.ReasonDenied, By: "uid:1 pid:2"} },
			setup: func(_ *testing.T, dir string, pol *Policy) {
				pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			}},
		{name: "askReadOpen: the entry's scope was replaced", flags: unix.O_RDONLY, reason: record.ReasonAskUnavailable, askKernel: true,
			answer: func(string) ask.Decision { return ask.Decision{Approved: true} },
			setup: func(_ *testing.T, dir string, pol *Policy) {
				real := filepath.Join(dir, "real")
				pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Path: real, Resolved: real, Kind: agent.FSDenyRead, AskRead: true, Raw: real})
			},
			after: func(t *testing.T, dir string) {
				real := filepath.Join(dir, "real")
				if err := os.Rename(real, real+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(real, "sub"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(real, "x.env"), []byte("planted"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "gateOpen: a gate ask with no ask kernel to hold it", flags: unix.O_RDWR, reason: record.ReasonAskUnavailable,
			setup: func(t *testing.T, dir string, pol *Policy) {
				pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Path: dir, Resolved: dir, Kind: agent.FSWrite, Raw: dir, Access: agent.AccessWriteSet})
				pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 70)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			spelled, reached := tree(t, dir)
			f := newFake()
			f.realWalks, f.goneOnSend = true, true
			var k kernel = f
			if tc.askKernel {
				ak := &askReadKernel{fakeKernel: f, tid: selfTask(t)}
				if tc.movedBeforePin {
					ak.beforePrepare = func() {
						if err := relinkDuringTheWait(dir); err != nil {
							t.Error(err)
						}
					}
					reached = filepath.Join(dir, "other/x.env")
				}
				k = ak
			}
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Tier = backend.TierLandlock
			pol.Rules.Workdir = dir
			pol.Rules.AskConfig = askConfig
			tc.setup(t, dir, pol)
			sink := &testSink{}
			l, err := New(testListener(), pol, sink, Options{kernel: k, Ask: func(context.Context, ask.Request) (ask.Decision, error) {
				if tc.answer == nil {
					return ask.Decision{Approved: true}, nil
				}
				return tc.answer(dir), nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(l.closeAskScopes)
			if tc.after != nil {
				tc.after(t, dir)
			}
			f.put(0x10000, cstr(spelled))
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000, uint64(tc.flags)))
			wantRefusalNamed(t, f, sink, tc.reason, reached)
		})
	}
	t.Run("heldRefuse: the gate refuses the copied name before the pin", func(t *testing.T) {
		x := newHeldAskFixture(t)
		x.f.realWalks, x.f.goneOnSend = true, true
		spelled, reached := tree(t, x.dir)
		x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
		x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
		x.openAs(t, l, spelled, unix.O_RDONLY, 0)
		wantRefusalNamed(t, x.f, sink, record.ReasonFSGate, reached)
	})
}

// relinkDuringTheWait moves dir/lk to other/sub, beside which other/x.env lies, while a person decides: a name walked
// after the wait, apart from the decision's walk, names other/x.env, a file nothing decided.
func relinkDuringTheWait(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, "other/sub"), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "other/x.env"), []byte("other"), 0o600); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "lk")); err != nil {
		return err
	}
	return os.Symlink("other/sub", filepath.Join(dir, "lk"))
}

// wantRefusalNamed checks that the open was answered EACCES and that its one fs line is a refusal for reason naming
// path.
func wantRefusalNamed(t *testing.T, f *fakeKernel, sink *testSink, reason record.Reason, path string) {
	t.Helper()
	if res, _ := f.lastResp(); res.Error != -int32(unix.EACCES) {
		t.Fatalf("answered %+v, want EACCES", res)
	}
	var lines []*record.Event
	for _, ev := range sink.all() {
		if ev.Kind == record.KindFS {
			lines = append(lines, ev)
		}
	}
	if len(lines) != 1 || lines[0].Verdict != record.VerdictRefused || lines[0].Reason != reason {
		t.Fatalf("fs lines %+v, want one refusal for %s", lines, reason)
	}
	var p record.FSPayload
	if err := lines[0].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Path != path {
		t.Errorf("the refusal names %q, want %q: the file the open reached", p.Path, path)
	}
}
