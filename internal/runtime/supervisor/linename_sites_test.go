// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEverySiteTakesTheEndWhereItsWalkPutsIt pins, one subtest per site, each place the loop decides, scores or names an
// end by its walk (R15b: landed, lineName, memoName), where reverting that one site to R6's spelling left every other
// test passing (the mutation sweep of the design).
// Each subtest fails with its site reverted. The tree: out/lk -> ../b/sub, so
// out/lk/../f reaches b/f while R6's lexical clean says out/f; out is the worktree.
//
// Spec: docs/p0/supervisor.md R15b, R15c; docs/p0/gate.md R1.
func TestEverySiteTakesTheEndWhereItsWalkPutsIt(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	tree := func(t *testing.T, w string) {
		t.Helper()
		for _, d := range []string{"out/sub", "out/realbin/sub", "b/sub", "b/secret"} {
			if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for _, f := range []string{"out/x", "b/secret/k", "out/realbin/e"} {
			if err := os.WriteFile(filepath.Join(w, f), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for link, target := range map[string]string{"out/lk": "../b/sub", "out/rl": "realbin/sub", "out/realbin/f": "../f",
			"out/realbin/ln": "e"} {
			if err := os.Symlink(target, filepath.Join(w, link)); err != nil {
				t.Fatal(err)
			}
		}
	}
	tempTree := func(t *testing.T) string {
		t.Helper()
		w, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		tree(t, w)
		return w
	}
	fsLine := func(t *testing.T, sink *testSink) (*record.Event, record.FSPayload) {
		t.Helper()
		var lines []*record.Event
		for _, ev := range sink.all() {
			if ev.Kind == record.KindFS {
				lines = append(lines, ev)
			}
		}
		if len(lines) != 1 {
			t.Fatalf("%d fs lines, want one", len(lines))
		}
		var p record.FSPayload
		if err := lines[0].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		return lines[0], p
	}

	// settleFS scores an unlink and a rename's new name where their walks land them (landed(e), landed(e2)): b/f and
	// b/y lie outside the worktree, their cleans out/f and out/y inside it.
	for _, tc := range []struct {
		name, syscall, from, to, reached string
		args                             []uint64
	}{
		{"the gate scores an unlink where its walk lands", "unlinkat", "out/lk/../f", "", "b/f", []uint64{argCWD, pathAddr, 0}},
		{"the gate scores a rename's new name where its walk lands", "renameat", "out/x", "out/lk/../y", "b/y",
			[]uint64{argCWD, pathAddr, argCWD, path2Addr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := tempTree(t)
			f := newFake()
			f.realWalks, f.goneOnSend = true, true
			pol := testPolicy(nil, []agent.FSRule{{Path: w, Resolved: w, Kind: agent.FSWrite, Raw: "./", Access: agent.AccessWriteSet}}, nil)
			pol.Rules.Tier = backend.TierLandlock
			pol.Rules.Workdir = w + "/out"
			pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90)
			l, sink := newTestLoop(t, f, pol)
			f.put(pathAddr, cstr(w+"/"+tc.from))
			if tc.to != "" {
				f.put(path2Addr, cstr(w+"/"+tc.to))
			}
			l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args...))
			ev, p := fsLine(t, sink)
			named := p.Path
			if tc.to != "" {
				named = p.Path2
			}
			if named != w+"/"+tc.reached || ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate {
				t.Errorf("line: %s %q %q rule %s (%s); want refused by the gate, naming %q: a write outside the worktree",
					ev.Verdict, p.Path, p.Path2, ev.Rule, ev.Reason, w+"/"+tc.reached)
			}
		})
	}

	// matchEnds matches an end's landing whenever it differs from the end's name (at != lineName), not from its
	// spelling: out/rl/../f, with out/rl -> realbin/sub, is named out/realbin/f (the final component unfollowed) and
	// the open follows that link to out/f, which is its lexical clean too, and a deny_write target. Skipped because the
	// landing equals the clean, the write reached the target with no refusal.
	t.Run("R15c matches a landing that only the lexical clean also spells", func(t *testing.T) {
		w := tempTree(t)
		f := newFake()
		f.realWalks, f.goneOnSend = true, true
		pol := testPolicy(nil, []agent.FSRule{{Path: w + "/out", Resolved: w + "/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
		pol.Rules.Tier = backend.TierLandlock
		pol.Rules.DenyWrite = []agent.FSRule{{Path: w + "/out/f", Resolved: w + "/out/f", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true}}
		pol.Record = agent.RecordFull
		l, sink := newTestLoop(t, f, pol)
		f.put(pathAddr, cstr(w+"/out/rl/../f"))
		l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT, 0o600))
		ev, p := fsLine(t, sink)
		res, _ := f.lastResp()
		if rule := "fs.deny_write[" + w + "/out/f]"; ev.Rule != rule || ev.Verdict != record.VerdictRefused || res.Error != -int32(unix.EACCES) ||
			p.Path != w+"/out/realbin/f" {
			t.Errorf("line: %s %q rule %s, answered %+v; want refused %q under %s, by this loop", ev.Verdict, p.Path, ev.Rule, res,
				w+"/out/realbin/f", rule)
		}
	})

	// listenerRefuses asks whether Landlock lets an open through to tier 2's listener where the open lands (landed):
	// out/lk/../secret/k reaches b/secret/k, inside the write entry b whose nested deny_read the listener enforces, so
	// the listener refuses it and writes its line, and this loop writes none. Its clean out/secret/k lies under a
	// deny_read no write entry encloses, which Landlock refuses first: asked there, this loop wrote a second line.
	t.Run("the listener's refusal is asked where the open lands", func(t *testing.T) {
		w := tempTree(t)
		f := newFake()
		f.realWalks, f.goneOnSend = true, true
		pol := testPolicy(nil, []agent.FSRule{
			{Path: w + "/b", Resolved: w + "/b", Kind: agent.FSWrite, Raw: "./b/", Access: agent.AccessWriteSet},
			{Path: w + "/b/secret", Resolved: w + "/b/secret", Kind: agent.FSDenyRead, Raw: "./b/secret/"},
			{Path: w + "/out/secret", Resolved: w + "/out/secret", Kind: agent.FSDenyRead, Raw: "./out/secret/"},
		}, nil)
		pol.Rules.Tier = backend.TierCgroup
		pol.Record = agent.RecordFull
		l, sink := newTestLoop(t, f, pol)
		f.put(pathAddr, cstr(w+"/out/lk/../secret/k"))
		l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, unix.O_RDONLY))
		if lines := sink.all(); len(lines) != 0 {
			var p record.FSPayload
			_ = lines[0].DecodePayload(&p)
			t.Errorf("%d lines from this loop (%s %q %s), want none: the listener refuses the read and writes its line",
				len(lines), lines[0].Verdict, p.Path, lines[0].Reason)
		}
	})

	// handOver keys the naming it leaves to the kernel recorder by the final component of where the open lands
	// (landed): out/lk/../ln is named out/realbin/ln and opens out/realbin/e, whose record carries "e".
	t.Run("the recorder's naming is found by the file the open reaches", func(t *testing.T) {
		w := tempTree(t)
		if err := os.Remove(filepath.Join(w, "out/lk")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("realbin/sub", filepath.Join(w, "out/lk")); err != nil {
			t.Fatal(err)
		}
		f := newFake()
		f.realWalks, f.goneOnSend = true, true
		pol := testPolicy(nil, []agent.FSRule{{Path: w + "/out", Resolved: w + "/out", Kind: agent.FSWrite, Raw: "./out/", Access: agent.AccessWriteSet}}, nil)
		pol.Rules.Tier = backend.TierCgroup
		pol.Rules.Record = agent.RecordFull
		l, sink := newTestLoop(t, f, pol)
		l.kernelFS = func() bool { return true }
		f.put(pathAddr, cstr(w+"/out/lk/../ln"))
		l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, unix.O_WRONLY))
		if got := len(sink.all()); got != 0 {
			t.Fatalf("%d lines from this loop, want none: the kernel recorder writes it", got)
		}
		n, ok := l.ContinuedFS(42, record.FSOpen, "e", "", monotonicNS())
		if !ok || n.Path != w+"/out/realbin/ln" {
			t.Errorf("ContinuedFS(e) = %+v, %v; want the naming of %q, found by the file the open reaches", n, ok, w+"/out/realbin/ln")
		}
	})

	// heldOpen scores the copied name where this loop's walk landed it (D3 step 1), before anything is pinned: b/f is a
	// write outside the worktree. Scored on the clean out/f, the open was pinned and refused only on the pinned object.
	t.Run("a held open's copied name is scored where its walk lands, before the pin", func(t *testing.T) {
		x := newHeldAskFixture(t)
		x.f.realWalks, x.f.goneOnSend = true, true
		tree(t, x.dir)
		x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
		x.pol.Rules.Workdir = x.dir + "/out"
		x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90).WithHeldCompletion()
		l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
		x.openAs(t, l, x.dir+"/out/lk/../f", unix.O_WRONLY|unix.O_CREAT, 0o600)
		ev, p := fsLine(t, sink)
		x.dep.mu.Lock()
		pins := x.dep.pins
		x.dep.mu.Unlock()
		if p.Path != x.dir+"/b/f" || ev.Reason != record.ReasonFSGate || pins != 0 || len(*asked) != 0 {
			t.Errorf("line: %s %q (%s), %d pins, %d asks; want refused %q by the gate on the copied name, nothing pinned",
				ev.Verdict, p.Path, ev.Reason, pins, len(*asked), x.dir+"/b/f")
		}
	})

	// heldName names a delivered held open of a nameless object (a memfd) as its decision's walk named it: pl/../fd/N,
	// with pl -> /proc/self/fd, reaches the memfd, which has no name; the walk names the open where it looked N up,
	// /proc/<pid>/fd/N, and the lexical clean names <dir>/fd/N, which does not exist. With no fallback the line named
	// nothing and read observed.
	t.Run("a delivered nameless held open is named as its decision named it", func(t *testing.T) {
		x := newHeldAskFixture(t)
		x.f.realWalks, x.f.goneOnSend = true, true
		x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
		fd, err := unix.MemfdCreate("held", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		if _, err := unix.Write(fd, []byte("anonymous")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/proc/self/fd", filepath.Join(x.dir, "pl")); err != nil {
			t.Fatal(err)
		}
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		x.openAs(t, l, x.dir+"/pl/../fd/"+strconv.Itoa(fd), unix.O_RDONLY, 0)
		if len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != "anonymous" {
			res, _ := x.f.lastResp()
			t.Fatalf("answer %+v, delivered %q, lines %+v: a memfd is nameless, and is delivered", res, x.k.heldDelivered, sink.all())
		}
		ev, p := fsLine(t, sink)
		if want := "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.Itoa(fd); p.Path != want {
			t.Errorf("line: %s %q rule %s; want it named %q, where the decision's walk looked the descriptor up", ev.Verdict, p.Path, ev.Rule, want)
		}
	})

	// heldCopiedRefusal scores an fs.ask hold's copied name where this loop's walk landed it, and its refusal stands
	// whatever the pin then reaches: the decision's walk reaches b/f, outside the worktree; the link moves
	// before the pin, which reaches out/f inside it. Scored on the clean out/f, the hold went on to the person.
	t.Run("an fs.ask hold's copied name is scored where the decision's walk landed", func(t *testing.T) {
		x := newHeldAskFixture(t)
		x.f.realWalks, x.f.goneOnSend = true, true
		tree(t, x.dir)
		x.pol.Rules.Workdir = x.dir + "/out"
		x.pol.Rules.FSAsk = []agent.FSRule{{Path: x.dir, Resolved: x.dir, Kind: agent.FSAsk, Raw: "./"}}
		x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
		x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90).WithHeldCompletion()
		x.k.beforePrepare = func() {
			_ = os.Remove(filepath.Join(x.dir, "out/lk"))
			_ = os.Symlink("sub", filepath.Join(x.dir, "out/lk"))
		}
		l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
		x.openAs(t, l, x.dir+"/out/lk/../f", unix.O_WRONLY|unix.O_CREAT, 0o600)
		ev, _ := fsLine(t, sink)
		if res, _ := x.f.lastResp(); ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate || len(*asked) != 0 ||
			res.Error != -int32(unix.EACCES) {
			t.Errorf("line: %s rule %s (%s), %d asks, answered %+v; want refused by the gate on the copied name, no one asked",
				ev.Verdict, ev.Rule, ev.Reason, len(*asked), res)
		}
	})
}
