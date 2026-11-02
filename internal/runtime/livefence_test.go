// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The fence the tests seed: one entry of each kind, the exec entry with a helper image and the program name an
// exec.deny entry named.
const (
	fenceRead  = "/srv/exports"
	fenceNet   = "192.0.2.9:443"
	fenceExec  = "/usr/bin/psql"
	fenceImage = "/usr/lib/postgresql/bin/psql"
)

var fenceDest = netip.MustParseAddrPort(fenceNet)

// fencedTable is an Adjustable table at tier cgroup that holds its reads, with the test fence.
func fencedTable() *agent.RuleTable {
	return &agent.RuleTable{Contract: &agent.Contract{Name: "fenced"}, Tier: backend.TierCgroup,
		Reads: agent.HeldReads{Mode: agent.ReadsHeld},
		Live: &agent.LiveTable{Mode: agent.LiveAdjustable, SHA256: strings.Repeat("ab", 32), Entries: []agent.LiveEntry{
			{Kind: agent.LiveKindRead, Value: fenceRead, Source: agent.LiveSourceDeny},
			{Kind: agent.LiveKindNet, Value: fenceNet, Source: agent.LiveSourceNew},
			{Kind: agent.LiveKindExec, Value: fenceExec, Source: agent.LiveSourceDeny, Name: "psql", Images: []string{fenceImage}},
		}}}
}

// fenceRunner is a runner of the fenced table with a run directory, a supervisor's listener stand-in and a queue.
func fenceRunner(t *testing.T) *runner {
	t.Helper()
	r := pauseRunner(t)
	r.rt = fencedTable()
	r.rt.FS = []agent.FSRule{{Path: r.dir, Resolved: r.dir, Kind: agent.FSDenyRead, BuiltIn: true}}
	r.queue = NewQueue(64)
	rd, wr, err := sys.Pipe2(syscall.O_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rd.Close(); _ = wr.Close() })
	r.notifyFD = rd
	return r
}

// refusedRules is the rule each fence refusal of s carries, "" for an action s does not refuse: the read beneath the
// read entry, the connect, and an exec of the program by its path, by its helper image and by its bare name.
func refusedRules(s *liveblock.Set) []string {
	var out []string
	add := func(e liveblock.Entry, ok bool) {
		if !ok {
			out = append(out, "")
			return
		}
		out = append(out, e.Rule())
	}
	add(s.MatchPath(fenceRead+"/q3.csv", liveblock.AccessRead))
	add(s.MatchInet(fenceDest, "", nil))
	add(s.MatchExec([]string{fenceExec}, liveblock.FileID{}, false))
	add(s.MatchExec([]string{fenceImage}, liveblock.FileID{}, false))
	add(s.MatchExec([]string{"/opt/elsewhere/psql"}, liveblock.FileID{}, false))
	return out
}

var allRefused = []string{"live.fence[read:" + fenceRead + "]", "live.fence[net:" + fenceNet + "]",
	"live.fence[exec:" + fenceExec + "]", "live.fence[exec:" + fenceExec + "]", "live.fence[exec:" + fenceExec + "]"}

// readLift is a lift of the read entry, MAC'ed under key, with its serial set as Overlay.Lift sets it.
func liftRead(t *testing.T, r *runner, key []byte, by string, at, until time.Time) {
	t.Helper()
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, err := o.Lift(liveblock.KindRead, fenceRead, by, at, until, key)
		return err
	})
}

// TestFenceFirstSetRefusesEveryEntry: the first Set the supervisor loads, before the agent's first instruction,
// refuses every fence entry under its live.fence rule, the exec entry by its path, its helper image and its name; the
// run's key is in its run directory, 0600; and nothing is lifted, so no line is written.
func TestFenceFirstSetRefusesEveryEntry(t *testing.T) {
	r := fenceRunner(t)
	b, err := r.startLiveBlocks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.fence == nil {
		t.Fatal("an Adjustable run has no fence")
	}
	if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
		t.Fatalf("first Set refuses %q, want %q", got, allRefused)
	}
	st, err := os.Lstat(filepath.Join(r.dir, liveblock.KeyName))
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() != 32 {
		t.Fatalf("live key: %v %v", st, err)
	}
	if lines := liveLines(t, r); len(lines) != 0 {
		t.Fatalf("seeding wrote lines: %+v", lines)
	}
}

// TestLockedRunHasNoFence: a Locked run makes no live-key, installs no fence and writes no live fields in run_start.
func TestLockedRunHasNoFence(t *testing.T) {
	for _, rt := range []*agent.RuleTable{{Contract: &agent.Contract{Name: "a"}},
		{Contract: &agent.Contract{Name: "a"}, Live: &agent.LiveTable{Mode: agent.LiveLocked}}} {
		r := pauseRunner(t)
		r.rt = rt
		b, err := r.startLiveBlocks(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if b.fence != nil {
			t.Fatal("a Locked run installed a fence")
		}
		if _, err := os.Lstat(filepath.Join(r.dir, liveblock.KeyName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a Locked run made a live key: %v", err)
		}
		if b.Load() != nil {
			t.Fatal("a Locked run with no overlay refuses something")
		}
		if mode, fence := runLiveFence(rt); mode != "" || fence != nil {
			t.Fatalf("a Locked run's run_start carries live_mode %q, live_fence %+v", mode, fence)
		}
	}
}

// TestRunStartCarriesTheFence: an Adjustable run's run_start carries live_mode adjustable and the fence, each entry
// under its live.fence rule.
func TestRunStartCarriesTheFence(t *testing.T) {
	rt := fencedTable()
	mode, fence := runLiveFence(rt)
	if mode != record.LiveModeAdjustable || fence == nil || fence.SHA256 != rt.Live.SHA256 || len(fence.Entries) != 3 {
		t.Fatalf("live_mode %q, live_fence %+v", mode, fence)
	}
	for i, e := range fence.Entries {
		le := rt.Live.Entries[i]
		if e.Kind != le.Kind || e.Value != le.Value || e.Source != le.Source || e.Rule != le.Rule() || e.Name != le.Name {
			t.Errorf("entry %d: %+v, want %+v", i, e, le)
		}
	}
}

// TestFenceLiftLoosensAfterItsLine: a lift with a good MAC loosens its entry, and its live-rule-lifted line is queued
// while the Set in force still refuses it; the other entries still refuse.
func TestFenceLiftLoosensAfterItsLine(t *testing.T) {
	r := fenceRunner(t)
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := b.fence.(*liveFence)
	refusedAtLine := false
	emit := f.emit
	f.emit = func(why string, n int, c *record.LiveBlockChange) {
		if why == record.GapLiveRuleLifted {
			_, refusedAtLine = b.Load().MatchPath(fenceRead+"/q3.csv", liveblock.AccessRead)
		}
		emit(why, n, c)
	}
	at := time.Now()
	liftRead(t, r, f.key, "uid:1000 pid:7 cli", at, time.Time{})
	r.pollLiveBlocks(ctx, b)
	if !refusedAtLine {
		t.Fatal("the lift's line was queued after the loosened Set was stored")
	}
	got := refusedRules(b.Load())
	if want := append([]string{""}, allRefused[1:]...); !slices.Equal(got, want) {
		t.Fatalf("after the lift the Set refuses %q, want %q", got, want)
	}
	lines := liveLines(t, r)
	if len(lines) != 1 || lines[0].Why != record.GapLiveRuleLifted {
		t.Fatalf("lines %+v, want one live-rule-lifted", lines)
	}
	c := lines[0].LiveBlock
	if c.Op != record.LiveOpLift || c.Rule != "live.fence[read:"+fenceRead+"]" || c.By != "uid:1000 pid:7 cli" ||
		c.Serial != 1 || !c.Until.IsZero() {
		t.Fatalf("lifted line %+v", c)
	}
}

// TestFenceRefusesBadLifts: a lift whose MAC does not check, one of an entry outside the fence and one whose limit
// has passed each get one live-lift-refused with its reason, and nothing loosens.
func TestFenceRefusesBadLifts(t *testing.T) {
	r := fenceRunner(t)
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := b.fence.(*liveFence).key
	t0 := time.Now().UTC().Round(time.Millisecond)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, err := o.Lift(liveblock.KindRead, fenceRead, "uid:1 pid:2 cli", t0, time.Time{}, make([]byte, 32)); err != nil {
			return err
		}
		if _, err := o.Lift(liveblock.KindNet, "198.51.100.1:443", "uid:1 pid:3 cli", t0, time.Time{}, key); err != nil {
			return err
		}
		_, err := o.Lift(liveblock.KindExec, fenceExec, "uid:1 pid:4 cli", t0, t0.Add(2*time.Minute), key)
		return err
	})
	old := liveNow
	liveNow = func() liveblock.Clock { c := liveblock.ReadClock(); c.Wall = t0.Add(5 * time.Minute); return c }
	t.Cleanup(func() { liveNow = old })
	r.pollLiveBlocks(ctx, b)
	if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
		t.Fatalf("after refused lifts the Set refuses %q, want %q", got, allRefused)
	}
	var got []string
	for _, p := range liveLines(t, r) {
		if p.Why != record.GapLiveLiftRefused {
			t.Fatalf("line %s %+v, want only live-lift-refused", p.Why, p.LiveBlock)
		}
		got = append(got, p.LiveBlock.Refused+" "+p.LiveBlock.Rule)
	}
	want := []string{record.LiveRefusedMAC + " live.fence[read:" + fenceRead + "]",
		record.LiveRefusedOutsideFence + " live.lift[net:198.51.100.1:443]",
		record.LiveRefusedUntil + " live.fence[exec:" + fenceExec + "]"}
	if !slices.Equal(got, want) {
		t.Fatalf("refused lines %q, want %q", got, want)
	}
}

// TestFenceRestore: a restore of a lifted entry refuses it again, with its live-rule-restored line; a restore of an
// entry that is not lifted writes nothing.
func TestFenceRestore(t *testing.T) {
	r := fenceRunner(t)
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := b.fence.(*liveFence).key
	liftRead(t, r, key, "uid:1 pid:2 cli", time.Now(), time.Time{})
	r.pollLiveBlocks(ctx, b)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, err := o.Restore(liveblock.KindRead, fenceRead, "uid:1 pid:3 dashboard", time.Now()); err != nil {
			return err
		}
		_, err := o.Restore(liveblock.KindNet, fenceNet, "uid:1 pid:4 cli", time.Now())
		return err
	})
	r.pollLiveBlocks(ctx, b)
	if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
		t.Fatalf("after the restore the Set refuses %q, want %q", got, allRefused)
	}
	lines := liveLines(t, r)
	if len(lines) != 2 || lines[0].Why != record.GapLiveRuleLifted || lines[1].Why != record.GapLiveRuleRestored {
		t.Fatalf("lines %+v, want lifted then restored", lines)
	}
	if c := lines[1].LiveBlock; c.Op != record.LiveOpRestore || c.By != "uid:1 pid:3 dashboard" || c.Serial != 2 ||
		c.Rule != "live.fence[read:"+fenceRead+"]" {
		t.Fatalf("restored line %+v", c)
	}
}

// TestFenceTimedLiftEndsAtTheInstant: on the real clocks, a lift for 2 s loosens its entry, the Set refuses it again
// at the instant with no poll in between, and the next poll writes one live-lift-expired carrying the until.
func TestFenceTimedLiftEndsAtTheInstant(t *testing.T) {
	r := fenceRunner(t)
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Round(time.Millisecond)
	until := at.Add(2 * time.Second)
	liftRead(t, r, b.fence.(*liveFence).key, "uid:1 pid:2 cli", at, until)
	r.pollLiveBlocks(ctx, b)
	if _, ok := b.Load().MatchPath(fenceRead, liveblock.AccessRead); ok {
		t.Fatal("a lift for 2 s did not loosen")
	}
	time.Sleep(time.Until(until) + 20*time.Millisecond)
	if e, ok := b.Load().MatchPath(fenceRead, liveblock.AccessRead); !ok || e.Rule() != "live.fence[read:"+fenceRead+"]" {
		t.Fatal("the Set did not refuse again at the lift's until")
	}
	r.pollLiveBlocks(ctx, b)
	r.pollLiveBlocks(ctx, b)
	lines := liveLines(t, r)
	if len(lines) != 2 || lines[1].Why != record.GapLiveLiftExpired {
		t.Fatalf("lines %+v, want lifted then one live-lift-expired", lines)
	}
	if c := lines[1].LiveBlock; c.Op != record.LiveOpExpire || !c.Until.Equal(until) || c.Serial != 1 {
		t.Fatalf("expired line %+v", c)
	}
}

// TestFenceLiftEndsOnEitherClock: with an injected clock, a lift ends as soon as either clock reaches its until. A
// wall clock stepped back an hour does not lengthen it: BOOTTIME reaching the pin ends it. A wall clock stepped
// forward ends it too.
func TestFenceLiftEndsOnEitherClock(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		after liveblock.Clock // the clock 3 s after the lift: wall stepped back, or forward
	}{
		{"wall stepped back", liveblock.Clock{Wall: t0.Add(-time.Hour), Boot: time.Hour + 3*time.Second}},
		{"wall stepped forward", liveblock.Clock{Wall: t0.Add(time.Hour), Boot: time.Hour + time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fenceRunner(t)
			ctx := context.Background()
			now := liveblock.Clock{Wall: t0, Boot: time.Hour}
			old := liveNow
			liveNow = func() liveblock.Clock { return now }
			t.Cleanup(func() { liveNow = old })
			b, err := r.startLiveBlocks(ctx)
			if err != nil {
				t.Fatal(err)
			}
			f := b.fence.(*liveFence)
			until := t0.Add(2 * time.Second)
			liftRead(t, r, f.key, "uid:1 pid:2 cli", t0, until)
			r.pollLiveBlocks(ctx, b)
			if l, ok := f.lifts[liveblock.Key(liveblock.KindRead, fenceRead)]; !ok || !l.pinned || l.pin != time.Hour+2*time.Second {
				t.Fatalf("lift %+v, want pinned at BOOTTIME 1h2s", l)
			}
			if e := f.Refusals(); !e[0].From.Equal(until) {
				t.Fatalf("the read refusal comes back at %v, want %v", e[0].From, until)
			}
			if p := f.Pins()[liveblock.DeadlineKey(liveblock.Key(liveblock.KindRead, fenceRead), until)]; p != time.Hour+2*time.Second {
				t.Fatalf("the Set's pin of the until is %v", p)
			}
			now = tc.after
			r.pollLiveBlocks(ctx, b)
			if _, ok := f.lifts[liveblock.Key(liveblock.KindRead, fenceRead)]; ok {
				t.Fatal("the lift outlived its until on one clock")
			}
			lines := liveLines(t, r)
			if len(lines) != 2 || lines[1].Why != record.GapLiveLiftExpired {
				t.Fatalf("lines %+v, want lifted then live-lift-expired", lines)
			}
		})
	}
}

// TestFenceBrokenOverlayDropsLifts: a corrupt overlay and a removed one each drop every lift, with a
// live-rule-restored line by tego, so every fence entry refuses again; a corrupt overlay keeps the blocks last read.
func TestFenceBrokenOverlayDropsLifts(t *testing.T) {
	for _, broken := range []string{"corrupt", "removed"} {
		t.Run(broken, func(t *testing.T) {
			r := fenceRunner(t)
			ctx := context.Background()
			b, err := r.startLiveBlocks(ctx)
			if err != nil {
				t.Fatal(err)
			}
			key := b.fence.(*liveFence).key
			updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
				if _, _, err := o.Add(liveblock.KindExec, "/bin/ls", "uid:1 pid:2 cli", time.Now()); err != nil {
					return err
				}
				if _, err := o.Lift(liveblock.KindRead, fenceRead, "uid:1 pid:3 cli", time.Now(), time.Time{}, key); err != nil {
					return err
				}
				_, err := o.Lift(liveblock.KindNet, fenceNet, "uid:1 pid:4 cli", time.Now(), time.Time{}, key)
				return err
			})
			r.pollLiveBlocks(ctx, b)
			if got := refusedRules(b.Load()); got[0] != "" || got[1] != "" {
				t.Fatalf("lifts did not loosen: %q", got)
			}
			overlay := filepath.Join(r.dir, liveblock.FileName)
			if broken == "corrupt" {
				if err := os.WriteFile(overlay, []byte("{not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(overlay); err != nil {
				t.Fatal(err)
			}
			r.pollLiveBlocks(ctx, b)
			if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
				t.Fatalf("after a %s overlay the Set refuses %q, want %q", broken, got, allRefused)
			}
			_, blocked := b.Load().MatchExec([]string{"/bin/ls"}, liveblock.FileID{}, false)
			if broken == "corrupt" && !blocked {
				t.Fatal("a corrupt overlay dropped the blocks last read")
			}
			restored := 0
			for _, p := range liveLines(t, r) {
				if p.Why == record.GapLiveRuleRestored {
					restored++
					if p.LiveBlock.By != fenceUnreadableBy {
						t.Errorf("restored line by %q", p.LiveBlock.By)
					}
				}
			}
			if restored != 2 {
				t.Fatalf("%d live-rule-restored lines, want 2", restored)
			}
		})
	}
}

// TestAdjustableRefusesToStart: an Adjustable run refuses to start, naming why, for each missing requirement of ADR
// 0125 decisions 6 and 7; with all of them it starts.
func TestAdjustableRefusesToStart(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(r *runner)
		why  string
	}{
		{"no run directory", func(r *runner) { r.dir = "" }, "no run directory"},
		{"observe", func(r *runner) { r.handle = verdictOnly{v: record.VerdictObserved} }, "--observe"},
		{"no supervisor", func(r *runner) { r.notifyFD = nil }, "no supervisor"},
		{"tier landlock", func(r *runner) { r.rt.Tier = backend.TierLandlock }, "tier landlock"},
		{"ledger readable", func(r *runner) { r.rt.FS[0].Unenforced = true }, "lies under no enforced built-in deny_read"},
		{"io_uring", func(r *runner) { c := *r.rt.Contract; c.IOUring = true; r.rt.Contract = &c }, "io_uring"},
		{"dropped notifications", func(r *runner) { r.planeFS = true }, "decision plane"},
		{"reads not held", func(r *runner) { r.rt.Reads.Mode = agent.ReadsDirect }, "read opens"},
		{"a fence the overlay cannot name", func(r *runner) { r.rt.Live.Entries[0].Value = "/srv/exports/" }, "form the live overlay"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fenceRunner(t)
			tc.set(r)
			err := r.checkAdjustable()
			if err == nil && r.dir != "" {
				_, err = r.startLiveBlocks(context.Background())
			}
			if !errors.Is(err, ErrLiveStart) || !strings.Contains(err.Error(), tc.why) {
				t.Fatalf("err %v, want ErrLiveStart naming %q", err, tc.why)
			}
		})
	}
	r := fenceRunner(t)
	if err := r.checkAdjustable(); err != nil {
		t.Fatalf("a run with every requirement refused: %v", err)
	}
	r.rt = &agent.RuleTable{Contract: &agent.Contract{Name: "a"}, Tier: backend.TierLandlock}
	r.dir, r.notifyFD = "", nil
	if err := r.checkAdjustable(); err != nil {
		t.Fatalf("a Locked run refused: %v", err)
	}
}

// supervisedRunner is fenceRunner made ready for startNotifyLoop with the write end of its listener stand-in, and a
// cgroup directory whose cgroup.procs names a live process.
func supervisedRunner(t *testing.T, rt *agent.RuleTable) (*runner, *group, context.Context, *sys.FD) {
	t.Helper()
	rd, wr, err := sys.Pipe2(syscall.O_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wr.Close() })
	cg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte("4242\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g, gctx := newGroup(context.Background())
	r := &runner{log: slog.New(slog.DiscardHandler), rt: rt, id: identity.RunID("r-00000000-000000000000a-aaaaaa"),
		agentID: identity.AgentID("fenced"), queue: NewQueue(64), group: g, notifyFD: rd, dir: t.TempDir(),
		cg: cgroup.Cgroup{Path: cg}}
	if rt.Adjustable() {
		rt.FS = append(rt.FS, agent.FSRule{Path: r.dir, Resolved: r.dir, Kind: agent.FSDenyRead, BuiltIn: true})
	}
	return r, g, gctx, wr
}

// TestSupervisorLoopEndEndsAdjustableRun is ADR 0125 decision 5's crash rule. A supervisor loop that returns nil after
// it started while the run's cgroup still holds a process (the listener hung up under a live run) ends an Adjustable
// run: the run's group fails with errLiveLoopEnded, which cancels the run, and awaitExit then kills its cgroup. A
// Locked run is left as it was: its kernel layers still hold the whole contract. A loop that returns an error after it
// started already ends both (the group fails with it).
func TestSupervisorLoopEndEndsAdjustableRun(t *testing.T) {
	old := loopEndSettle
	loopEndSettle = 100 * time.Millisecond
	t.Cleanup(func() { loopEndSettle = old })
	for _, tc := range []struct {
		name    string
		rt      *agent.RuleTable
		failure string // "hangup" closes the listener's peer; "error" makes its receive fail
		want    error  // nil: the run goes on
	}{
		{"adjustable, hangup", fencedTable(), "hangup", errLiveLoopEnded},
		{"locked, hangup", &agent.RuleTable{Contract: &agent.Contract{Name: "fenced"}}, "hangup", nil},
		{"adjustable, error", fencedTable(), "error", errors.New("listener")},
		{"locked, error", &agent.RuleTable{Contract: &agent.Contract{Name: "fenced"}}, "error", errors.New("listener")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, g, gctx, wr := supervisedRunner(t, tc.rt)
			if err := r.startNotifyLoop(gctx); err != nil {
				t.Fatalf("startNotifyLoop: %v", err)
			}
			if !r.sup.Started() {
				t.Fatal("the loop never started")
			}
			if tc.failure == "hangup" {
				_ = wr.Close()
			} else if err := wr.Borrow(func(fd int) error { _, err := syscall.Write(fd, []byte{1}); return err }); err != nil {
				t.Fatal(err)
			}
			select {
			case <-gctx.Done():
			case <-time.After(time.Second):
			}
			err := g.Err()
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("the run was ended: %v", err)
			case tc.want == nil && gctx.Err() != nil:
				t.Fatal("the run was cancelled")
			case tc.want != nil && (err == nil || gctx.Err() == nil):
				t.Fatalf("the run goes on (err %v)", err)
			case errors.Is(tc.want, errLiveLoopEnded) && !errors.Is(err, errLiveLoopEnded):
				t.Fatalf("err %v, want errLiveLoopEnded", err)
			}
			g.Cancel()
			_ = g.Wait()
		})
	}
}

// TestAdjustableLoopEndAfterTheRun: a loop that returns nil once the run's cgroup holds no process (the agent exited,
// so the listener hung up) does not fail an Adjustable run.
func TestAdjustableLoopEndAfterTheRun(t *testing.T) {
	r, g, gctx, wr := supervisedRunner(t, fencedTable())
	if err := os.WriteFile(filepath.Join(r.cg.Path, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.startNotifyLoop(gctx); err != nil {
		t.Fatalf("startNotifyLoop: %v", err)
	}
	_ = wr.Close()
	time.Sleep(300 * time.Millisecond)
	if err := g.Err(); err != nil || gctx.Err() != nil {
		t.Fatalf("a run whose agent exited was ended as a failure: %v", err)
	}
	g.Cancel()
	_ = g.Wait()
}

// gapWhys drains r's queue for the why of every gap line.
func gapWhys(t *testing.T, r *runner) []string {
	t.Helper()
	r.queue.Close()
	var out []string
	for ev := range r.queue.C() {
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p.Why)
	}
	return out
}

// TestFenceRefusesFromStartWhenTheOverlayIsUnreadable: an overlay that could not be read at the run's first poll
// stored no Set, and the Adjustable run started with every fence entry open. Whatever broke the
// file, the first Set refuses every entry, a poll of the same broken file keeps it, one live-block-unreadable line is
// written, and once the file is good again a lift in it loosens as usual.
func TestFenceRefusesFromStartWhenTheOverlayIsUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		root  bool // the case holds as root too
		spoil func(t *testing.T, r *runner, overlay string)
		mend  func(t *testing.T, overlay string)
	}{
		{"a directory in its place", true,
			func(t *testing.T, _ *runner, overlay string) {
				if err := os.Mkdir(overlay, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			func(t *testing.T, overlay string) {
				if err := os.Remove(overlay); err != nil {
					t.Fatal(err)
				}
			}},
		{"corrupt", true,
			func(t *testing.T, _ *runner, overlay string) {
				if err := os.WriteFile(overlay, []byte("{not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			func(t *testing.T, overlay string) {
				if err := os.Remove(overlay); err != nil {
					t.Fatal(err)
				}
			}},
		{"mode 000", false,
			func(t *testing.T, r *runner, overlay string) {
				updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
					_, _, err := o.Add(liveblock.KindExec, "/bin/ls", "uid:1 pid:2 cli", time.Now())
					return err
				})
				if err := os.Chmod(overlay, 0); err != nil {
					t.Fatal(err)
				}
			},
			func(t *testing.T, overlay string) {
				if err := os.Chmod(overlay, 0o600); err != nil {
					t.Fatal(err)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.root && os.Geteuid() == 0 {
				t.Skip("root reads a file of mode 000")
			}
			r := fenceRunner(t)
			ctx := context.Background()
			overlay := filepath.Join(r.dir, liveblock.FileName)
			tc.spoil(t, r, overlay)
			b, err := r.startLiveBlocks(ctx)
			if err != nil {
				t.Fatalf("start with an unreadable overlay: %v", err)
			}
			if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
				t.Fatalf("first Set with an unreadable overlay refuses %q, want %q", got, allRefused)
			}
			r.pollLiveBlocks(ctx, b)
			if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
				t.Fatalf("the next poll of the same broken overlay refuses %q, want %q", got, allRefused)
			}
			tc.mend(t, overlay)
			liftRead(t, r, b.fence.(*liveFence).key, "uid:1 pid:3 cli", time.Now(), time.Time{})
			r.pollLiveBlocks(ctx, b)
			want := slices.Clone(allRefused)
			want[0] = ""
			if got := refusedRules(b.Load()); !slices.Equal(got, want) {
				t.Fatalf("after the overlay was mended, a lift of the read entry leaves %q, want %q", got, want)
			}
			whys := gapWhys(t, r)
			if n := strings.Count(strings.Join(whys, " "), record.GapLiveBlockUnreadable); n != 1 {
				t.Fatalf("%d live-block-unreadable lines, want 1: %q", n, whys)
			}
		})
	}
}

// TestFenceInForceRefusesAStartWithoutTheFence: the start's own check refuses an Adjustable run whose first Set holds
// no fence refusal or not all of them, and passes a Set holding every one, and a run with no fence.
func TestFenceInForceRefusesAStartWithoutTheFence(t *testing.T) {
	r := fenceRunner(t)
	f, err := r.seedFence()
	if err != nil {
		t.Fatal(err)
	}
	b := &liveBlocks{fence: f}
	if err := fenceInForce(b); !errors.Is(err, ErrLiveStart) {
		t.Fatalf("no Set stored: %v, want ErrLiveStart", err)
	}
	refusals := f.Refusals()
	b.set.Store(liveblock.CompileEntries(refusals[1:], 0, liveblock.Resolved{}))
	if err := fenceInForce(b); !errors.Is(err, ErrLiveStart) {
		t.Fatalf("a Set one refusal short: %v, want ErrLiveStart", err)
	}
	b.set.Store(liveblock.CompileEntries(refusals, 0, liveblock.Resolved{}))
	if err := fenceInForce(b); err != nil {
		t.Fatalf("a Set with every refusal: %v", err)
	}
	if err := fenceInForce(&liveBlocks{}); err != nil {
		t.Fatalf("a run with no fence: %v", err)
	}
}

// TestFenceHostsAreLookedUpOnce: a net fence entry that names a host is looked up at the run's first store and not on
// each overlay change after it, which delayed every block by a lookup per fence host; a host the
// overlay blocks is looked up on each new state, as before. A new host block refuses by its name before its lookup
// returns, since the Set compiled with what is already known is stored first.
func TestFenceHostsAreLookedUpOnce(t *testing.T) {
	const fenceHost, blockHost = "db.example.test", "exfil.example.test"
	fenceAddr, blockAddr := netip.MustParseAddr("192.0.2.77"), netip.MustParseAddr("198.51.100.7")
	r := fenceRunner(t)
	r.rt.Live.Entries[1].Value = fenceHost + ":5432"
	var b *liveBlocks
	lookups := map[string]int{}
	refusedBefore := false
	old := liveLookup
	liveLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		lookups[host]++
		switch host {
		case fenceHost:
			return []netip.Addr{fenceAddr}, nil
		case blockHost:
			if lookups[host] == 1 {
				_, refusedBefore = b.Load().MatchInet(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), 443), blockHost, nil)
			}
			return []netip.Addr{blockAddr}, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { liveLookup = old })
	ctx := context.Background()
	var err error
	if b, err = r.startLiveBlocks(ctx); err != nil {
		t.Fatal(err)
	}
	if e, ok := b.Load().MatchInet(netip.AddrPortFrom(fenceAddr, 5432), "", nil); !ok || e.Rule() != "live.fence[net:"+fenceHost+":5432]" {
		t.Fatalf("the fence host's address is not refused at start: %+v %v", e, ok)
	}
	for _, add := range []struct {
		kind  liveblock.Kind
		value string
	}{{liveblock.KindNet, blockHost}, {liveblock.KindExec, "/bin/ls"}} {
		updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
			_, _, err := o.Add(add.kind, add.value, "uid:1 pid:2 cli", time.Now())
			return err
		})
		r.pollLiveBlocks(ctx, b)
	}
	if lookups[fenceHost] != 1 || lookups[blockHost] != 2 {
		t.Fatalf("lookups %v: want the fence host once, at start, and the blocked host on each of its 2 states", lookups)
	}
	if !refusedBefore {
		t.Fatal("the new host block was not in force while its host was looked up")
	}
	if _, ok := b.Load().MatchInet(netip.AddrPortFrom(blockAddr, 443), "", nil); !ok {
		t.Fatal("the blocked host's looked-up address is not refused")
	}
	if _, ok := b.Load().MatchInet(netip.AddrPortFrom(fenceAddr, 5432), "", nil); !ok {
		t.Fatal("the fence host's address is no longer refused after the overlay changed")
	}
}

// TestFenceRestoreKeepsTheHostsAddresses: a net fence entry's looked-up addresses outlive its lift.
// They were kept only in what the last compile resolved, which a lift pruned to the entries still refused, so the
// restore looked the host up again and, for up to liveLookupWait, refused the entry by its declared host alone. The
// restore now puts the refusal by address back in force at once, with no lookup.
func TestFenceRestoreKeepsTheHostsAddresses(t *testing.T) {
	const fenceHost = "db.example.test"
	fenceAddr := netip.MustParseAddr("192.0.2.77")
	r := fenceRunner(t)
	value := fenceHost + ":5432"
	r.rt.Live.Entries[1].Value = value
	lookups := 0
	old := liveLookup
	liveLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != fenceHost {
			return nil, errors.New("no such host")
		}
		lookups++
		return []netip.Addr{fenceAddr}, nil
	}
	t.Cleanup(func() { liveLookup = old })
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := b.fence.(*liveFence).key
	byAddr := netip.AddrPortFrom(fenceAddr, 5432)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, e := o.Lift(liveblock.KindNet, value, "uid:1 pid:3 cli", time.Now(), time.Time{}, key)
		return e
	})
	r.pollLiveBlocks(ctx, b)
	if _, ok := b.Load().MatchInet(byAddr, "", nil); ok {
		t.Fatal("the lift was not applied")
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, e := o.Restore(liveblock.KindNet, value, "uid:1 pid:3 cli", time.Now())
		return e
	})
	r.pollLiveBlocks(ctx, b)
	if e, ok := b.Load().MatchInet(byAddr, "", nil); !ok || e.Rule() != "live.fence[net:"+value+"]" {
		t.Fatalf("after the restore %v is refused %v (%+v): want the entry's refusal by address", byAddr, ok, e)
	}
	if lookups != 1 {
		t.Fatalf("the fence host was looked up %d times: want once, at start, and not again at the restore", lookups)
	}
}

// TestFenceFailedLookupIsRetriedOncePerMinute: a fence host whose lookup fails is not looked up on
// every store, each of which would hold the poll for up to liveLookupWait, but again only liveLookupRetry later on the
// run's CLOCK_BOOTTIME. Meanwhile the entry is refused by its declared host; once a retry succeeds, by address too.
func TestFenceFailedLookupIsRetriedOncePerMinute(t *testing.T) {
	const fenceHost = "db.example.test"
	fenceAddr := netip.MustParseAddr("192.0.2.77")
	r := fenceRunner(t)
	r.rt.Live.Entries[1].Value = fenceHost + ":5432"
	lookups, resolves := 0, false
	oldLookup, oldNow := liveLookup, liveNow
	liveLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != fenceHost {
			return nil, errors.New("no such host")
		}
		lookups++
		if !resolves {
			return nil, errors.New("i/o timeout")
		}
		return []netip.Addr{fenceAddr}, nil
	}
	now := liveblock.ReadClock()
	liveNow = func() liveblock.Clock { return now }
	t.Cleanup(func() { liveLookup, liveNow = oldLookup, oldNow })
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	change := func(i int) {
		t.Helper()
		updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
			_, _, e := o.Add(liveblock.KindRead, "/srv/other"+string(rune('a'+i)), "uid:1 pid:2 cli", time.Now())
			return e
		})
		r.pollLiveBlocks(ctx, b)
	}
	for i := range 3 {
		now.Boot += 10 * time.Second
		change(i)
	}
	if lookups != 1 {
		t.Fatalf("the failing fence host was looked up %d times over the start and 3 overlay changes within a minute, want once", lookups)
	}
	if _, ok := b.Load().MatchInet(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), 5432), fenceHost, nil); !ok {
		t.Fatal("the fence entry is not refused by its declared host while its lookup fails")
	}
	resolves = true
	now.Boot += liveLookupRetry
	change(3)
	if lookups != 2 {
		t.Fatalf("lookups %d: want the host tried again at the first store a minute after it failed", lookups)
	}
	if _, ok := b.Load().MatchInet(netip.AddrPortFrom(fenceAddr, 5432), "", nil); !ok {
		t.Fatal("the retried lookup's address is not refused")
	}
	change(4)
	if lookups != 2 {
		t.Fatalf("lookups %d: a host found is kept for the run", lookups)
	}
}

// TestFenceOverlayFIFOAndSymlink: an overlay that is a FIFO at the run's start neither hangs the
// start nor opens the fence; an overlay replaced by a symbolic link, even to a valid overlay holding a valid lift, is not
// followed and drops the lifts in force (fail closed).
func TestFenceOverlayFIFOAndSymlink(t *testing.T) {
	r := fenceRunner(t)
	ctx := context.Background()
	overlay := filepath.Join(r.dir, liveblock.FileName)
	if err := syscall.Mkfifo(overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var b *liveBlocks
	var err error
	go func() { b, err = r.startLiveBlocks(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the start hung on a FIFO overlay")
	}
	if err != nil {
		t.Fatal(err)
	}
	if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
		t.Fatalf("FIFO overlay: the Set refuses %q, want %q", got, allRefused)
	}
	if err := os.Remove(overlay); err != nil {
		t.Fatal(err)
	}
	key := b.fence.(*liveFence).key
	other := t.TempDir()
	if _, err := liveblock.Update(ctx, other, string(r.id), func(o *liveblock.Overlay) (bool, error) {
		_, e := o.Lift(liveblock.KindRead, fenceRead, "uid:1 pid:3 cli", time.Now(), time.Time{}, key)
		return true, e
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, liveblock.FileName), overlay); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
		t.Fatalf("a symlinked overlay was followed: the Set refuses %q", got)
	}
	if err := os.Remove(overlay); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	liftRead(t, r, key, "uid:1 pid:4 cli", time.Now(), time.Time{})
	r.pollLiveBlocks(ctx, b)
	if got := refusedRules(b.Load()); got[0] != "" {
		t.Fatalf("the lift was not applied: %q", got)
	}
	if err := os.Rename(overlay, overlay+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(overlay+".bak", overlay); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if got := refusedRules(b.Load()); !slices.Equal(got, allRefused) {
		t.Fatalf("a lift survived the overlay becoming a symlink: %q", got)
	}
}
