// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// die leaves w as a launcher killed at this instant leaves its run: the kernel drops the lock and every
// descriptor, and nothing else happens.
func die(w *Writer) {
	w.release()
	w.closeDirs()
}

// openLive opens a run under root at the given start time, as the launcher's openLedger does before it
// lists the run.
func openLive(t *testing.T, root string, at time.Time, rand6 string) (*Writer, record.RunRef) {
	t.Helper()
	ref := record.RunRef{ID: runID(at, rand6), Agent: "retriever"}
	w, err := Open(filepath.Join(root, ref.ID), ref, WithAnchor(&memAnchor{}),
		WithClock(newStepClock(at, 1_000_000_000, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	return w, ref
}

// listed reports whether the live index of root names id.
func listed(t *testing.T, root, id string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(root, LiveDir, id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// sealedRun is a run whose launcher ended it and cleared its entry, as every run that exited normally is.
func sealedRun(t *testing.T, root string, at time.Time, rand6 string) record.RunRef {
	t.Helper()
	w, ref := openLive(t, root, at, rand6)
	if err := MarkLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := ClearLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestMarkLiveListsTheRun(t *testing.T) {
	root := t.TempDir()
	id := runID(fixedStart, "k7m2pq")
	if err := MarkLive(root, id); err != nil {
		t.Fatalf("MarkLive: %v", err)
	}
	st, err := os.Lstat(filepath.Join(root, LiveDir))
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("index directory: %v %v", st, err)
	}
	st, err = os.Lstat(filepath.Join(root, LiveDir, id))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 || st.Size() != 0 {
		t.Fatalf("entry: %v %v", st, err)
	}
	if err := MarkLive(root, id); err != nil {
		t.Fatalf("an entry that already exists lists the run: %v", err)
	}
	for _, bad := range []string{"", "..", "../" + id, id + "/x", "not-a-run"} {
		if err := MarkLive(root, bad); !errors.Is(err, ErrBadRunRef) {
			t.Errorf("MarkLive(%q): %v, want ErrBadRunRef", bad, err)
		}
		if err := ClearLive(root, bad); !errors.Is(err, ErrBadRunRef) {
			t.Errorf("ClearLive(%q): %v, want ErrBadRunRef", bad, err)
		}
	}
}

// TestClearLiveOnlyOnceTheRunIsOver: the launcher clears its entry after Close, and only a run whose ledger
// ends in run_end, or whose directory is gone, loses it; a Close that could not append run_end leaves a
// lost run, which keeps its entry for the next sweep.
func TestClearLiveOnlyOnceTheRunIsOver(t *testing.T) {
	root := t.TempDir()
	ended := sealedRun(t, root, fixedStart, "a00001")
	if listed(t, root, ended.ID) {
		t.Error("an ended run kept its entry")
	}

	w, lost := openLive(t, root, fixedStart, "a00002")
	if err := MarkLive(root, lost.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	w.torn = errors.New("disk full") // the run_end append cannot be made
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); !errors.Is(err, ErrTorn) {
		t.Fatalf("Close: %v, want ErrTorn", err)
	}
	if err := ClearLive(root, lost.ID); err != nil {
		t.Fatal(err)
	}
	if !listed(t, root, lost.ID) {
		t.Error("a run whose Close wrote no run_end lost its entry: no sweep but gc's would end it")
	}

	running, ref := openLive(t, root, fixedStart, "a00003")
	defer running.Close(record.RunEndPayload{Reason: record.RunEndExit}) //nolint:errcheck // the test's own run
	if err := MarkLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, running, 1)
	if err := ClearLive(root, ref.ID); err != nil || !listed(t, root, ref.ID) {
		t.Errorf("a running run: err %v, listed %v; want its entry kept", err, listed(t, root, ref.ID))
	}

	gone := runID(fixedStart, "a00004")
	if err := MarkLive(root, gone); err != nil {
		t.Fatal(err)
	}
	if err := ClearLive(root, gone); err != nil || listed(t, root, gone) {
		t.Errorf("a run whose directory is gone: err %v, listed %v", err, listed(t, root, gone))
	}
	if err := ClearLive(t.TempDir(), gone); err != nil {
		t.Errorf("a root with no index: %v", err)
	}
}

// TestSweepLiveAtEveryKillPoint is the index's completeness: a launcher killed at any point of its run
// leaves a run the sweep of `run` and `stop` ends, or one that has nothing to end and gc's full pass
// removes at retention. The points are the launcher's order: run directory (MakeRunDir), lock (Open),
// entry (MarkLive), run_start, the run's lines, run_end, lock release (Close), entry cleared (ClearLive).
func TestSweepLiveAtEveryKillPoint(t *testing.T) {
	type outcome struct {
		swept  bool          // the sweep ended it with run_end{orphaned}
		kept   bool          // its entry is still there after the sweep
		last   record.Kind   // the ledger's last line after the sweep, "" for none
		reason string        // run_end's reason, when last is run_end
		gcKeep time.Duration // a gc pass with this retention removes it (0: not asked)
	}
	cases := []struct {
		name string
		kill func(t *testing.T, root string) string
		want outcome
	}{
		{
			name: "after the run directory, before the lock",
			kill: func(t *testing.T, root string) string {
				id := runID(fixedStart, "kill01")
				if err := MakeRunDir(root, id); err != nil {
					t.Fatal(err)
				}
				return id
			},
			want: outcome{gcKeep: time.Hour},
		},
		{
			name: "after the lock, before the entry",
			kill: func(t *testing.T, root string) string {
				w, ref := openLive(t, root, fixedStart, "kill02")
				die(w)
				return ref.ID
			},
			want: outcome{gcKeep: time.Hour},
		},
		{
			name: "after the entry, before run_start",
			kill: func(t *testing.T, root string) string {
				w, ref := openLive(t, root, fixedStart, "kill03")
				if err := MarkLive(root, ref.ID); err != nil {
					t.Fatal(err)
				}
				die(w)
				return ref.ID
			},
			want: outcome{gcKeep: time.Hour},
		},
		{
			name: "after run_start",
			kill: func(t *testing.T, root string) string {
				w, ref := openLive(t, root, fixedStart, "kill04")
				if err := MarkLive(root, ref.ID); err != nil {
					t.Fatal(err)
				}
				startRun(t, w, 0)
				die(w)
				return ref.ID
			},
			want: outcome{swept: true, last: record.KindRunEnd, reason: record.RunEndOrphaned},
		},
		{
			name: "in the middle of a line",
			kill: func(t *testing.T, root string) string {
				w, ref := openLive(t, root, fixedStart, "kill05")
				if err := MarkLive(root, ref.ID); err != nil {
					t.Fatal(err)
				}
				startRun(t, w, 3)
				tearTail(t, w)
				die(w)
				return ref.ID
			},
			want: outcome{swept: true, last: record.KindRunEnd, reason: record.RunEndOrphaned},
		},
		{
			// Close appends run_end before it releases the lock, and the launcher clears the entry after
			// Close: a launcher killed between run_end and the lock release, and one killed between the
			// release and the clear, leave the same ended run with its entry still there.
			name: "after run_end, before the entry is cleared",
			kill: func(t *testing.T, root string) string {
				w, ref := openLive(t, root, fixedStart, "kill06")
				if err := MarkLive(root, ref.ID); err != nil {
					t.Fatal(err)
				}
				startRun(t, w, 1)
				if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
					t.Fatal(err)
				}
				return ref.ID
			},
			want: outcome{last: record.KindRunEnd, reason: record.RunEndExit},
		},
		{
			name: "after a Close that could not write run_end",
			kill: func(t *testing.T, root string) string {
				w, ref := openLive(t, root, fixedStart, "kill07")
				if err := MarkLive(root, ref.ID); err != nil {
					t.Fatal(err)
				}
				startRun(t, w, 1)
				w.torn = errors.New("disk full")
				_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
				if err := ClearLive(root, ref.ID); err != nil {
					t.Fatal(err)
				}
				return ref.ID
			},
			want: outcome{swept: true, last: record.KindRunEnd, reason: record.RunEndOrphaned},
		},
		{
			name: "after the entry is cleared",
			kill: func(t *testing.T, root string) string {
				return sealedRun(t, root, fixedStart, "kill08").ID
			},
			want: outcome{last: record.KindRunEnd, reason: record.RunEndExit},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sealed := sealedRun(t, root, fixedStart, "seal01") // the index exists, as after any run
			id := tc.kill(t, root)
			var hooked []string
			hook := func(_ context.Context, _ sys.Lender, run record.RunRef) error {
				hooked = append(hooked, run.ID)
				return nil
			}
			rep, err := SweepLive(context.Background(), root, WithSweepHook(hook), WithWriterOptions(WithAnchor(&memAnchor{})))
			if err != nil || len(rep.Errors) != 0 {
				t.Fatalf("SweepLive: %v %v", err, rep.Errors)
			}
			if got := slices.Contains(rep.Swept, id); got != tc.want.swept {
				t.Errorf("swept %v (report %+v), want %v", got, rep, tc.want.swept)
			}
			if got := slices.Contains(hooked, id); got != tc.want.swept {
				t.Errorf("the hook ran for it: %v, want %v", got, tc.want.swept)
			}
			if got := listed(t, root, id); got != tc.want.kept {
				t.Errorf("listed after the sweep: %v, want %v", got, tc.want.kept)
			}
			if slices.Contains(hooked, sealed.ID) || slices.Contains(rep.Swept, sealed.ID) {
				t.Errorf("the sweep reached the sealed run %s", sealed.ID)
			}
			last, reason := lastOf(t, filepath.Join(root, id))
			if last != tc.want.last || reason != tc.want.reason {
				t.Errorf("last line %q %q, want %q %q", last, reason, tc.want.last, tc.want.reason)
			}
			// Swept again at once: nothing left to do.
			if rep, err := SweepLive(context.Background(), root, WithSweepHook(hook)); err != nil || len(rep.Swept) != 0 {
				t.Errorf("a second sweep: %+v %v", rep, err)
			}
			if tc.want.gcKeep == 0 {
				return
			}
			later := func() time.Time { return fixedStart.Add(2 * tc.want.gcKeep) }
			gc, err := GC(context.Background(), root, tc.want.gcKeep, false, WithNow(later), WithSweepHook(hook))
			if err != nil || !slices.Contains(gc.Deleted, id) {
				t.Errorf("gc's full pass: %+v %v, want %s deleted", gc, err, id)
			}
		})
	}
}

// TestSweepLiveEndsAKilledWriter is the kill points' real-process case: a writer that listed its run and
// was killed with SIGKILL mid-line leaves a free lock, a torn tail and its entry, and the index sweep alone
// ends the run and clears the entry.
func TestSweepLiveEndsAKilledWriter(t *testing.T) {
	root := t.TempDir()
	sealedRun(t, root, fixedStart, "seal01")
	dir := filepath.Join(root, testRef.ID)
	cmd := helper(t, "crash", dir, "TEGO_LEDGER_N=2", "TEGO_LEDGER_LIVE=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("helper should die by SIGKILL: %v %s", err, out)
	}
	if !listed(t, root, testRef.ID) {
		t.Fatal("the killed writer's run is not listed")
	}
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil || len(rep.Errors) != 0 || !slices.Equal(rep.Swept, []string{testRef.ID}) {
		t.Fatalf("SweepLive: %+v %v", rep, err)
	}
	if last, reason := lastOf(t, dir); last != record.KindRunEnd || reason != record.RunEndOrphaned {
		t.Errorf("last line %s %s, want run_end orphaned", last, reason)
	}
	if listed(t, root, testRef.ID) {
		t.Error("the swept run is still listed")
	}
}

// lastOf is the kind of a run's last line, and run_end's reason when it is one; "" when there is none.
func lastOf(t *testing.T, dir string) (record.Kind, string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, EventsFile)); errors.Is(err, os.ErrNotExist) {
		return "", ""
	}
	evs := readAll(t, dir)
	if len(evs) == 0 {
		return "", ""
	}
	last := evs[len(evs)-1]
	if last.Kind != record.KindRunEnd {
		return last.Kind, ""
	}
	var p record.RunEndPayload
	if err := last.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return last.Kind, p.Reason
}

// TestSweepLiveLeavesUnlistedRunsAlone is what makes the sweep cheap: a run the index does not name is
// never read. Every sealed run here is unreadable, so a sweep that probed one would report it.
func TestSweepLiveLeavesUnlistedRunsAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 file")
	}
	root := t.TempDir()
	for i := range 20 {
		ref := sealedRun(t, root, fixedStart.Add(time.Duration(i)*time.Second), fmt.Sprintf("s%05d", i))
		if err := os.Chmod(filepath.Join(root, ref.ID, EventsFile), 0); err != nil {
			t.Fatal(err)
		}
	}
	w, lost := openLive(t, root, fixedStart, "lost01")
	if err := MarkLive(root, lost.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	die(w)
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil || len(rep.Errors) != 0 {
		t.Fatalf("SweepLive: %v %v", err, rep.Errors)
	}
	if !slices.Equal(rep.Swept, []string{lost.ID}) {
		t.Errorf("swept %v, want only the listed orphan", rep.Swept)
	}
	// gc's pass still reads every one.
	gc, err := GC(context.Background(), root, keepAll, false)
	n := 0
	for id := range gc.Errors {
		if IsRunID(id) {
			n++
		}
	}
	if err != nil || n != 20 {
		t.Errorf("gc met %d unreadable runs (%v), want all 20", n, err)
	}
}

// TestSweepLiveWithoutAnIndex: a ledger root no launcher has indexed — written by a tego that kept no
// index, or whose index was deleted — gets GC's full pass, so an orphan from before the index is ended.
func TestSweepLiveWithoutAnIndex(t *testing.T) {
	root := t.TempDir()
	lost := makeRun(t, root, fixedStart, "old001", StateLost)
	ended := makeRun(t, root, fixedStart, "old002", StateEnded)
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rep.Swept, []string{lost.ID}) || len(rep.Deleted) != 0 {
		t.Fatalf("report %+v, want %s swept and nothing deleted", rep, lost.ID)
	}
	if s := stateOf(t, filepath.Join(root, ended.ID)); s != StateEnded {
		t.Errorf("the ended run is %s", s)
	}
	if _, err := os.Stat(filepath.Join(root, LiveDir)); !errors.Is(err, os.ErrNotExist) {
		t.Error("the sweep made an index; only a launcher's MarkLive does")
	}
}

// TestSweepLiveKeepsWhatItCannotFinish: a run still running, one whose hook failed (its tree may be alive)
// and one another sweeper holds keep their entries, so the next sweep meets them again.
func TestSweepLiveKeepsWhatItCannotFinish(t *testing.T) {
	root := t.TempDir()
	running, run := openLive(t, root, fixedStart, "run001")
	defer running.Close(record.RunEndPayload{Reason: record.RunEndExit}) //nolint:errcheck // the test's own run
	if err := MarkLive(root, run.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, running, 1)

	w, hookFails := openLive(t, root, fixedStart, "hook01")
	if err := MarkLive(root, hookFails.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	die(w)

	hook := func(_ context.Context, _ sys.Lender, ref record.RunRef) error {
		if ref.ID == hookFails.ID {
			return errors.New("cgroup busy")
		}
		return nil
	}
	rep, err := SweepLive(context.Background(), root, WithSweepHook(hook), WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rep.Kept, run.ID) || !listed(t, root, run.ID) {
		t.Errorf("the running run: report %+v, listed %v", rep, listed(t, root, run.ID))
	}
	if rep.Errors[hookFails.ID] == nil || !listed(t, root, hookFails.ID) || stateOf(t, filepath.Join(root, hookFails.ID)) != StateLost {
		t.Errorf("a failed hook: report %+v, listed %v; want it reported, kept and not ended", rep, listed(t, root, hookFails.ID))
	}

	// Another sweeper holds the lost run's lock while it ends it: this sweep cannot, and keeps the entry
	// until the ledger says the run is over. It does not kill the run's tree either: the lock comes before the
	// hook, so only the sweeper that holds it kills (runtime-launch.md §6 case 10).
	w, busy := openLive(t, root, fixedStart, "busy01")
	if err := MarkLive(root, busy.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	die(w)
	other := &fsRunRepository{root: root, opts: []Option{WithAnchor(&memAnchor{})}}
	held, err := other.Lock(context.Background(), busy.ID, record.RunRef{ID: busy.ID, Agent: busy.Agent})
	if err != nil {
		t.Fatal(err)
	}
	hooked := false
	hook = func(_ context.Context, _ sys.Lender, ref record.RunRef) error {
		if ref.ID == busy.ID {
			hooked = true
		}
		return nil
	}
	rep, err = SweepLive(context.Background(), root, WithSweepHook(hook), WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil {
		t.Fatal(err)
	}
	if hooked {
		t.Error("the hook ran for a run another sweeper holds: two sweepers killed one tree")
	}
	if slices.Contains(rep.Swept, busy.ID) || !listed(t, root, busy.ID) {
		t.Errorf("a run another sweeper holds: report %+v, listed %v; want it kept", rep, listed(t, root, busy.ID))
	}
	if err := held.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{}))); err != nil || listed(t, root, busy.ID) {
		t.Errorf("once the other sweeper ended it: %v, listed %v", err, listed(t, root, busy.ID))
	}
}

// TestSweepLiveAgainstPlantedEntries: what someone who can write the index can plant costs the sweep one
// probe per entry and can aim it at nothing outside the ledger root. Names that are no run id are passed
// over and left; an entry is never opened, so a FIFO or a link planted as one neither blocks nor
// redirects; a run id whose path in the root is a link is no run, even to a real lost run elsewhere; and a
// run id naming nothing is cleared.
func TestSweepLiveAgainstPlantedEntries(t *testing.T) {
	root := t.TempDir()
	sealedRun(t, root, fixedStart, "seal01")
	live := filepath.Join(root, LiveDir)
	outside := t.TempDir()
	w, far := openLive(t, outside, fixedStart, "far001") // a lost run outside the ledger root
	startRun(t, w, 1)
	die(w)
	farLines := len(readAll(t, filepath.Join(outside, far.ID)))
	if err := os.Symlink(filepath.Join(outside, far.ID), filepath.Join(root, far.ID)); err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, far.ID); err != nil {
		t.Fatal(err)
	}

	w, fifo := openLive(t, root, fixedStart, "fifo01") // a real lost run, listed by a FIFO
	startRun(t, w, 1)
	die(w)
	if err := syscall.Mkfifo(filepath.Join(live, fifo.ID), 0o600); err != nil {
		t.Fatal(err)
	}
	w, link := openLive(t, root, fixedStart, "link01") // a real lost run, listed by a link to a file outside
	startRun(t, w, 1)
	die(w)
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(live, link.ID)); err != nil {
		t.Fatal(err)
	}
	junk := []string{"not-a-run", "..x", "r-zzzzzzzz-0000000000000-aaaaaa"}
	for _, name := range junk {
		if err := os.WriteFile(filepath.Join(live, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(live, "d-not-a-run"), 0o700); err != nil {
		t.Fatal(err)
	}
	dirEntry := runID(fixedStart, "dir001") // an empty directory planted as an entry, naming no run
	if err := os.Mkdir(filepath.Join(live, dirEntry), 0o700); err != nil {
		t.Fatal(err)
	}
	nothing := []string{dirEntry}
	for i := range 200 {
		id := runID(fixedStart.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("n%05d", i))
		nothing = append(nothing, id)
		if err := MarkLive(root, id); err != nil {
			t.Fatal(err)
		}
	}

	done := make(chan struct{})
	var rep Report
	var err error
	go func() {
		defer close(done)
		rep, err = SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the sweep blocked on a planted entry")
	}
	if err != nil || len(rep.Errors) != 0 {
		t.Fatalf("SweepLive: %v %v", err, rep.Errors)
	}
	slices.Sort(rep.Swept)
	want := []string{fifo.ID, link.ID}
	slices.Sort(want)
	if !slices.Equal(rep.Swept, want) {
		t.Errorf("swept %v, want the two real lost runs %v", rep.Swept, want)
	}
	if n := len(readAll(t, filepath.Join(outside, far.ID))); n != farLines || stateOf(t, filepath.Join(outside, far.ID)) != StateLost {
		t.Errorf("the run outside the ledger root was written: %d lines, was %d", n, farLines)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep\n" {
		t.Errorf("the file a planted entry links to was written: %q", b)
	}
	for _, id := range append(nothing, far.ID, fifo.ID, link.ID) {
		if listed(t, root, id) {
			t.Errorf("%s is still listed", id)
		}
	}
	for _, name := range append(junk, "d-not-a-run") {
		if _, err := os.Lstat(filepath.Join(live, name)); err != nil {
			t.Errorf("the sweep touched %s, which is no entry of its: %v", name, err)
		}
	}
}

// TestSweepLiveDoesNotFollowALinkedIndex: an index replaced by a link is not read through, whoever runs the
// sweep: the pass falls back to GC's over every run and says why, and the entries the link points at are
// left as they are.
func TestSweepLiveDoesNotFollowALinkedIndex(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	id := runID(fixedStart, "else01")
	if err := os.WriteFile(filepath.Join(elsewhere, id), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, LiveDir)); err != nil {
		t.Fatal(err)
	}
	lost := makeRun(t, root, fixedStart, "lost01", StateLost)
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(rep.Errors[LiveDir], ErrLinkRefused) {
		t.Errorf("index error %v, want ErrLinkRefused", rep.Errors[LiveDir])
	}
	if !slices.Equal(rep.Swept, []string{lost.ID}) {
		t.Errorf("swept %v, want the full pass to end %s", rep.Swept, lost.ID)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, id)); err != nil {
		t.Errorf("an entry behind the link was removed: %v", err)
	}
}

// TestMarkLiveAsRootRefusesALinkedIndex: as root, the walk to the index refuses a link the ledger root's
// owner left in place of it, so root creates nothing wherever the link points (the hand-over rule's walk,
// taken here through actingAsRoot; the integration suite repeats it as root).
func TestMarkLiveAsRootRefusesALinkedIndex(t *testing.T) {
	prev := actingAsRoot
	actingAsRoot = func() bool { return true }
	defer func() { actingAsRoot = prev }()
	root := t.TempDir()
	if err := os.Chmod(root, 0o770); err != nil { // not root's alone, as a user's ledger root is not
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, LiveDir)); err != nil {
		t.Fatal(err)
	}
	id := runID(fixedStart, "root01")
	if err := MarkLive(root, id); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("MarkLive through a linked index: %v, want ErrLinkRefused", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("root created %v behind the link", entries)
	}
}
