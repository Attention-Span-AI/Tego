// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const reapTestRun = "r-00000000-000000000000a-reaper"

// reapTestSpec is a reaper's spec for reapTestRun in root, its scope under mount, with no build.
func reapTestSpec(t *testing.T, root, mount string) reapSpec {
	t.Helper()
	return reapSpec{ID: reapTestRun, Agent: "tester", Dir: filepath.Join(root, reapTestRun), CgroupMount: mount,
		CgroupPath: filepath.Join(mount, identity.TopSlice, identity.AgentSlice("tester"),
			identity.RunScope(identity.RunID(reapTestRun))),
		CgroupID: 7, Target: cgroupenforce.ReapTarget{Linger: time.Minute},
		Anchor: filepath.Join(t.TempDir(), "chain.log")}
}

// openPathDir opens dir O_PATH, as the launcher hands the reaper its run directory.
func openPathDir(t *testing.T, dir string) *sys.FD {
	t.Helper()
	fd, err := sys.Own(unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fd.Close() })
	return fd
}

// TestTheReapersArgvRoundTrips: everything the reaper is told is its argv, written by the launcher before the
// child stage exists, and a field that does not parse makes it do nothing rather than guess.
func TestTheReapersArgvRoundTrips(t *testing.T) {
	spec := reapTestSpec(t, "/l", "/sys/fs/cgroup")
	spec.Target = cgroupenforce.ReapTarget{Hash: "abc", BPFFS: "/sys/fs/bpf", StateDir: "", Linger: 5 * time.Minute,
		Slot: 17, PlaneMode: record.DecisionPlaneFmodRet}
	args := spec.args()
	if len(args) != reapArgCount {
		t.Fatalf("%d arguments, want %d", len(args), reapArgCount)
	}
	got, err := parseReapSpec(args)
	if err != nil {
		t.Fatalf("parseReapSpec: %v", err)
	}
	if got != spec {
		t.Fatalf("round trip: %+v, want %+v", got, spec)
	}
	for i, bad := range map[int]string{0: "not-a-run", 1: "Bad Agent", 4: "/sys/fs/cgroup/other.scope", 5: "x",
		6: "../x", 9: "soon", 11: "-1", 12: "fanotify"} {
		mangled := slices.Clone(args)
		mangled[i] = bad
		if _, err := parseReapSpec(mangled); err == nil {
			t.Errorf("argument %d = %q parsed", i, bad)
		}
	}
	if _, err := parseReapSpec(args[1:]); err == nil {
		t.Error("a short argv parsed")
	}
}

// TestTheReaperLeavesARunItsLauncherEnded is ADR 0020 (3)'s first step: a run whose ledger has run_end and whose
// scope is gone was torn down by its launcher, and the reaper writes nothing and purges nothing.
func TestTheReaperLeavesARunItsLauncherEnded(t *testing.T) {
	root, mount := t.TempDir(), t.TempDir()
	w := openRun(t, root, reapTestRun)
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "cgroup", BPFHash: "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, reapTestRun)
	before := readFile(t, filepath.Join(dir, ledger.EventsFile))
	spec := reapTestSpec(t, root, mount)
	spec.Target.Hash = "abc"
	purged, err := sweepRun(context.Background(), spec, openPathDir(t, dir), slog.New(slog.DiscardHandler))
	if err != nil || purged {
		t.Fatalf("sweepRun of an ended run: purged %v, %v; want nothing done", purged, err)
	}
	if after := readFile(t, filepath.Join(dir, ledger.EventsFile)); !bytes.Equal(before, after) {
		t.Fatalf("the ended run's ledger changed:\n%s", after)
	}
}

// TestTheReaperMakesNothingInARunDirectoryBeingRemoved: the reaper wakes as its launcher exits, and an ended run's
// directory can be going by then. Its Open made a lock, an empty events.jsonl and blobs/ again behind the RemoveAll,
// which then failed with "directory not empty" (TestRootAskUnix's t.TempDir, once).
func TestTheReaperMakesNothingInARunDirectoryBeingRemoved(t *testing.T) {
	root, mount := t.TempDir(), t.TempDir()
	w := openRun(t, root, reapTestRun)
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "cgroup"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, reapTestRun)
	fd := openPathDir(t, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	purged, err := sweepRun(context.Background(), reapTestSpec(t, root, mount), fd, slog.New(slog.DiscardHandler))
	if err != nil || purged {
		t.Fatalf("sweepRun of a run being removed: purged %v, %v; want nothing done", purged, err)
	}
	if left, err := os.ReadDir(dir); err != nil || len(left) != 0 {
		t.Fatalf("the reaper made %v in a directory being removed (%v)", left, err)
	}
}

// TestTheReaperWritesThroughItsDescriptorNeverThePath is ADR 0020 (3)'s descriptor discipline: the reaper ends the
// run in the directory its launcher handed it, and a runs/<id> swapped for a symlink after the start is never
// followed. The symlink's target, which a same-uid process chose, gets nothing.
func TestTheReaperWritesThroughItsDescriptorNeverThePath(t *testing.T) {
	root, mount := t.TempDir(), t.TempDir()
	startedRun(t, root, reapTestRun)
	dir := filepath.Join(root, reapTestRun)
	fd := openPathDir(t, dir)

	moved := filepath.Join(root, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	purged, err := sweepRun(context.Background(), reapTestSpec(t, root, mount), fd, slog.New(slog.DiscardHandler))
	if err != nil || !purged {
		t.Fatalf("sweepRun: purged %v, %v", purged, err)
	}
	if got := lastReason(t, moved); got != record.RunEndOrphaned {
		t.Fatalf("the run's own directory ends with %q, want orphaned", got)
	}
	evs := events(t, moved)
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil || end.ExitCode != identity.ExitLauncher {
		t.Fatalf("orphan end %+v (%v), want launcher failure %d", end, err, identity.ExitLauncher)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("the symlink's target holds %v (%v); the reaper followed runs/<id>", entries, err)
	}
}

// TestTheReaperLeavesARunThatNeverStarted: a launcher that died before run_start leaves an empty ledger, which the
// reaper, like a sweep, leaves for retention rather than ending with a run_end as its first line.
func TestTheReaperLeavesARunThatNeverStarted(t *testing.T) {
	root, mount := t.TempDir(), t.TempDir()
	w := openRun(t, root, reapTestRun)
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, reapTestRun)
	if _, err := sweepRun(context.Background(), reapTestSpec(t, root, mount), openPathDir(t, dir),
		slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("sweepRun: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ledger.EventsFile)); len(b) != 0 {
		t.Fatalf("a run that never started got a ledger:\n%s", b)
	}
}

// TestTheReaperNeverTouchesAnotherRunsScope: a scope at the run's path whose cgroup id is not the run's was made
// since, for another run, and the reaper neither kills nor removes it.
func TestTheReaperNeverTouchesAnotherRunsScope(t *testing.T) {
	root, mount := t.TempDir(), t.TempDir()
	startedRun(t, root, reapTestRun)
	spec := reapTestSpec(t, root, mount)
	if err := os.MkdirAll(spec.CgroupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.CgroupPath, "cgroup.events"), []byte("populated 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := cgroup.NewAt(mount)
	if err != nil {
		t.Fatal(err)
	}
	if runScopePresent(fs, cgroup.Cgroup{Path: spec.CgroupPath}, spec.CgroupID) {
		t.Fatal("a scope with another cgroup id reads as the run's")
	}
	if _, err := sweepRun(context.Background(), spec, openPathDir(t, spec.Dir), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("sweepRun: %v", err)
	}
	if _, err := os.Stat(filepath.Join(spec.CgroupPath, "cgroup.kill")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cgroup.kill was written into another run's scope (%v)", err)
	}
	if _, err := os.Stat(spec.CgroupPath); err != nil {
		t.Errorf("another run's scope was removed: %v", err)
	}
}

// TestAReaperOwesTheBuildItsDutiesAfterAPartialPurge is ADR 0022 (3): once the run's scope is gone, a purge that
// met an unrelated failure (a ring it could not trim, a slot it could not release) still counts as purged, so the
// reaper stamps the build's idle start and starts its timer; skipping them left the build with a stale mtime, which
// the next Prepare took for long idle and removed at once. Only a cgroup still listed (ErrRunAlive) keeps them.
func TestAReaperOwesTheBuildItsDutiesAfterAPartialPurge(t *testing.T) {
	prev := purgeRun
	t.Cleanup(func() { purgeRun = prev })
	for _, tc := range []struct {
		name   string
		err    error
		purged bool
	}{
		{"a ring left untrimmed", errors.New("cgroup: trim the rings: busy"), true},
		{"the run's cgroup still listed", fmt.Errorf("%w: cgroup 7", cgroupenforce.ErrRunAlive), false},
		{"a clean purge", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			purgeRun = func(cgroupenforce.PurgeOptions) (cgroupenforce.PurgeResult, error) {
				return cgroupenforce.PurgeResult{}, tc.err
			}
			root, mount := t.TempDir(), t.TempDir()
			startedRun(t, root, reapTestRun)
			spec := reapTestSpec(t, root, mount)
			spec.Target.Hash = "abc"
			purged, err := sweepRun(context.Background(), spec, openPathDir(t, spec.Dir), slog.New(slog.DiscardHandler))
			if purged != tc.purged {
				t.Fatalf("sweepRun: purged %v (%v), want %v", purged, err, tc.purged)
			}
			if (err != nil) != (tc.err != nil) {
				t.Fatalf("sweepRun: %v, want the purge's error %v reported", err, tc.err)
			}
		})
	}
}

// TestTheReaperInheritsExactlyTwoDescriptors is ADR 0020 (2)'s descriptor set as amended: the reaper's exec
// passes the launcher's pidfd at 3 and the run directory at 4, and nothing else beyond its standard streams, and
// it runs in a session of its own. The reaper's command is run with this test binary in its place, running
// ReapMain itself (reapMainHelper), with two stray descriptors right above the run directory (5 and 6, as a parent
// that passed more than it meant would leave them) and one this process holds without CLOEXEC: ReapMain's start-up
// sweep closes all three, and at its hold, its launcher gone and the pidfd closed, it holds the run directory
// alone.
func TestTheReaperInheritsExactlyTwoDescriptors(t *testing.T) {
	root := t.TempDir()
	w := openRun(t, root, reapTestRun)
	defer func() { _ = w.Abandon() }()
	dir, err := w.OpenDirPath()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	pidfd := deadLauncherPidfd(t)
	// A descriptor this process holds without CLOEXEC must not reach the reaper either.
	leak, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(leak) }()
	stray, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stray.Close() }()

	cmd := reaperCommand(os.Args[0], reapTestSpec(t, root, "/sys/fs/cgroup"), pidfd, dir, nil, nil)
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("the reaper's standard streams are not /dev/null")
	}
	if len(cmd.ExtraFiles) != 2 || cmd.ExtraFiles[0] != pidfd || cmd.ExtraFiles[1] != dir || cmd.SysProcAttr == nil ||
		!cmd.SysProcAttr.Setsid {
		t.Fatalf("extra files %d, sysprocattr %+v: want the pidfd and the run directory and a session of its own",
			len(cmd.ExtraFiles), cmd.SysProcAttr)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, stray, stray)
	r := runReapMain(t, cmd, "run")
	if r.code != 0 || !r.hold {
		t.Fatalf("reaper exit %d, hold %t, stderr %q: want its hold", r.code, r.hold, r.stderr)
	}
	if got := r.numbers(); !slices.Equal(got, []int{0, 1, 2, reapDirFD}) {
		t.Fatalf("the reaper holds descriptors %v (%v), want 0-2 and the run directory at %d", got, r.fds, reapDirFD)
	}
	if r.fds[reapDirFD] != filepath.Join(root, reapTestRun) {
		t.Errorf("descriptor %d is %q, want the run directory", reapDirFD, r.fds[reapDirFD])
	}
	own, _ := unix.Getsid(0)
	if r.sid == "" || r.sid == strconv.Itoa(own) {
		t.Errorf("the reaper's session %q is the launcher's", r.sid)
	}
}

// TestWatchCgroupRecordsTheGiveUp is ADR 0020 (5): a watcher that cannot read the run cgroup's event counters no
// longer ends with a line in tego's own log alone; the run's record says its oom and pids reasons went unseen.
func TestWatchCgroupRecordsTheGiveUp(t *testing.T) {
	dir := t.TempDir()
	// A directory where pids.events should be: every read of it fails.
	if err := os.Mkdir(filepath.Join(dir, "pids.events"), 0o700); err != nil {
		t.Fatal(err)
	}
	q := NewQueue(8)
	r := &runner{log: slog.New(slog.DiscardHandler), queue: q, cgm: &fakeCgroups{root: dir},
		cg: cgroup.Cgroup{Path: dir}}
	if err := r.watchCgroup(t.Context()); err != nil {
		t.Fatalf("watchCgroup: %v", err)
	}
	select {
	case ev := <-q.C():
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Kind != record.KindGap || p.What != record.GapRecord || p.Why != GapCgroupEventsUnavailable {
			t.Fatalf("event %s %+v, want gap what=record why=%s", ev.Kind, p, GapCgroupEventsUnavailable)
		}
	default:
		t.Fatal("no gap recorded")
	}
}

// TestTheReaperRecordsThePlaneCounters is enforce-plane §2.8's counters half for an orphaned run: the reaper, once
// the run's tree is killed and before its run_end, reads the slot its launcher held in the mode it decided in and
// writes one gap what=enforce line per non-zero counter, naming the mode; a slot it cannot read is one
// plane-counters-unread line; a run with no plane mode reads nothing.
func TestTheReaperRecordsThePlaneCounters(t *testing.T) {
	target := cgroupenforce.ReapTarget{Hash: "abc", BPFFS: "/sys/fs/bpf", Slot: 9, PlaneMode: record.DecisionPlaneLSM}
	var asked cgroupenforce.ReapTarget
	read := func(tg cgroupenforce.ReapTarget) ([]cgroupenforce.PlaneCount, error) {
		asked = tg
		return []cgroupenforce.PlaneCount{{Why: record.GapPlaneBound, Count: 2}, {Why: record.GapPlaneNoRows},
			{Why: record.GapPlaneMismatch, Count: 1}}, nil
	}
	decode := func(evs []*record.Event) []record.GapPayload {
		var out []record.GapPayload
		for _, ev := range evs {
			var g record.GapPayload
			if ev.Kind != record.KindGap || ev.DecodePayload(&g) != nil {
				t.Fatalf("not a gap: %+v", ev)
			}
			out = append(out, g)
		}
		return out
	}
	got := decode(orphanPlaneGaps(target, 7, read, slog.New(slog.DiscardHandler)))
	want := []record.GapPayload{
		{What: record.GapEnforce, Why: record.GapPlaneBound, Count: 2, DecisionPlane: record.DecisionPlaneLSM},
		{What: record.GapEnforce, Why: record.GapPlaneMismatch, Count: 1, DecisionPlane: record.DecisionPlaneLSM},
	}
	if !slices.Equal(got, want) || asked != target {
		t.Errorf("gaps %+v (asked %+v), want %+v", got, asked, want)
	}
	failing := func(cgroupenforce.ReapTarget) ([]cgroupenforce.PlaneCount, error) { return nil, errors.New("gone") }
	got = decode(orphanPlaneGaps(target, 7, failing, slog.New(slog.DiscardHandler)))
	if len(got) != 1 || got[0].Why != record.GapPlaneCountersUnread || got[0].DecisionPlane != record.DecisionPlaneLSM {
		t.Errorf("an unread slot: %+v", got)
	}
	target.PlaneMode = ""
	if evs := orphanPlaneGaps(target, 7, read, slog.New(slog.DiscardHandler)); len(evs) != 0 {
		t.Errorf("a run on the listener wrote %d plane gaps", len(evs))
	}
}
