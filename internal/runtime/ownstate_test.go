// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ownStateTree is a ~/.tego as a run finds it: the anchor's directory holding chain.log and the ledger root, which
// holds its live index.
type ownStateTree struct{ base, state, anchor, root, live string }

// newOwnStateTree makes an ownStateTree under a temporary directory, in tego's own modes, and makes the test's launcher
// its owner (asOwnerOf).
func newOwnStateTree(t *testing.T) ownStateTree {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, StateDir)
	tr := ownStateTree{base: base, state: state, anchor: filepath.Join(state, ledger.ChainLogFile),
		root: filepath.Join(state, "runs")}
	tr.live = filepath.Join(tr.root, ledger.LiveDir)
	if err := os.MkdirAll(tr.live, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tr.anchor, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	asOwnerOf(t, base)
	t.Cleanup(func() { ownerRightsBack(base) }) // before the temporary directory's removal, whatever the test left
	return tr
}

// asOwnerOf makes the test's launcher the owner of everything under dir: this process, or, as root, which restores no
// mode, a uid of its own that the tree is handed to.
func asOwnerOf(t *testing.T, dir string) {
	t.Helper()
	uid := os.Geteuid()
	if uid == 0 {
		uid = 65534
		if err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, uid, -1)
		}); err != nil {
			t.Fatal(err)
		}
	}
	prev := launcherEUID
	launcherEUID = func() int { return uid }
	t.Cleanup(func() { launcherEUID = prev })
}

// chmodAll sets each path's mode in turn.
func chmodAll(t *testing.T, mode os.FileMode, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
}

// modeOf is path's permission bits, not following a final link.
func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// ownerRightsBack gives the owner back their rights on every directory and file under dir, a directory before what it
// holds, so a test's temporary directory can be removed whatever a run left in it.
func ownerRightsBack(dir string) {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		if err == nil && st.Mode().IsRegular() {
			_ = os.Chmod(dir, st.Mode().Perm()|0o600) // best effort: a failure shows as the removal's own error
		}
		return
	}
	_ = os.Chmod(dir, st.Mode().Perm()|0o700) // best effort, as above
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		ownerRightsBack(filepath.Join(dir, e.Name()))
	}
}

// TestRestoreOwnStateNamesTheConfigLayerAndTheRuntimeParent: the home's ~/.tego and the config layer in it, which tego
// only reads, so its owner's read is all that comes back, tego's own log, and the runtime parent every run makes its
// directory in.
func TestRestoreOwnStateNamesTheConfigLayerAndTheRuntimeParent(t *testing.T) {
	tr := newOwnStateTree(t)
	layer, log := filepath.Join(tr.base, config.UserRelPath), filepath.Join(tr.state, "tego.log")
	for _, p := range []string{layer, log} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	xdg := filepath.Join(tr.base, "xdg")
	parent := filepath.Join(xdg, agent.RuntimeDirName)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	asOwnerOf(t, tr.base)
	chmodAll(t, 0, layer, log, tr.state, parent)
	got, err := RestoreOwnState(OwnState{Home: tr.base, Log: log, RuntimeParent: parent})
	if err != nil {
		t.Fatalf("RestoreOwnState: %v", err)
	}
	if want := []ModeRestored{{tr.state, 0, 0o700}, {parent, 0, 0o700}, {log, 0, 0o600}, {layer, 0, 0o400}}; !slices.Equal(got, want) {
		t.Fatalf("restored %v, want %v", got, want)
	}
	// The parent named is the one a run makes its directory in, and none where a run makes none.
	prev := launcherEUID
	t.Cleanup(func() { launcherEUID = prev })
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	if got := RuntimeParent(); got != parent {
		t.Errorf("RuntimeParent() = %q, want %q", got, parent)
	}
	launcherEUID = func() int { return 0 }
	if got := RuntimeParent(); got != "" {
		t.Errorf("a root launcher's RuntimeParent() = %q, want none: it makes no runtime directory", got)
	}
	launcherEUID = prev
	for _, v := range []string{"", "relative/dir"} {
		t.Setenv("XDG_RUNTIME_DIR", v)
		if got := RuntimeParent(); got != "" {
			t.Errorf("XDG_RUNTIME_DIR=%q: RuntimeParent() = %q, want none", v, got)
		}
	}
}

// TestRestoreOwnStateGivesTheOwnerTheirRightsBack is GAPS C52's state with every mode taken: chain.log, the directory
// that holds it, the ledger root and its live index, chmod 000 innermost first, as an agent must take them. Each is
// restored to tego's own mode, a directory before what it holds, and named with the mode it had; a second pass finds
// nothing to restore.
func TestRestoreOwnStateGivesTheOwnerTheirRightsBack(t *testing.T) {
	tr := newOwnStateTree(t)
	chmodAll(t, 0, tr.live, tr.root, tr.anchor, tr.state)
	got, err := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: tr.root})
	if err != nil {
		t.Fatalf("RestoreOwnState: %v", err)
	}
	want := []ModeRestored{{tr.state, 0, 0o700}, {tr.root, 0, 0o700}, {tr.anchor, 0, 0o600}, {tr.live, 0, 0o700}}
	if !slices.Equal(got, want) {
		t.Fatalf("restored %v, want %v", got, want)
	}
	for _, m := range want {
		if mode := modeOf(t, m.Path); mode != os.FileMode(m.To) {
			t.Errorf("%s has mode %04o, want %04o", m.Path, mode, m.To)
		}
	}
	if again, err := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: tr.root}); err != nil || again != nil {
		t.Fatalf("a second pass restored %v, %v; want nothing", again, err)
	}
}

// TestRestoreOwnStateTakesOnlyWhatLacksAnOwnerRight: a mode that keeps the owner's read, write and search (a file's
// read and write) is left as it is, group and other bits included; one that lacks any of them gets those owner bits
// back, and every other bit it had, with the mode it had named.
func TestRestoreOwnStateTakesOnlyWhatLacksAnOwnerRight(t *testing.T) {
	tr := newOwnStateTree(t)
	chmodAll(t, 0o755, tr.state)
	chmodAll(t, 0o711, tr.live)
	chmodAll(t, 0o640, tr.anchor)
	chmodAll(t, 0o311, tr.root) // no read: a sweep could not list it
	got, err := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: tr.root})
	if err != nil {
		t.Fatalf("RestoreOwnState: %v", err)
	}
	if want := []ModeRestored{{tr.root, 0o311, 0o711}}; !slices.Equal(got, want) {
		t.Fatalf("restored %v, want %v", got, want)
	}
	for p, want := range map[string]os.FileMode{tr.state: 0o755, tr.live: 0o711, tr.anchor: 0o640, tr.root: 0o711} {
		if mode := modeOf(t, p); mode != want {
			t.Errorf("%s has mode %04o, want %04o", p, mode, want)
		}
	}
	chmodAll(t, 0o400, tr.anchor) // read only: no append
	if got, _ := RestoreOwnState(OwnState{Anchor: tr.anchor}); !slices.Equal(got, []ModeRestored{{tr.anchor, 0o400, 0o600}}) {
		t.Fatalf("a read-only chain.log: restored %v", got)
	}
}

// TestRestoreOwnStateLeavesGroupAndOtherBitsToTheChecks: a directory others could write is one whose entries someone
// else could have replaced, which the config trust check (R20) and the runtime directory's (R10a) refuse. A restore
// that set such a directory to 0700 would have passed them over it, so it gives the owner their bits back and leaves the
// rest, and the trust check still refuses it, with its own fix.
func TestRestoreOwnStateLeavesGroupAndOtherBitsToTheChecks(t *testing.T) {
	tr := newOwnStateTree(t)
	chmodAll(t, 0o066, tr.anchor)
	chmodAll(t, 0o077, tr.state) // last: the owner can no longer search it
	got, err := RestoreOwnState(OwnState{Anchor: tr.anchor})
	if err != nil {
		t.Fatalf("RestoreOwnState: %v", err)
	}
	if want := []ModeRestored{{tr.state, 0o077, 0o777}, {tr.anchor, 0o066, 0o666}}; !slices.Equal(got, want) {
		t.Fatalf("restored %v, want %v", got, want)
	}
	d, err := os.Open(tr.state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }() // read only
	var ue *config.UntrustedError
	if err := config.CheckTrusted(d, tr.state, launcherEUID()); !errors.As(err, &ue) || ue.Reason != "group or other writable" {
		t.Errorf("the trust check reads the restored ~/.tego as %v, want it still refused as group or other writable", err)
	}
}

// TestRestoreOwnStateFollowsNoLink: a link at one of the names is neither followed nor changed, so the file or
// directory it leads to keeps its mode, and so does whatever else sits there that tego never makes.
func TestRestoreOwnStateFollowsNoLink(t *testing.T) {
	tr := newOwnStateTree(t)
	victims := filepath.Join(tr.base, "elsewhere")
	victimFile, victimDir := filepath.Join(victims, "file"), filepath.Join(victims, "dir")
	if err := os.MkdirAll(victimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victimFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	asOwnerOf(t, tr.base)
	for _, p := range []string{tr.anchor, tr.live} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(victimFile, tr.anchor); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(tr.live, 0); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tr.base, "root-link")
	if err := os.Symlink(victimDir, root); err != nil {
		t.Fatal(err)
	}
	chmodAll(t, 0, victimFile, victimDir)
	got, _ := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: root}) // root's live index lies beyond the link, which may not be searched
	if len(got) != 0 {
		t.Fatalf("restored %v through links and a FIFO, want nothing", got)
	}
	got, _ = RestoreOwnState(OwnState{Root: tr.root}) // the ledger root itself, holding the FIFO at its live index
	if len(got) != 0 {
		t.Fatalf("restored %v, want nothing", got)
	}
	for _, p := range []string{victimFile, victimDir, tr.live} {
		if mode := modeOf(t, p); mode != 0 {
			t.Errorf("%s has mode %04o, want it left at 0000", p, mode)
		}
	}
}

// TestRestoreOwnStateLeavesWhatIsNotTheLaunchers: a root launcher, which reads and writes through any mode, restores
// none, and an object another uid owns is not this launcher's to change; nothing at a path is no error.
func TestRestoreOwnStateLeavesWhatIsNotTheLaunchers(t *testing.T) {
	tr := newOwnStateTree(t)
	chmodAll(t, 0o400, tr.anchor)
	owner := launcherEUID()
	for _, euid := range []int{0, owner + 1} {
		launcherEUID = func() int { return euid }
		if got, err := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: tr.root}); err != nil || got != nil {
			t.Errorf("as uid %d: restored %v, %v; want nothing", euid, got, err)
		}
	}
	launcherEUID = func() int { return owner }
	if mode := modeOf(t, tr.anchor); mode != 0o400 {
		t.Errorf("chain.log has mode %04o, want 0400 kept", mode)
	}
	missing := filepath.Join(tr.base, "none")
	if got, err := RestoreOwnState(OwnState{Anchor: filepath.Join(missing, ledger.ChainLogFile), Root: filepath.Join(missing, "runs")}); err != nil || got != nil {
		t.Errorf("nothing there: restored %v, %v; want nothing and no error", got, err)
	}
}

// TestRestoreTreeWalksTheRunDirectory: at its end a run restores its directory's entries and those of the directories
// it holds (blobs/), a directory before what it holds, and goes no deeper than the writer makes.
func TestRestoreTreeWalksTheRunDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r-run")
	blobs := filepath.Join(dir, ledger.BlobsDir)
	deeper := filepath.Join(blobs, "deeper")
	if err := os.MkdirAll(deeper, 0o700); err != nil {
		t.Fatal(err)
	}
	events, lock, blob, past := filepath.Join(dir, ledger.EventsFile), filepath.Join(dir, ledger.LockFile),
		filepath.Join(blobs, "abc"), filepath.Join(deeper, "past")
	for _, p := range []string{events, lock, blob, past} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asOwnerOf(t, filepath.Dir(dir))
	t.Cleanup(func() { ownerRightsBack(dir) })
	chmodAll(t, 0, past, deeper, blob, blobs, events)
	var got []ModeRestored
	if err := restoreTree(dir, runTreeDepth, needDir, needFile, &got); err != nil {
		t.Fatalf("restoreTree: %v", err)
	}
	var paths []string
	for _, m := range got {
		paths = append(paths, m.Path)
	}
	want := slices.Sorted(slices.Values([]string{events, blobs, blob, deeper}))
	if !slices.Equal(slices.Sorted(slices.Values(paths)), want) {
		t.Fatalf("restored %q, want %q", paths, want)
	}
	if slices.Index(paths, blobs) > slices.Index(paths, blob) {
		t.Errorf("restored %q: blobs/ after what it holds", paths)
	}
	if mode := modeOf(t, past); mode != 0 {
		t.Errorf("%s, below the depth the writer makes, has mode %04o, want it left at 0000", past, mode)
	}
}

// TestRestoreRunStateGivesTheUserStateBack: at its end a run gives back the user's ~/.tego, config layer and tego.log
// (Deps.UserState) beside its own state, so a mode its agent took from the layer is not left for the commands after
// it, which pass over a layer they cannot read; with no UserState it gives back its own state only.
func TestRestoreRunStateGivesTheUserStateBack(t *testing.T) {
	tr := newOwnStateTree(t)
	layer, log := filepath.Join(tr.base, config.UserRelPath), filepath.Join(tr.state, "tego.log")
	dir := filepath.Join(tr.root, "r-run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{layer, log, filepath.Join(dir, ledger.EventsFile)} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asOwnerOf(t, tr.base)
	for _, c := range []struct {
		user               OwnState
		layerMode, logMode os.FileMode
	}{{OwnState{}, 0, 0}, {OwnState{Home: tr.base, Log: log}, 0o400, 0o600}} {
		chmodAll(t, 0, layer, log, tr.state)
		r := &runner{dir: dir, log: slog.New(slog.DiscardHandler), deps: Deps{AnchorPath: tr.anchor, UserState: c.user}}
		r.restoreRunState()
		if got := modeOf(t, tr.state); got != 0o700 {
			t.Errorf("UserState %+v: ~/.tego, chain.log's directory, has mode %04o, want 0700", c.user, got)
		}
		if got, want := modeOf(t, layer), c.layerMode; got != want {
			t.Errorf("UserState %+v: the config layer has mode %04o, want %04o", c.user, got, want)
		}
		if got, want := modeOf(t, log), c.logMode; got != want {
			t.Errorf("UserState %+v: tego.log has mode %04o, want %04o", c.user, got, want)
		}
	}
}

// TestOwnStateGapNamesEachPath: what the caller restored before the run is one gap line each after run_start, what=record
// why=own-state-mode-restored binary=<path>, with no count, which readers take for lost events.
func TestOwnStateGapNamesEachPath(t *testing.T) {
	restored := []ModeRestored{{"/home/u/.tego", 0, 0o700}, {"/home/u/.tego/chain.log", 0, 0o600}}
	r := &runner{queue: NewQueue(64), log: slog.New(slog.DiscardHandler), deps: Deps{OwnStateRestored: restored}}
	r.emitOwnStateGap()
	r.queue.Close()
	var got []record.GapPayload
	for ev := range r.queue.C() {
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil || ev.Kind != record.KindGap {
			t.Fatalf("%s line %s: %v", ev.Kind, ev.Payload, err)
		}
		got = append(got, p)
	}
	want := []record.GapPayload{{What: record.GapRecord, Why: record.GapOwnStateModeRestored, Binary: restored[0].Path},
		{What: record.GapRecord, Why: record.GapOwnStateModeRestored, Binary: restored[1].Path}}
	if !slices.Equal(got, want) {
		t.Fatalf("gap lines %+v, want %+v", got, want)
	}
}

// TestRestoreOwnStateGivesBackTheRunDirectoriesUnderTheRoot (A48): an agent that took its own run directory while it
// ran, and the files in it, left tego status, events, stop and the dashboard out of it; no run end restored an
// orphaned or earlier run's directory. A run's start now gives the owner their rights back on every run directory
// under the root, adding the owner's bits and nothing else.
func TestRestoreOwnStateGivesBackTheRunDirectoriesUnderTheRoot(t *testing.T) {
	tr := newOwnStateTree(t)
	live := filepath.Join(tr.root, "r-0a0a0a0a-0000000000001-aaaaaa")    // taken whole, while live
	earlier := filepath.Join(tr.root, "r-0a0a0a0a-0000000000002-bbbbbb") // its events file taken
	orphan := filepath.Join(tr.root, "r-0a0a0a0a-0000000000003-cccccc")  // blobs/ taken, with the group's rights kept
	fine := filepath.Join(tr.root, "r-0a0a0a0a-0000000000004-dddddd")    // nothing taken: not touched
	named := filepath.Join(tr.root, "r-0a0a0a0a-0000000000005-eeeeee")   // a file with a run's name
	for _, d := range []string{live, earlier, orphan, fine} {
		if err := os.MkdirAll(filepath.Join(d, ledger.BlobsDir), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{ledger.EventsFile, ledger.LockFile} {
			if err := os.WriteFile(filepath.Join(d, f), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(named, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	asOwnerOf(t, tr.root)
	t.Cleanup(func() { ownerRightsBack(tr.root) })
	liveEvents, earlierEvents := filepath.Join(live, ledger.EventsFile), filepath.Join(earlier, ledger.EventsFile)
	orphanBlobs := filepath.Join(orphan, ledger.BlobsDir)
	chmodAll(t, 0, liveEvents, filepath.Join(live, ledger.BlobsDir), live, earlierEvents, orphanBlobs)
	chmodAll(t, 0o070, orphan) // the group's rights stay: the checks judge them
	got, err := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: tr.root})
	if err != nil {
		t.Fatalf("RestoreOwnState: %v", err)
	}
	want := map[string]os.FileMode{live: 0o700, liveEvents: 0o600, filepath.Join(live, ledger.BlobsDir): 0o700,
		earlierEvents: 0o600, orphan: 0o770, orphanBlobs: 0o700}
	have := map[string]os.FileMode{}
	for _, m := range got {
		have[m.Path] = os.FileMode(m.To)
	}
	for p, mode := range want {
		if have[p] != mode || modeOf(t, p) != mode {
			t.Errorf("%s: restored to %04o, now %04o; want %04o (all restored: %v)", p, have[p], modeOf(t, p), mode, got)
		}
	}
	for _, p := range []string{fine, earlier, named} {
		if _, ok := have[p]; ok {
			t.Errorf("%s was restored though it lacked no owner right", p)
		}
	}
	if mode := modeOf(t, named); mode != 0 {
		t.Errorf("a file with a run's name has mode %04o, want it left at 0000", mode)
	}
	if again, err := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: tr.root}); err != nil || again != nil {
		t.Errorf("a second pass restored %v, %v; want nothing", again, err)
	}
	// Another user's run directory is nobody's to restore here.
	chmodAll(t, 0, earlier)
	owner := launcherEUID()
	launcherEUID = func() int { return owner + 1 }
	if got, err := RestoreOwnState(OwnState{Anchor: tr.anchor, Root: tr.root}); err != nil || got != nil {
		t.Errorf("as another uid: restored %v, %v; want nothing", got, err)
	}
	launcherEUID = func() int { return owner }
	if mode := modeOf(t, earlier); mode != 0 {
		t.Errorf("another user's run directory has mode %04o, want it left at 0000", mode)
	}
}

// TestRestoreOwnStateGivesBackAWindowLock: chmod is the one thing a held agent can still do to the ledger root, and the
// name of an agent's window lock follows from its identity, so an agent can take the lock's mode; every later start of
// that agent (and of no other) would then be refused at the lock's open until a person ran chmod. The restore gives the
// owner their rights back on it, as it does on a run's directory, and on nothing that only looks like a lock: S3, another
// agent never blocks this one, holds when the start restores it.
func TestRestoreOwnStateGivesBackAWindowLock(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	g.end(first)
	asOwnerOf(t, filepath.Dir(g.root))
	t.Cleanup(func() { ownerRightsBack(filepath.Dir(g.root)) })
	locks, _ := filepath.Glob(filepath.Join(g.root, ".window-*.lock"))
	if len(locks) != 1 {
		t.Fatalf("locks %v, want one", locks)
	}
	lookalikes := []string{filepath.Join(g.root, ".window-notahash.lock"), filepath.Join(g.root, "x.lock")}
	for _, p := range lookalikes {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	chmodAll(t, 0, append([]string{locks[0]}, lookalikes...)...)
	if os.Geteuid() != 0 { // root opens a file whatever its mode: the refusal below is a non-root launcher's
		if _, _, _, err := g.start(windowLimits(1000), thirtyDays); !errors.Is(err, ErrBudgetWindow) {
			t.Fatalf("a taken lock: err = %v, want the start refused before the restore", err)
		}
	}
	got, err := RestoreOwnState(OwnState{Root: g.root})
	if err != nil {
		t.Fatalf("RestoreOwnState: %v", err)
	}
	if want := []ModeRestored{{locks[0], 0, 0o600}}; !slices.Equal(got, want) {
		t.Fatalf("restored %v, want only the lock: %v", got, want)
	}
	for _, p := range lookalikes {
		if mode := modeOf(t, p); mode != 0 {
			t.Errorf("%s has mode %04o: a name that is not a lock's is nobody's to restore here", p, mode)
		}
	}
	second, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatalf("after the restore the agent starts: %v", err)
	}
	g.end(second)
	if again, err := RestoreOwnState(OwnState{Root: g.root}); err != nil || again != nil {
		t.Fatalf("a second pass restored %v, %v; want nothing", again, err)
	}
}
