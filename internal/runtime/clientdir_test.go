// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// clientSpy is a source that wants a directory for a file the agent reads, as the MCP relay does.
type clientSpy struct {
	dir      string
	fd       *sys.FD
	uid, gid int
	calls    int
	err      error
}

func (s *clientSpy) Name() string                                            { return "spy" }
func (s *clientSpy) Start(context.Context, source.RunRef, source.Sink) error { return nil }
func (s *clientSpy) Stop() error                                             { return nil }
func (s *clientSpy) Gaps() []source.Gap                                      { return nil }
func (s *clientSpy) UseClientDir(dir string, fd *sys.FD, uid, gid int) error {
	s.dir, s.fd, s.uid, s.gid = dir, fd, uid, gid
	s.calls++
	return s.err
}

// asLauncher makes clientFileDir see a root or an unprivileged launcher whose agent drops to this test's own account,
// with a client directory parent of the test's own.
func asLauncher(t *testing.T, root bool) string {
	t.Helper()
	parent := fakeRun(t)
	oldP, oldR, oldT := clientDirParent, clientDirRoot, clientDirTarget
	clientDirParent = parent
	clientDirRoot = func() bool { return root }
	clientDirTarget = func() (int, int, error) { return os.Getuid(), os.Getgid(), nil }
	t.Cleanup(func() { clientDirParent, clientDirRoot, clientDirTarget = oldP, oldR, oldT })
	return parent
}

// fakeRun makes a directory that stands for /run (this user's, 0755) and returns the path of the client parent in it.
func fakeRun(t *testing.T) string {
	t.Helper()
	run := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(run, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(run, "tego-agent")
}

func clientRunner(extra ...source.Source) *runner {
	return &runner{id: "r-00000000-000000000000a-aaaaaa", log: slog.New(slog.DiscardHandler), deps: Deps{Extra: extra}}
}

func lstatModeOwner(t *testing.T, p string) (os.FileMode, uint32) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode(), fi.Sys().(*syscall.Stat_t).Uid
}

// TestRootLauncherMakesAClientDirectory: a root launcher's run gets /run/tego-agent/<id> in place of the runtime
// directory it does not make: both root's (this euid's) and 0711, the source told whose file it is to make, the lock
// file in it 0600, and the directory gone, its lock released, when the run ends.
func TestRootLauncherMakesAClientDirectory(t *testing.T) {
	parent := asLauncher(t, true)
	spy := &clientSpy{}
	r := clientRunner(spy)
	if err := r.tellClientDir(); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(parent, string(r.id))
	if spy.dir != want || r.client == nil || r.client.path != want || r.client.lock == nil || spy.fd != r.client.dir {
		t.Fatalf("source got %q (descriptor %v), run holds %+v, want %q and its descriptor", spy.dir, spy.fd, r.client, want)
	}
	if spy.uid != os.Getuid() || spy.gid != os.Getgid() {
		t.Errorf("source told owner %d:%d, want the account the agent drops to %d:%d", spy.uid, spy.gid, os.Getuid(), os.Getgid())
	}
	for _, p := range []string{parent, want} {
		if m, uid := lstatModeOwner(t, p); !m.IsDir() || m.Perm() != 0o711 || int(uid) != os.Geteuid() {
			t.Errorf("%s: mode %v owner %d, want a directory 0711 of euid %d", p, m, uid, os.Geteuid())
		}
	}
	if m, _ := lstatModeOwner(t, filepath.Join(want, runtimeLockFile)); m.Perm() != 0o600 {
		t.Errorf("lock file mode %v, want 0600", m)
	}
	if r.runtimeDir != "" {
		t.Errorf("the client directory became the runtime directory %q: harness, CODEX_HOME and reason file would engage", r.runtimeDir)
	}
	r.removeClientDir()
	if _, err := os.Lstat(want); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory outlived the run: %v", err)
	}
	if r.client != nil {
		t.Errorf("the run still holds %+v", r.client)
	}
}

// TestUnprivilegedLauncherUsesItsRuntimeDirectory: the run's own private runtime directory is the place, no owner is
// asked for and no client directory is made.
func TestUnprivilegedLauncherUsesItsRuntimeDirectory(t *testing.T) {
	parent := asLauncher(t, false)
	spy := &clientSpy{}
	r := clientRunner(spy)
	r.runtimeDir = t.TempDir()
	if err := r.tellClientDir(); err != nil {
		t.Fatal(err)
	}
	if spy.dir != r.runtimeDir || spy.uid != -1 || spy.gid != -1 || spy.fd != nil || r.client != nil {
		t.Errorf("source got %q %d:%d (descriptor %v), client dir %+v; want the runtime directory, no descriptor and no owner", spy.dir, spy.uid, spy.gid, spy.fd, r.client)
	}
	if _, err := os.Lstat(parent); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unprivileged launcher made %s: %v", parent, err)
	}
}

// TestNoPlaceForTheClientFileRefusesTheRun: an unprivileged launcher with no runtime directory (no absolute
// XDG_RUNTIME_DIR) used to start the run with TEGO_MCP_RELAY and no TEGO_MCP_CONFIG and say so only in tego's log.
// It is refused now, naming the fix, before any source is asked to write.
func TestNoPlaceForTheClientFileRefusesTheRun(t *testing.T) {
	asLauncher(t, false)
	t.Setenv("XDG_RUNTIME_DIR", "")
	spy := &clientSpy{}
	err := clientRunner(spy).tellClientDir()
	if !errors.Is(err, ErrNoClientDir) || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") || !strings.Contains(err.Error(), "mcp entries") {
		t.Fatalf("err = %v, want ErrNoClientDir naming XDG_RUNTIME_DIR and the fix", err)
	}
	if spy.calls != 0 {
		t.Errorf("the source was asked to write %d times", spy.calls)
	}
}

// TestASourceThatCannotWriteRefusesTheRun: its error is the run's, named for the source, and a root launcher leaves
// no directory behind it once the run's teardown removes it.
func TestASourceThatCannotWriteRefusesTheRun(t *testing.T) {
	asLauncher(t, true)
	spy := &clientSpy{err: errors.New("disk full")}
	r := clientRunner(spy)
	err := r.tellClientDir()
	if err == nil || !strings.Contains(err.Error(), "spy: disk full") {
		t.Fatalf("err = %v, want the source's, named", err)
	}
	dir := r.client.path
	r.removeClientDir()
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s was left: %v", dir, err)
	}
}

// TestNoSourceNoClientDirectory: a run with no source that writes for the agent makes nothing, root or not, and an
// account to drop to is not looked for.
func TestNoSourceNoClientDirectory(t *testing.T) {
	parent := asLauncher(t, true)
	clientDirTarget = func() (int, int, error) { t.Error("asked for the account the agent drops to"); return 0, 0, nil }
	r := clientRunner(&plainSource{name: "other"})
	if err := r.tellClientDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(parent); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a run with no such source made %s: %v", parent, err)
	}
}

// TestRootLauncherWithNoAccountToDropToMakesNothing: a root launcher that is no sudo user is refused later for want
// of an account to run the agent as; it is refused here first, and makes no directory.
func TestRootLauncherWithNoAccountToDropToMakesNothing(t *testing.T) {
	parent := asLauncher(t, true)
	bad := errors.New("no target")
	clientDirTarget = func() (int, int, error) { return 0, 0, bad }
	spy := &clientSpy{}
	if err := clientRunner(spy).tellClientDir(); !errors.Is(err, bad) || spy.calls != 0 {
		t.Fatalf("err = %v, calls %d", err, spy.calls)
	}
	if _, err := os.Lstat(parent); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("made %s: %v", parent, err)
	}
}

// TestClientDirectoryRefusesWhatItDidNotMake: a link, a file or another owner's directory where tego's parent is to
// be, and a name already taken where the run's directory is to be, are refused and written through by nothing.
func TestClientDirectoryRefusesWhatItDidNotMake(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	const id = "r-00000000-000000000000a-aaaaaa"
	t.Run("a link as the parent", func(t *testing.T) {
		target := t.TempDir()
		parent := fakeRun(t)
		if err := os.Symlink(target, parent); err != nil {
			t.Fatal(err)
		}
		if _, err := makeClientDir(parent, id, log); err == nil {
			t.Fatal("a link as the parent was followed")
		}
		if ents, _ := os.ReadDir(target); len(ents) != 0 {
			t.Errorf("tego wrote %d entries through the link", len(ents))
		}
	})
	t.Run("a file as the parent", func(t *testing.T) {
		parent := fakeRun(t)
		if err := os.WriteFile(parent, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := makeClientDir(parent, id, log); err == nil {
			t.Fatal("a file as the parent was taken")
		}
	})
	t.Run("a link where the run's directory goes", func(t *testing.T) {
		target := t.TempDir()
		parent := fakeRun(t)
		if err := os.Mkdir(parent, 0o711); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(parent, id)); err != nil {
			t.Fatal(err)
		}
		if _, err := makeClientDir(parent, id, log); err == nil {
			t.Fatal("a link where the run's directory goes was taken")
		}
		if ents, _ := os.ReadDir(target); len(ents) != 0 {
			t.Errorf("tego wrote %d entries through the link", len(ents))
		}
		if m, _ := lstatModeOwner(t, filepath.Join(parent, id)); m&os.ModeSymlink == 0 {
			t.Errorf("the planted link was replaced: %v", m)
		}
	})
	t.Run("a directory where the run's directory goes", func(t *testing.T) {
		parent := fakeRun(t)
		if err := os.MkdirAll(filepath.Join(parent, id), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := makeClientDir(parent, id, log); err == nil {
			t.Fatal("a directory made before the run's was taken")
		}
	})
}

// TestClientDirectoryRefusesAnUnsafeRun: /run (the directory the client parent is made in) that group or others can
// write without the sticky bit is refused before anything is made, with words that say what it must be; a sticky one
// (as /tmp is) is taken.
func TestClientDirectoryRefusesAnUnsafeRun(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	const id = "r-00000000-000000000000a-aaaaaa"
	for _, tc := range []struct {
		name string
		mode os.FileMode
		ok   bool
	}{{"world-writable", 0o777, false}, {"group-writable", 0o775, false}, {"sticky world-writable", 0o777 | os.ModeSticky, true}, {"root's own", 0o755, true}} {
		t.Run(tc.name, func(t *testing.T) {
			parent := fakeRun(t)
			if err := os.Chmod(filepath.Dir(parent), tc.mode); err != nil {
				t.Fatal(err)
			}
			c, err := makeClientDir(parent, id, log)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				_ = c.close()
				return
			}
			if !errors.Is(err, ErrRuntimeDirUnsafe) || !strings.Contains(err.Error(), "must be root's and not writable by group or others") {
				t.Fatalf("err = %v, want ErrRuntimeDirUnsafe saying what /run must be", err)
			}
			if _, err := os.Lstat(parent); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refused /run still had %s made in it: %v", parent, err)
			}
		})
	}
	t.Run("a link as /run", func(t *testing.T) {
		parent := fakeRun(t)
		real := filepath.Dir(parent)
		link := real + "-link"
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := makeClientDir(filepath.Join(link, "tego-agent"), id, log); err == nil {
			t.Fatal("a link as /run was followed")
		}
	})
}

// TestClientDirectoryStepsFollowNoSwappedLink: after /run is checked and each later step, another user who could
// rename entries swaps the client parent for a link to a directory of theirs. No step follows it: everything goes on
// in the directory that was checked and opened, and the other directory stays empty.
func TestClientDirectoryStepsFollowNoSwappedLink(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	for _, step := range []string{"run", "parent", "swept"} {
		t.Run(step, func(t *testing.T) {
			attacker := t.TempDir()
			parent := fakeRun(t)
			aside := parent + ".aside"
			swapped := false
			clientStepHook = func(s string) {
				if s != step || swapped {
					return
				}
				swapped = true
				if _, err := os.Lstat(parent); err == nil {
					if err := os.Rename(parent, aside); err != nil {
						t.Error(err)
						return
					}
				}
				if err := os.Symlink(attacker, parent); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { clientStepHook = func(string) {} })
			c, err := makeClientDir(parent, "r-00000000-000000000000a-aaaaaa", log)
			if step == "run" {
				// The parent was not made yet when /run was checked: the swapped-in link is where the next step looks.
				if err == nil {
					_ = c.close()
					t.Fatal("a link put where the parent goes was followed")
				}
			} else if err != nil {
				t.Fatal(err)
			} else {
				if _, err := os.Lstat(filepath.Join(aside, c.id)); err != nil {
					t.Errorf("the run's directory is not in the directory that was checked: %v", err)
				}
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.close() }()
			}
			if ents, _ := os.ReadDir(attacker); len(ents) != 0 {
				t.Errorf("a step followed the swapped link: %d entries in the other directory", len(ents))
			}
		})
	}
}

// plantPending makes parent/<name> as a launcher that died part way leaves it: 0700, with a lock file when withLock,
// held (flock) by the returned file when hold is set, its mtime age ago.
func plantPending(t *testing.T, parent, name string, withLock, hold bool, age time.Duration) *os.File {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var lock *os.File
	if withLock {
		f, err := os.OpenFile(filepath.Join(dir, runtimeLockFile), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		lock = f
		if hold {
			if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	return lock
}

// TestClientDirectorySweepTakesPendingDirectories: a `.new-<run id>` directory is what a launcher that died between
// its mkdir and its rename leaves. A sweep takes it by the proof it uses for a run's directory (its lock is free), and,
// when it has no lock file yet, only once it is older than clientPendingStale; one whose lock is held, or one with no
// lock made a moment ago, is a launcher in the middle of making it and stays.
func TestClientDirectorySweepTakesPendingDirectories(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	parent := fakeRun(t)
	if err := os.Mkdir(parent, 0o711); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id             string
		withLock, hold bool
		age            time.Duration
		gone           bool
	}{
		{"r-00000000-000000000000a-aaaaaa", true, false, 0, true},                       // lock free: its launcher is gone
		{"r-00000000-000000000000b-bbbbbb", true, true, time.Hour, false},               // lock held: a launcher is making it
		{"r-00000000-000000000000c-cccccc", false, false, 0, false},                     // no lock, just made
		{"r-00000000-000000000000d-dddddd", false, false, 2 * clientPendingStale, true}, // no lock, long ago
	}
	for _, c := range cases {
		if f := plantPending(t, parent, runtimeDirPending+c.id, c.withLock, c.hold, c.age); f != nil && c.hold {
			t.Cleanup(func() { _ = f.Close() })
		} else if f != nil {
			_ = f.Close()
		}
	}
	// A directory that is not a pending run's: left alone whatever its age.
	plantPending(t, parent, ".new-notarunid", false, false, 2*clientPendingStale)
	c, err := makeClientDir(parent, "r-00000000-000000000000e-eeeeee", log)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.close() }()
	for _, tc := range cases {
		_, err := os.Lstat(filepath.Join(parent, runtimeDirPending+tc.id))
		if gone := errors.Is(err, os.ErrNotExist); gone != tc.gone {
			t.Errorf("%s (lock %v held %v age %v): removed %v, want %v", tc.id, tc.withLock, tc.hold, tc.age, gone, tc.gone)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, ".new-notarunid")); err != nil {
		t.Errorf("a directory that is no run's was removed: %v", err)
	}
}

// TestClientDirectorySweepTakesOnlyDeadRuns: a root launcher's next launch removes the directory of a launcher that
// was killed (its lock free) and leaves the one whose launcher lives.
func TestClientDirectorySweepTakesOnlyDeadRuns(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	parent := fakeRun(t)
	dead, err := makeClientDir(parent, "r-00000000-000000000000a-aaaaaa", log)
	if err != nil {
		t.Fatal(err)
	}
	live, err := makeClientDir(parent, "r-00000000-000000000000b-bbbbbb", log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.close() })
	_ = dead.lock.Close() // the kernel drops a dead launcher's flock
	next, err := makeClientDir(parent, "r-00000000-000000000000c-cccccc", log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.close() })
	if _, err := os.Lstat(dead.path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dead run's directory stayed: %v", err)
	}
	for _, p := range []string{live.path, next.path} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
