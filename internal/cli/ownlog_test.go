// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// selfOnly trusts this process's own uid and root, as processOwnLog does for an unprivileged run.
func selfOnly(u uint32) bool { return u == 0 || int(u) == os.Geteuid() }

// testOwnLog is an appender under a fresh home with this process as the owner.
func testOwnLog(t *testing.T) (*ownLog, string) {
	t.Helper()
	home := t.TempDir()
	return newOwnLog(home, ownLogOwner{uid: -1, gid: -1}, selfOnly), home
}

// machineAt is a machine config whose log.level is level.
func machineAt(level string) *config.Machine {
	m := config.Builtin()
	m.Log.Level = config.Setting[string]{Value: level}
	return m
}

func logPath(home string, suffix string) string {
	return filepath.Join(home, ownLogDir, ownLogName+suffix)
}

// TestOwnLogWritesTheInvokingUsersLog is the layout of P0-DESIGN §3.3 and OPERATIONS.md: one structured
// line per record in ~/.tego/tego.log, the file 0600 in a 0700 directory, pid on every line so two
// concurrent processes can be told apart.
func TestOwnLogWritesTheInvokingUsersLog(t *testing.T) {
	l, home := testOwnLog(t)
	newOwnLogger(l, machineAt("info")).With("run", "r-1").Warn("run: detach", "err", "busy")

	b, err := os.ReadFile(logPath(home, ""))
	if err != nil {
		t.Fatalf("no log written: %v", err)
	}
	line := string(b)
	for _, want := range []string{"level=WARN", `msg="run: detach"`, "pid=" + strconv.Itoa(os.Getpid()), "run=r-1", "err=busy"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q lacks %s", line, want)
		}
	}
	if n := strings.Count(line, "\n"); n != 1 {
		t.Errorf("%d lines for one record", n)
	}
	for path, want := range map[string]os.FileMode{filepath.Join(home, ownLogDir): 0o700, logPath(home, ""): 0o600} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got&^want != 0 {
			t.Errorf("%s mode %o, want at most %o", path, got, want)
		}
	}
}

// TestOwnLogLevelComesFromTheMachineConfig is spec/config/v0's log.level: debug | info | warn.
func TestOwnLogLevelComesFromTheMachineConfig(t *testing.T) {
	for _, tc := range []struct {
		level       string
		debug, info bool
	}{
		{"debug", true, true},
		{"info", false, true},
		{"warn", false, false},
	} {
		t.Run(tc.level, func(t *testing.T) {
			l, home := testOwnLog(t)
			log := newOwnLogger(l, machineAt(tc.level))
			log.Debug("d-line")
			log.Info("i-line")
			log.Warn("w-line")
			b, _ := os.ReadFile(logPath(home, ""))
			got := string(b)
			if strings.Contains(got, "d-line") != tc.debug || strings.Contains(got, "i-line") != tc.info ||
				!strings.Contains(got, "w-line") {
				t.Fatalf("log.level %s wrote %q", tc.level, got)
			}
		})
	}
	if lvl := ownLogLevel(nil); lvl.String() != "INFO" {
		t.Fatalf("no machine config gives level %s, want the built-in info", lvl)
	}
}

// TestOwnLogRotatesAtItsSizeLimit is "rotated 10 MB x 5": past the limit the file is renamed to .1, the
// older ones shift, and no more than the configured number of files is ever kept.
func TestOwnLogRotatesAtItsSizeLimit(t *testing.T) {
	l, home := testOwnLog(t)
	l.max, l.files = 200, 3
	line := strings.Repeat("x", 63) + "\n"
	for i := range 40 {
		if _, err := l.Write([]byte(strconv.Itoa(i%10) + line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	for _, suffix := range []string{"", ".1", ".2"} {
		st, err := os.Stat(logPath(home, suffix))
		if err != nil {
			t.Fatalf("tego.log%s missing after rotation: %v", suffix, err)
		}
		if suffix != "" && st.Size() < l.max {
			t.Errorf("tego.log%s is %d bytes, rotated before reaching %d", suffix, st.Size(), l.max)
		}
		if st.Size() > l.max+int64(len(line))+1 {
			t.Errorf("tego.log%s is %d bytes, past the limit by more than one line", suffix, st.Size())
		}
	}
	if _, err := os.Stat(logPath(home, ".3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tego.log.3 exists (%v): only 3 files may be kept", err)
	}
}

// TestOwnLogFollowsARotationByAnotherProcess: two appenders share the file, as two concurrent tego
// processes do. When one rotates, the other's next line must go to the new tego.log, not keep growing
// the file that is now tego.log.1.
func TestOwnLogFollowsARotationByAnotherProcess(t *testing.T) {
	a, home := testOwnLog(t)
	b := newOwnLog(home, ownLogOwner{uid: -1, gid: -1}, selfOnly)
	a.max, b.max = 100, 100
	if _, err := b.Write([]byte("b-first\n")); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := a.Write([]byte(strings.Repeat("a", 59) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	// a has rotated on its third write; b still holds what is now tego.log.1.
	if _, err := b.Write([]byte("b-second\n")); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(logPath(home, ""))
	if !strings.Contains(string(cur), "b-second") {
		old, _ := os.ReadFile(logPath(home, ".1"))
		t.Fatalf("b kept writing to the rotated file:\ntego.log: %q\ntego.log.1: %q", cur, old)
	}
}

// TestOwnLogRefusesAPlantedFile covers the reason every name is opened O_NOFOLLOW against a directory
// descriptor and checked afterwards. Under sudo this process is root writing into the invoking user's
// directory, and that user could otherwise make root append to any file on the machine.
func TestOwnLogRefusesAPlantedFile(t *testing.T) {
	plant := map[string]func(t *testing.T, home, victim string){
		"symlinked log": func(t *testing.T, home, victim string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := os.Symlink(victim, logPath(home, "")); err != nil {
				t.Fatal(err)
			}
		},
		"hard-linked log": func(t *testing.T, home, victim string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := os.Link(victim, logPath(home, "")); err != nil {
				t.Fatal(err)
			}
		},
		"symlinked directory": func(t *testing.T, home, victim string) {
			other := filepath.Join(filepath.Dir(victim), "elsewhere")
			mustMkdir(t, other)
			if err := os.Symlink(other, filepath.Join(home, ownLogDir)); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable directory": func(t *testing.T, home, victim string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := os.Chmod(filepath.Join(home, ownLogDir), 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, home, victim string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := syscall.Mkfifo(logPath(home, ""), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range plant {
		t.Run(name, func(t *testing.T) {
			l, home := testOwnLog(t)
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			setup(t, home, victim)
			done := make(chan error, 1)
			go func() {
				_, err := l.Write([]byte("planted\n"))
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("the log was written through a planted name")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the write blocked on the planted name")
			}
			if b, _ := os.ReadFile(victim); len(b) != 0 {
				t.Fatalf("the victim file received %q", b)
			}
			if entries, _ := os.ReadDir(filepath.Join(filepath.Dir(victim), "elsewhere")); len(entries) != 0 {
				t.Fatalf("the log landed in the symlink's target: %v", entries)
			}
			// Best effort: one failure is remembered, not retried on every line.
			if _, err := l.Write([]byte("again\n")); err == nil {
				t.Fatal("a broken log accepted a second write")
			}
		})
	}
}

// TestOwnLogTightensALooseFile: a log another tool left 0644 carries paths and errors about the user's
// runs, so it is brought back to the 0600 the layout names.
func TestOwnLogTightensALooseFile(t *testing.T) {
	l, home := testOwnLog(t)
	mustMkdir(t, filepath.Join(home, ownLogDir))
	if err := os.WriteFile(logPath(home, ""), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(logPath(home, ""), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(logPath(home, ""))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", st.Mode().Perm())
	}
}

// TestOwnLogHomeIsThePasswdHome is the Trust rule of spec/config/v0: the passwd database names the home,
// $HOME is never read for a secure-exec process, and a root process with no passwd entry has no log
// rather than one wherever $HOME points.
func TestOwnLogHomeIsThePasswdHome(t *testing.T) {
	passwd := func(int) (string, error) { return "/home/from-passwd", nil }
	none := func(int) (string, error) { return "", errors.New("no passwd entry") }
	env := func() (string, error) { return "/home/from-env", nil }
	notSecure := func() (bool, error) { return false, nil }
	secure := func() (bool, error) { return true, nil }
	unreadable := func() (bool, error) { return false, errors.New("auxv") }

	if got := ownLogHome(1000, notSecure, env, passwd); got != "/home/from-passwd" {
		t.Errorf("home %q, want the passwd entry's even when $HOME differs", got)
	}
	if got := ownLogHome(1000, secure, env, none); got != "" {
		t.Errorf("home %q under AT_SECURE with no passwd entry, want none", got)
	}
	if got := ownLogHome(1000, unreadable, env, none); got != "" {
		t.Errorf("home %q with an unreadable auxv, want none", got)
	}
	want := "/home/from-env"
	if os.Geteuid() == 0 {
		want = ""
	}
	if got := ownLogHome(1000, notSecure, env, none); got != want {
		t.Errorf("home %q for an ordinary process with no passwd entry, want %q", got, want)
	}
	// A process with no home at all has no log, and says so instead of writing anywhere.
	l := newOwnLog("", ownLogOwner{uid: -1, gid: -1}, selfOnly)
	if _, err := l.Write([]byte("x\n")); !errors.Is(err, errNoHome) {
		t.Fatalf("write with no home: %v, want errNoHome", err)
	}
}

// TestProcessLogStaysInTheTestsHome: what this package's tests make tego log goes to the home TestMain
// gave the process's appender, never to the developer's own ~/.tego/tego.log, which one run of the suites
// had grown by two dozen ERROR lines and the stack of the internal-error test's "kaboom" panic.
func TestProcessLogStaysInTheTestsHome(t *testing.T) {
	marker := "own-log seam " + strconv.FormatInt(time.Now().UnixNano(), 36)
	logOwn(marker)
	b, err := os.ReadFile(logPath(testHome, ""))
	if err != nil || !strings.Contains(string(b), marker) {
		t.Fatalf("%q is not in %s (%v): the process's own log is not the test's", marker, logPath(testHome, ""), err)
	}
	if got := processOwnLog().home; got != testHome {
		t.Fatalf("the process's own log is under %q, want TestMain's %q", got, testHome)
	}
}

// TestOwnLogHandsItsFilesToTheInvokingUser is the sudo case: root creates ~/.tego and tego.log in the
// invoking user's home, and they must end up that user's, or the user's own later runs and commands
// could neither read the log nor write into ~/.tego. Needs root to chown.
func TestOwnLogHandsItsFilesToTheInvokingUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: chown to another uid")
	}
	const uid, gid = 4242, 4343
	home := t.TempDir()
	l := newOwnLog(home, ownLogOwner{uid: uid, gid: gid}, func(u uint32) bool { return u == 0 || u == uid })
	if _, err := l.Write([]byte("as root\n")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(home, ownLogDir), logPath(home, "")} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		sys := st.Sys().(*syscall.Stat_t)
		if sys.Uid != uid || sys.Gid != gid {
			t.Errorf("%s is %d:%d, want the invoking user's %d:%d", path, sys.Uid, sys.Gid, uid, gid)
		}
	}
}

// TestOwnLogStaysBoundedWhileTheRotationLockIsHeld: any process of the user's uid can open ~/.tego and
// hold the flock rotation takes — the agent can, and it can make tego log warnings at will — and with the
// lock held the appender kept writing past the limit forever (64,006 bytes against a limit of 200 in a
// thousand lines). Past twice the limit it drops and counts lines instead, and says how many once it can
// rotate again.
func TestOwnLogStaysBoundedWhileTheRotationLockIsHeld(t *testing.T) {
	l, home := testOwnLog(t)
	l.max = 200
	line := strings.Repeat("y", 63) + "\n"
	if _, err := l.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	holder, err := os.Open(filepath.Join(home, ownLogDir))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	dropped := 0
	for range 1000 {
		if _, err := l.Write([]byte(line)); errors.Is(err, errLogFull) {
			dropped++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(logPath(home, ""))
	if err != nil {
		t.Fatal(err)
	}
	if limit := 2*l.max + int64(len(line)); st.Size() > limit {
		t.Fatalf("tego.log is %d bytes with the rotation lock held, want at most %d", st.Size(), limit)
	}
	if dropped == 0 {
		t.Fatal("no line was reported dropped")
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(logPath(home, ""))
	if want := strconv.Itoa(dropped) + " lines dropped"; !strings.Contains(string(cur), want) || !strings.HasSuffix(string(cur), "after\n") {
		t.Fatalf("after the lock was released tego.log holds %q, want the note %q and then the line", cur, want)
	}
}

// TestOwnLogRefusesADirectorySwappedInAfterItsMkdir is the sudo case of openDir's two lookups: root makes
// ~/.tego and then opens the name, and in between a user can rename in a directory they may write but do
// not own. It was chowned to them because root had made "a" directory there. It is refused now, and keeps
// its owner. Needs root, to chown and to make a directory another uid owns.
func TestOwnLogRefusesADirectorySwappedInAfterItsMkdir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the swapped-in directory belongs to a third uid")
	}
	const uid, gid, third = 4242, 4343, 5151
	home := t.TempDir()
	shared := filepath.Join(t.TempDir(), "shared")
	mustMkdir(t, shared)
	if err := os.Chown(shared, third, third); err != nil {
		t.Fatal(err)
	}
	prev := ownLogMkdirHook
	ownLogMkdirHook = func() {
		if err := os.Remove(filepath.Join(home, ownLogDir)); err != nil {
			t.Error(err)
		}
		if err := os.Rename(shared, filepath.Join(home, ownLogDir)); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { ownLogMkdirHook = prev })
	l := newOwnLog(home, ownLogOwner{uid: uid, gid: gid}, func(u uint32) bool { return u == 0 || u == uid })
	if _, err := l.Write([]byte("as root\n")); err == nil {
		t.Fatal("the log was written into a directory this process did not make")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(home, ownLogDir), &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != third {
		t.Fatalf("the swapped-in directory is now uid %d's, want it left %d's", st.Uid, third)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}
