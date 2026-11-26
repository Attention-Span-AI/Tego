// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Public issue 98: what the client directory's unit tests cannot show, since an unprivileged test cannot chown to
// another account, be refused as another account, or meet a /run that another account owns.
const (
	clientOwnerUID = 41001 // the account the agent drops to
	clientOtherUID = 41002 // another local user
)

// shAsUser runs `sh -c script` as uid, with no supplementary groups, from /.
func shAsUser(t *testing.T, uid uint32, script string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{"-c", script, "sh"}, args...)...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// clientScene makes the stand-in for /run: a directory of root's that everyone may walk through, and the path of the
// client parent in it.
func clientScene(t *testing.T) (run, parent string) {
	t.Helper()
	base, err := os.MkdirTemp("", "tego-client-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	run = filepath.Join(base, "run")
	if err := os.Mkdir(run, 0o755); err != nil {
		t.Fatal(err)
	}
	return run, filepath.Join(run, "tego-agent")
}

// TestRootClientDirectory: from a root launcher, the client directory of a run is root's and 0711 whatever the umask; the
// file in it, handed to the agent's account (an account other than the launcher's), is read by that account and by no
// other, and neither account can add a file beside it or list the directory; a /run or a parent that another account owns
// is refused; and a sweep leaves a live run's locked directory and a directory another account owns alone while it takes
// a dead run's.
func TestRootClientDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: chown to another account, DAC as another account, a /run of another owner")
	}
	log := slog.New(slog.DiscardHandler)
	const (
		id1 = "r-00000000-000000000000a-aaaaaa"
		id2 = "r-00000000-000000000000b-bbbbbb"
		id3 = "r-00000000-000000000000c-cccccc"
		id4 = "r-00000000-000000000000d-dddddd"
	)

	t.Run("the modes are 0711 whatever the umask", func(t *testing.T) {
		for _, umask := range []int{0o077, 0o000, 0o277} {
			_, parent := clientScene(t)
			old := unix.Umask(umask)
			c, err := makeClientDir(parent, id1, log)
			unix.Umask(old)
			if err != nil {
				t.Fatalf("umask %04o: %v", umask, err)
			}
			for _, p := range []string{parent, c.path} {
				fi, err := os.Lstat(p)
				if err != nil || fi.Mode().Perm() != 0o711 || fi.Sys().(*syscall.Stat_t).Uid != 0 {
					t.Errorf("umask %04o: %s is %v (%v), want root's 0711", umask, p, fi.Mode(), err)
				}
			}
			_ = c.close()
		}
	})

	t.Run("the account the agent drops to reads its file and nobody else does", func(t *testing.T) {
		_, parent := clientScene(t)
		c, err := makeClientDir(parent, id1, log)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.close() }()
		fd, err := c.dir.Openat("tego-mcp.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o400)
		if err != nil {
			t.Fatal(err)
		}
		f, err := fd.Release("tego-mcp.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("{}\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Chown(clientOwnerUID, clientOwnerUID); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		file := filepath.Join(c.path, "tego-mcp.json")
		if out, err := shAsUser(t, clientOwnerUID, `cat "$1"`, file); err != nil || out != "{}\n" {
			t.Errorf("the agent's account reads %q (%v), want its file", out, err)
		}
		if out, err := shAsUser(t, clientOtherUID, `cat "$1"`, file); err == nil || !strings.Contains(out, "Permission denied") {
			t.Errorf("another user read the file: %q (%v)", out, err)
		}
		for _, uid := range []uint32{clientOwnerUID, clientOtherUID} {
			if out, err := shAsUser(t, uid, `echo x > "$1/x"`, c.path); err == nil {
				t.Errorf("uid %d created a file beside it: %q", uid, out)
			}
			if out, err := shAsUser(t, uid, `rm -f "$1"`, file); err == nil && !fileExists(file) {
				t.Errorf("uid %d removed the file: %q", uid, out)
			}
		}
		if out, err := shAsUser(t, clientOtherUID, `ls "$1"`, c.path); err == nil {
			t.Errorf("another user listed the run's directory: %q", out)
		}
		if out, err := shAsUser(t, clientOtherUID, `ls "$1"`, parent); err == nil {
			t.Errorf("another user listed the client parent: %q", out)
		}
		if st, err := os.Lstat(file); err != nil || st.Mode().Perm() != 0o400 || st.Sys().(*syscall.Stat_t).Uid != clientOwnerUID {
			t.Errorf("the file is %v (%v), want 0400 of uid %d", st, err, clientOwnerUID)
		}
	})

	t.Run("a /run or a parent of another owner is refused", func(t *testing.T) {
		run, parent := clientScene(t)
		if err := os.Chown(run, clientOtherUID, clientOtherUID); err != nil {
			t.Fatal(err)
		}
		if c, err := makeClientDir(parent, id1, log); !errors.Is(err, ErrRuntimeDirUnsafe) {
			if c != nil {
				_ = c.close()
			}
			t.Errorf("a /run of another owner: %v, want ErrRuntimeDirUnsafe", err)
		}
		if _, err := os.Lstat(parent); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was made in it: %v", parent, err)
		}
		if err := os.Chown(run, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(parent, 0o711); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(parent, clientOtherUID, clientOtherUID); err != nil {
			t.Fatal(err)
		}
		if c, err := makeClientDir(parent, id1, log); !errors.Is(err, ErrRuntimeDirUnsafe) {
			if c != nil {
				_ = c.close()
			}
			t.Errorf("a parent of another owner: %v, want ErrRuntimeDirUnsafe", err)
		}
		if ents, _ := os.ReadDir(parent); len(ents) != 0 {
			t.Errorf("%d entries were made in another user's directory", len(ents))
		}
	})

	t.Run("a sweep takes a dead run's directory and leaves a live run's and another account's", func(t *testing.T) {
		_, parent := clientScene(t)
		dead, err := makeClientDir(parent, id1, log)
		if err != nil {
			t.Fatal(err)
		}
		live, err := makeClientDir(parent, id2, log)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = live.close() }()
		// A run's directory another account made and holds the lock of: root cannot take it for its own.
		theirs := filepath.Join(parent, id3)
		if err := os.Mkdir(theirs, 0o700); err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(theirs, runtimeLockFile)
		lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		if err := os.Chown(lockPath, clientOtherUID, clientOtherUID); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(theirs, clientOtherUID, clientOtherUID); err != nil {
			t.Fatal(err)
		}
		_ = dead.lock.Close() // the kernel drops a dead launcher's flock
		next, err := makeClientDir(parent, id4, log)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = next.close() }()
		if fileExists(dead.path) {
			t.Errorf("the dead run's directory stayed")
		}
		for _, p := range []string{live.path, theirs, next.path} {
			if !fileExists(p) {
				t.Errorf("%s was removed", p)
			}
		}
	})
}

func fileExists(p string) bool { _, err := os.Lstat(p); return err == nil }
