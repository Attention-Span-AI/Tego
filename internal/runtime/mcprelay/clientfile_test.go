// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// dirFD holds the directory open, as a root launcher hands it to the relay.
func dirFD(t *testing.T, dir string) *sys.FD {
	t.Helper()
	fd, err := sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fd.Close() })
	return fd
}

// fdFor is the descriptor a root launcher passes (uid >= 0), or none for the user's own runtime directory (uid < 0).
func fdFor(t *testing.T, dir string, uid int) *sys.FD {
	t.Helper()
	if uid < 0 {
		return nil
	}
	return dirFD(t, dir)
}

// owner is the mode and owner of the file or link at p, not followed.
func owner(t *testing.T, p string) (os.FileMode, int, int) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return fi.Mode(), int(st.Uid), int(st.Gid)
}

// TestClientFileOfARootLauncher: in a directory a root launcher made, the file is 0400 and handed to the account the
// agent runs as by its descriptor, so that account reads it and no group or world bit lets another user. (The test
// hands it to its own account, which any user may; root's chown to another is the same call.)
func TestClientFileOfARootLauncher(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	dir := t.TempDir()
	if err := s.UseClientDir(dir, dirFD(t, dir), os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	p := s.Vars()[EnvConfig]
	if p != filepath.Join(dir, ConfigName) {
		t.Fatalf("TEGO_MCP_CONFIG = %q, want the file in %s", p, dir)
	}
	if m, uid, gid := owner(t, p); m != 0o400 || uid != os.Getuid() || gid != os.Getgid() {
		t.Errorf("file mode %v owner %d:%d, want 0400 and %d:%d", m, uid, gid, os.Getuid(), os.Getgid())
	}
	if b, err := os.ReadFile(p); err != nil || !strings.Contains(string(b), `"mcp"`) || !strings.Contains(string(b), "--server") {
		t.Errorf("config %q, %v", b, err)
	}
}

// TestClientFileIsMadeExclusivelyAndNeverThroughALink: a link or a file already at the name is refused, the link's
// target and the file are untouched, and the run has no TEGO_MCP_CONFIG then (it is refused as a whole by the runner).
func TestClientFileIsMadeExclusivelyAndNeverThroughALink(t *testing.T) {
	for _, uid := range []int{-1, os.Getuid()} {
		s, _, _ := start(t, nil, filesServer())
		dir, victim := t.TempDir(), filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(dir, ConfigName)); err != nil {
			t.Fatal(err)
		}
		if err := s.UseClientDir(dir, fdFor(t, dir, uid), uid, os.Getgid()); err == nil {
			t.Fatalf("uid %d: a link at the name was written through", uid)
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Errorf("uid %d: the link's target is now %q", uid, b)
		}
		if _, ok := s.Vars()[EnvConfig]; ok {
			t.Errorf("uid %d: TEGO_MCP_CONFIG is set after a refused write", uid)
		}
		if m, _, _ := owner(t, filepath.Join(dir, ConfigName)); m&os.ModeSymlink == 0 {
			t.Errorf("uid %d: the planted link was replaced (%v)", uid, m)
		}
		other := t.TempDir()
		if err := os.WriteFile(filepath.Join(other, ConfigName), []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.UseClientDir(other, fdFor(t, other, uid), uid, os.Getgid()); err == nil {
			t.Fatalf("uid %d: a file already there was replaced", uid)
		}
		if b, _ := os.ReadFile(filepath.Join(other, ConfigName)); string(b) != "mine" {
			t.Errorf("uid %d: the file is now %q", uid, b)
		}
	}
}

// TestNoDirectoryRefusesInsteadOfSkipping: the relay used to log a warning and go on with TEGO_MCP_RELAY and no
// TEGO_MCP_CONFIG; with no directory it is an error now, and the variable is never set.
func TestNoDirectoryRefusesInsteadOfSkipping(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	if err := s.UseClientDir("", nil, -1, -1); !errors.Is(err, ErrNoClientDir) {
		t.Fatalf("err = %v, want ErrNoClientDir", err)
	}
	if _, ok := s.Vars()[EnvConfig]; ok {
		t.Error("TEGO_MCP_CONFIG is set")
	}
}

// TestRelayNeverReadsTheClientFileBack: the file is the client's convenience. An agent that rewrites its copy to name
// another command is still admitted for the declared one only, and its denied tool is still refused: what the relay
// decides comes from the contract the launcher compiled.
func TestRelayNeverReadsTheClientFileBack(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	dir := t.TempDir()
	if err := s.UseClientDir(dir, dirFD(t, dir), os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	p := s.Vars()[EnvConfig]
	if err := os.Chmod(p, 0o600); err != nil { // the file is the agent's own: it may
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mcpServers":{"files":{"command":"python3","args":["/tmp/evil.py"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, f := dial(t, s, "files", []string{"python3", "/tmp/evil.py"}); f.OK || !strings.Contains(f.Error, "not server files's declared command") {
		t.Fatalf("the rewritten command was admitted: %+v", f)
	}
	sh, f := dial(t, s, "files", filesCmd)
	if !f.OK {
		t.Fatalf("the declared command was refused: %+v", f)
	}
	sh.client(toolCall(1, "delete_file"))
	if f := sh.read(); f.ToServer != nil || !strings.Contains(string(f.ToClient), `"code":-32001`) {
		t.Fatalf("the denied tool went through: %+v", f)
	}
}
