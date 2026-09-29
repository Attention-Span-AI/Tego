// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	// modeUnixRelay runs the target's unix connects under a net: section whose only admits are the write
	// directory and the entries helperUnixPaths declares.
	modeUnixRelay = "unixrelay"
	// helperUnixPaths is the target's list of sockets to connect to, comma-separated, each as name=path;
	// a relative path is connected as written, from the harness directory.
	helperUnixPaths = "TEGO_SUPERVISOR_UNIX_PATHS"
	// helperOwnSocks is the stream sockets the target binds and listens on in its directory, under its filter,
	// before it connects: the sockets the run itself bound (R11a), comma-separated names. A name written
	// taken>name first binds the socket to taken, a name already taken, and that bind must fail; the same socket
	// then binds name.
	helperOwnSocks = "TEGO_SUPERVISOR_OWN_SOCKS"
	// helperOwnCwd is the directory, relative to the harness directory, the target binds helperOwnSocks from; it
	// connects from the harness directory again after.
	helperOwnCwd = "TEGO_SUPERVISOR_OWN_CWD"
	// helperBinds is the bind mounts a target in a mount namespace of its own makes before its filter,
	// comma-separated, each as source=target.
	helperBinds = "TEGO_SUPERVISOR_BINDS"
	// harnessDirMark in helperUnixPaths or helperBinds stands for the harness directory, which does not
	// exist yet when a test writes the target's environment.
	harnessDirMark = "@DIR@"
)

// inHarnessDir replaces harnessDirMark with the harness directory the target was given.
func inHarnessDir(s string) string {
	return strings.ReplaceAll(s, harnessDirMark, os.Getenv(helperDir))
}

// unixRelayChecks connects to each socket helperUnixPaths names, one fresh stream socket each, from
// inside the harness directory: a relative name is walked from the target's cwd, and stays short enough
// for sun_path whatever TMPDIR is.
func unixRelayChecks() []checkResult {
	var out []checkResult
	if err := unix.Chdir(os.Getenv(helperDir)); err != nil {
		return []checkResult{{Name: "chdir", Err: errText(err)}}
	}
	if cwd := os.Getenv(helperOwnCwd); cwd != "" {
		if err := unix.Chdir(cwd); err != nil {
			return []checkResult{{Name: "chdir " + cwd, Err: errText(err)}}
		}
	}
	for _, name := range splitComma(os.Getenv(helperOwnSocks)) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if taken, rest, rebind := strings.Cut(name, ">"); rebind && err == nil {
			if unix.Bind(fd, &unix.SockaddrUnix{Name: taken}) == nil {
				return []checkResult{{Name: "own " + name, Err: "the bind to a taken name took"}}
			}
			name = rest
		}
		if err == nil {
			err = unix.Bind(fd, &unix.SockaddrUnix{Name: name})
		}
		if err == nil {
			err = unix.Listen(fd, 8) // held open, and so bound, for the target's life
		}
		if err != nil {
			return []checkResult{{Name: "own " + name, Err: errText(err)}}
		}
	}
	if err := unix.Chdir(os.Getenv(helperDir)); err != nil {
		return []checkResult{{Name: "chdir", Err: errText(err)}}
	}
	for _, kv := range splitComma(inHarnessDir(os.Getenv(helperUnixPaths))) {
		name, p, _ := strings.Cut(kv, "=")
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			err = unix.Connect(fd, &unix.SockaddrUnix{Name: p})
			_ = unix.Close(fd)
		}
		out = append(out, checkResult{Name: name, Err: errText(err)})
	}
	return out
}

// credListener is a unix listener that records the SO_PEERCRED of every connection it accepts.
type credListener struct {
	creds chan *unix.Ucred
}

func listenCreds(t *testing.T, path string, mode os.FileMode) *credListener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	l := &credListener{creds: make(chan *unix.Ucred, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var cred *unix.Ucred
			if raw, err := c.(*net.UnixConn).SyscallConn(); err == nil {
				_ = raw.Control(func(fd uintptr) {
					cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				})
			}
			l.creds <- cred
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return l
}

// accepted drains what the listener has accepted so far.
func (l *credListener) accepted() []*unix.Ucred {
	var out []*unix.Ucred
	for {
		select {
		case c := <-l.creds:
			out = append(out, c)
		case <-time.After(100 * time.Millisecond):
			return out
		}
	}
}

// TestIntegrationUnixRelaySymlink is R11 on the real kernel, unprivileged: the target
// makes a symlink's worth of escape out of its write directory, and the relay refuses it. Before, the
// relay passed the target's path to connect(2) in this process, the kernel followed the symlink, and a
// socket outside every admitted path was connected and recorded allow against the write entry. A
// symlink that stays inside the write directory, to a socket the target bound itself, still connects; the
// harness's own socket there, which the target did not bind, is refused unix-foreign (R11a).
func TestIntegrationUnixRelaySymlink(t *testing.T) {
	// Not t.TempDir: its test-named path does not fit in sun_path (108 bytes) once TMPDIR is long.
	outside, err := os.MkdirTemp("", "o")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	secret := listenCreds(t, filepath.Join(outside, "secret.sock"), 0o777)
	h := startHarnessWith(t, harnessOpts{
		mode: modeUnixRelay,
		prepare: func(d string) {
			for link, target := range map[string]string{
				"esc.sock":   filepath.Join(outside, "secret.sock"),
				"lnk":        outside,
				"alias.sock": "own.sock",
			} {
				if err := os.Symlink(target, filepath.Join(d, link)); err != nil {
					t.Fatal(err)
				}
			}
		},
		env: []string{helperOwnSocks + "=own.sock",
			helperUnixPaths + "=escape=esc.sock,dir_escape=lnk/secret.sock,alias=alias.sock,foreign=u.sock"},
	})
	h.stop(t)
	for _, c := range []struct{ name, want string }{{"escape", "EACCES"}, {"dir_escape", "EACCES"}, {"alias", ""}, {"foreign", "EACCES"}} {
		got := h.check(t, c.name).Err
		if (c.want == "" && got != "") || (c.want != "" && !isErrno(got, unix.EACCES)) {
			t.Errorf("%s: connect = %q, want %s", c.name, got, map[bool]string{true: "success", false: c.want}[c.want == ""])
		}
	}
	if n := len(secret.accepted()); n != 0 {
		t.Errorf("the socket outside the write directory accepted %d connection(s), want none", n)
	}
	for dst, rule := range map[string]string{
		"unix:esc.sock":        ruleUnmatched,
		"unix:lnk/secret.sock": ruleUnmatched,
		"unix:u.sock":          ruleUnixForeign,
	} {
		evs := h.netEvents(t, dst)
		if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != rule {
			t.Errorf("%s: events %+v, want one refused/%s", dst, evs, rule)
		}
	}
}

// TestIntegrationUnixRelayAsTask is the tier-2 shape: this process is root and the target runs as
// uid 1000, as a root launcher drops it (runtime-launch R4). A declared connect used to be relayed by this
// process as root: the uid-1000 target reached a 0600 socket in a 0700 root directory, and the listener
// read uid 0 in SO_PEERCRED. Relayed as the task, the kernel refuses the first exactly as it refuses the
// target's own connect, and the second reads uid 1000.
func TestIntegrationUnixRelayAsTask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the target must run as another uid than this process (kvm-run.sh)")
	}
	const uid, gid = 1000, 1000
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := listenCreds(t, filepath.Join(private, "secret.sock"), 0o600)
	public, err := os.MkdirTemp("", "tego-relay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(public) })
	if err := os.Chmod(public, 0o755); err != nil {
		t.Fatal(err)
	}
	open := listenCreds(t, filepath.Join(public, "open.sock"), 0o777)
	secretPath, openPath := filepath.Join(private, "secret.sock"), filepath.Join(public, "open.sock")

	h := startHarnessWith(t, harnessOpts{
		mode:     modeUnixRelay,
		as:       &syscall.Credential{Uid: uid, Gid: gid},
		declared: []string{secretPath, openPath},
		env:      []string{helperUnixPaths + "=root_only=" + secretPath + ",open=" + openPath},
	})
	h.stop(t)

	if c := h.check(t, "root_only"); !isErrno(c.Err, unix.EACCES) {
		t.Errorf("declared 0600 root socket in a 0700 root directory = %q, want EACCES, as the uid-%d task's own connect gets", c.Err, uid)
	}
	if got := secret.accepted(); len(got) != 0 {
		t.Errorf("the root-only listener accepted %d connection(s) (first peer %+v), want none", len(got), got[0])
	}
	if c := h.check(t, "open"); c.Err != "" {
		t.Errorf("declared socket uid %d may open = %q, want success", uid, c.Err)
	}
	peers := open.accepted()
	if len(peers) != 1 || peers[0] == nil || peers[0].Uid != uid || peers[0].Gid != gid {
		t.Errorf("SO_PEERCRED of the relayed connect = %+v, want uid %d gid %d, not this process's", peers, uid, gid)
	}
	// The relay's own EACCES is the kernel's answer to the task, recorded against the entry that admitted
	// the name, like a relayed ECONNREFUSED (§7).
	if evs := h.netEvents(t, "unix:"+secretPath); len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
		t.Errorf("root-only socket: events %+v, want one allow line", evs)
	}
	if c, err := os.ReadFile("/proc/self/status"); err == nil && !strings.Contains(string(c), "\nUid:\t0\t0\t0\t0\n") {
		t.Errorf("this process's credentials changed:\n%s", c)
	}
}

// TestIntegrationUnixRelayOtherMountTree is R11's own-view check as root: the target runs in a mount
// namespace of its own and bind-mounts a socket from outside its write directory onto a name inside it. It
// then connects to that name by its absolute path. The relay's walk, rooted at the task's root, reaches the
// outside socket, and the path the kernel reports for it is the name under the write directory, since d_path
// builds it from the task's mounts. Matched as it was, that string admitted the connect against the write
// entry and the outside listener accepted it. Walked again here, where the name is the empty file the
// target mounted over, it reaches another inode, and the connect is refused path-unreliable. A socket both
// trees hold at one place, one the target bound itself (R11a), still connects.
func TestIntegrationUnixRelayOtherMountTree(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the target makes a mount namespace and a bind mount of its own (kvm-run.sh)")
	}
	outside, err := os.MkdirTemp("", "o")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	secretPath := filepath.Join(outside, "secret.sock")
	secret := listenCreds(t, secretPath, 0o777)
	var dir string
	h := startHarnessWith(t, harnessOpts{
		mode:    modeUnixRelay,
		mountNS: true,
		prepare: func(d string) {
			dir = d
			// The mount point: an empty file, which is all this process's tree holds at the name.
			if err := os.WriteFile(filepath.Join(d, "ns.sock"), nil, 0o666); err != nil {
				t.Fatal(err)
			}
		},
		env: []string{
			helperBinds + "=" + secretPath + "=" + harnessDirMark + "/ns.sock",
			helperOwnSocks + "=own.sock",
			helperUnixPaths + "=foreign=" + harnessDirMark + "/ns.sock,own=" + harnessDirMark + "/own.sock",
		},
	})
	h.stop(t)
	if c := h.check(t, "foreign"); !isErrno(c.Err, unix.EACCES) {
		t.Errorf("a socket bind-mounted into the write directory in the task's own tree = %q, want EACCES", c.Err)
	}
	if n := len(secret.accepted()); n != 0 {
		t.Errorf("the socket outside the write directory accepted %d connection(s), want none", n)
	}
	if c := h.check(t, "own"); c.Err != "" {
		t.Errorf("a socket at the same place in both trees = %q, want success", c.Err)
	}
	evs := h.netEvents(t, "unix:"+filepath.Join(dir, "ns.sock"))
	if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != rulePathUnreliable {
		t.Errorf("events %+v, want one refused/%s", evs, rulePathUnreliable)
	}
}
