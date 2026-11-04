// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unixOwnProbe binds a stream and a datagram socket of its own in argv[1] and reaches each, then reaches the
// stream and datagram sockets the test bound there before the run, and writes what each returned. argv[3] is a
// directory outside every entry, where the test has sockets of its own that no name the probe uses may reach.
const unixOwnProbe = `import errno, json, os, socket, sys
d, out, x = sys.argv[1], sys.argv[2], sys.argv[3]
res = {}
def attempt(key, f):
    try:
        f()
        res[key] = "ok"
    except OSError as e:
        res[key] = errno.errorcode.get(e.errno, str(e.errno))
def own_stream():
    p = os.path.join(d, "own.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(p)
    srv.listen(1)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(p)
    c.sendall(b"hi")
    conn, _ = srv.accept()
    if conn.recv(2) != b"hi":
        raise OSError(errno.EIO, "own stream lost its bytes")
def own_dgram():
    p = os.path.join(d, "own.dg")
    r = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    r.bind(p)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", p)
    r.settimeout(2)
    r.recv(4)
def daemon_stream():
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(os.path.join(d, "daemon.sock"))
def daemon_dgram():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", os.path.join(d, "daemon.dg"))
def own_renamed():
    p, q = os.path.join(d, "bound.sock"), os.path.join(d, "renamed.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(p)
    srv.listen(1)
    os.rename(p, q)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(q)
def planted_dgram():
    # A symlink the agent puts at a name a unix: entry declares (in the "yes" contract), leading out of the write entry
    # to the test's socket there: decided where it leads.
    p = os.path.join(d, "pg.dg")
    os.symlink(os.path.join(x, "pd.dg"), p)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", p)
def planted_stream():
    p = os.path.join(d, "pg.sock")
    os.symlink(os.path.join(x, "ps.sock"), p)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(p)
def dotdot_dgram():
    # Its own socket at dd.dg, and a datagram to lnk/../dd.dg: lnk leads out of the write entry, and the kernel
    # climbs from where it leads, to the test's socket there, while the name's lexical spelling is the run's own.
    r = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    r.bind(os.path.join(d, "dd.dg"))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", os.path.join(d, "lnk", "..", "dd.dg"))
def dotdot_own():
    # A ".." that stays where it is spelled reaches the run's own socket.
    p = os.path.join(d, "own2.dg")
    r = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    r.bind(p)
    os.mkdir(os.path.join(d, "sub"))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"y", os.path.join(d, "sub", "..", "own2.dg"))
    r.settimeout(2)
    r.recv(4)
def dotdot_daemon():
    # The daemon's datagram socket by a ".." name: its unix: entry, where declared, matches where the name lands.
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", os.path.join(d, "sub", "..", "daemon.dg"))
def magic():
    # The run's own socket at mg.dg, the symlink me -> /proc/self/cwd, and a datagram to me/mg.dg sent from x, outside
    # every entry, where the test's socket x/mg.dg is: the kernel resolves the magic link as this task, into x.
    r = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    r.bind(os.path.join(d, "mg.dg"))
    os.symlink("/proc/self/cwd", os.path.join(d, "me"))
    here = os.getcwd()
    os.chdir(x)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.sendto(b"x", os.path.join(d, "me", "mg.dg"))
    finally:
        os.chdir(here)
def magic_bind():
    # A socket of its own bound through that magic link from d, where it lands, then reached by its plain name.
    here = os.getcwd()
    os.chdir(d)
    try:
        r = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        r.bind(os.path.join(d, "me", "mb.dg"))
    finally:
        os.chdir(here)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"y", os.path.join(d, "mb.dg"))
    r.settimeout(2)
    r.recv(4)
def foreign_nondumpable():
    # A socket a non-dumpable process outside the run bound under the write entry: foreign, whoever reads its bind.
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(os.path.join(d, "nd.sock"))
def absent_dgram():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", os.path.join(d, "absent.dg"))
def nondumpable_child(kind, listen):
    # A child that makes itself non-dumpable before it binds, as ssh-agent does: a supervisor without CAP_SYS_PTRACE
    # (tier landlock's, unprivileged) can neither read its bind's address nor duplicate its socket. C40 refuses the
    # unreadable bind before a socket is created; a root supervisor passes the dumpable check. The pipe reports the
    # actual child errno, so a generic readiness error cannot masquerade as the security refusal.
    import ctypes
    p = os.path.join(d, "agent.sock" if kind == socket.SOCK_DGRAM else "agent-listen.sock")
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE, 0
            srv = socket.socket(socket.AF_UNIX, kind)
            srv.bind(p)
            if listen:
                srv.listen(1)
            os.write(w, b"y")
            srv.settimeout(3)
            try:
                srv.accept() if listen else srv.recv(1)
            except OSError:
                pass
        except OSError as e:
            os.write(w, bytes([e.errno]))
        finally:
            os._exit(0)
    os.close(w)
    ready = os.read(r, 1)
    try:
        if ready != b"y":
            raise OSError(ready[0] if ready else errno.EIO, "the non-dumpable child's bind/listen was refused")
        c = socket.socket(socket.AF_UNIX, kind)
        if listen:
            c.connect(p)
        else:
            c.sendto(b"x", p)
    finally:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
def nondumpable():
    nondumpable_child(socket.SOCK_DGRAM, False)
def nondumpable_listen():
    nondumpable_child(socket.SOCK_STREAM, True)
# Non-dumpable cases exercise C40 after the ordinary socket-provenance cases.
for k, f in (("own_stream", own_stream), ("own_dgram", own_dgram), ("own_renamed", own_renamed), ("daemon_stream", daemon_stream),
             ("daemon_dgram", daemon_dgram), ("planted_dgram", planted_dgram), ("planted_stream", planted_stream),
             ("dotdot_dgram", dotdot_dgram), ("dotdot_own", dotdot_own), ("dotdot_daemon", dotdot_daemon),
             ("magic", magic), ("magic_bind", magic_bind), ("foreign_nondumpable", foreign_nondumpable),
             ("absent_dgram", absent_dgram), ("nondumpable", nondumpable),
             ("nondumpable_listen", nondumpable_listen)):
    attempt(k, f)
json.dump(res, open(out, "w"))
`

// nonDumpableBinder is a process outside the run that makes itself non-dumpable, binds a stream socket at argv[1],
// opens it to everyone and listens, says so on stdout, and waits to be killed.
const nonDumpableBinder = `import ctypes, os, socket, sys, time
ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o777)
s.listen(1)
print("y", flush=True)
time.sleep(60)
`

// tracesAnyone reports whether this process holds CAP_SYS_PTRACE, which passes ptrace_may_access's dumpable check:
// a supervisor that has it reads the bind of a non-dumpable process of the run and duplicates its socket.
func tracesAnyone(t *testing.T) bool {
	t.Helper()
	c, err := sys.ReadTaskCreds(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return c.CapEff&(1<<unix.CAP_SYS_PTRACE) != 0
}

// TestUnixForeign is supervisor R11 and R11a at tier landlock on the real kernel: under a write entry, the sockets
// the agent binds itself are reached with no unix: entry (stream and datagram), while a stream and a datagram socket
// another process bound there before the run — a daemon's control socket, as Codex's app-server left in CODEX_HOME
// (interactive-codex POC finding F6) — are refused, unix-foreign, and receive nothing. Declaring the daemon's sockets
// with unix: entries admits them, so the refusal is R11a's and not a permission or a listener that never listened. A
// socket the run bound and then renamed is still the run's; a datagram to a name that names nothing reads ENOENT,
// unix-absent; a socket a non-dumpable process outside the run bound is foreign, and one a non-dumpable child of the
// run bound (as ssh-agent does) is decided by whether the supervisor could read its bind: unprivileged it cannot, and
// C40 refuses its unreadable bind as builtin.tego_surface before a socket exists; with CAP_SYS_PTRACE (root, as in
// the KVM guest) it reads the bind, and the socket is the run's own (base verification item 6).
//
// A name is decided on what it reaches when the task's own lookup resolves it, never on its spelling: a symlink the
// agent puts at a name a unix: entry declares, leading outside every entry, is refused and the socket there receives
// nothing; a datagram whose name climbs out through a symlink and a ".." lands outside,
// though its lexical spelling is the run's own socket; and one through a /proc/self/cwd link is
// refused rather than resolved as the supervisor — whose cwd is the write entry here, where the run's own socket of
// that name is — while the kernel resolves it as the task, into a directory outside. A ".." that
// lands on the run's own socket reaches it, one that lands on the daemon's is matched by its unix: entry, and a socket
// bound through the magic link is still the run's where its file settles it.
func TestUnixForeign(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	privileged := tracesAnyone(t)
	for _, declared := range []bool{false, true} {
		t.Run(map[bool]string{false: "no", true: "yes"}[declared], func(t *testing.T) {
			// The fixture's home is its project, so ~/out/ is the write entry the sockets lie under.
			section := "net:\n  allow: []\n"
			if declared {
				section = "net:\n  allow: [\"unix:~/out/daemon.sock\", \"unix:~/out/daemon.dg\", \"unix:~/out/pg.dg\", \"unix:~/out/pg.sock\"]\n"
			}
			f := newFixtureIn(t, unixSocketProject(t), contractFor("unix-own", []string{python}, []string{python, resolved})+section, nil)
			deps := f.deps(t, nil) // before the chdir below: it builds the tego binary from the package directory
			// The supervisor runs in this process: its cwd is the write entry, where the run's own mg.dg will be.
			t.Chdir(f.out)
			stream := filepath.Join(f.out, "daemon.sock")
			dgram := filepath.Join(f.out, "daemon.dg")
			ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stream, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			dg, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: dgram, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer dg.Close()
			// Outside the write entry: x, the probe's cwd for its magic-link cell, and x/deep, where out/lnk leads, so
			// out/lnk/.. is x; and sockets of the test's own there that no name the probe uses may reach.
			outside := filepath.Join(f.dir, "x")
			if err := os.MkdirAll(filepath.Join(outside, "deep"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{outside, filepath.Join(outside, "deep")} {
				if err := os.Chmod(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			reach := map[string]*net.UnixConn{}
			for _, name := range []string{"dd.dg", "pd.dg", "mg.dg"} {
				c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(outside, name), Net: "unixgram"})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				reach[name] = c
			}
			planted, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(outside, "ps.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer planted.Close()
			if err := os.Symlink(filepath.Join(outside, "deep"), filepath.Join(f.out, "lnk")); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, filepath.Join(f.out, "lnk"))
			for _, p := range []string{stream, dgram, filepath.Join(outside, "dd.dg"), filepath.Join(outside, "pd.dg"),
				filepath.Join(outside, "mg.dg"), filepath.Join(outside, "ps.sock")} {
				if err := os.Chmod(p, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			// A non-dumpable process outside the run binds out/nd.sock.
			nd := exec.Command(python, "-c", nonDumpableBinder, filepath.Join(f.out, "nd.sock"))
			ndOut, err := nd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := nd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = nd.Process.Kill(); _ = nd.Wait() }()
			if line, err := bufio.NewReader(ndOut).ReadString('\n'); err != nil || line != "y\n" {
				t.Fatalf("the non-dumpable binder did not bind: %q, %v", line, err)
			}
			script := filepath.Join(f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(unixOwnProbe), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			if _, err := Run(context.Background(), f.rt, []string{python, script, f.out, filepath.Join(f.out, "result.json"), outside}, deps); err != nil {
				t.Fatalf("Run: %v", err)
			}
			raw, err := os.ReadFile(filepath.Join(f.out, "result.json"))
			if err != nil {
				t.Fatalf("the probe wrote nothing: %v", err)
			}
			got := map[string]string{}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			daemon := "EACCES"
			if declared {
				daemon = "ok"
			}
			// A bind's name decides nothing: the socket bound through the magic link is the run's on every
			// filesystem, its file found by identity (on btrfs and overlayfs the directory a bind's name reached decided, and
			// a magic link left it unknown, refused unix-origin-unread).
			magicBind := "ok"
			nondumpable, nondumpableListen := "EACCES", "EACCES"
			if privileged {
				nondumpable, nondumpableListen = "ok", "ok"
			}
			for k, want := range map[string]string{"own_stream": "ok", "own_dgram": "ok", "own_renamed": "ok",
				"daemon_stream": daemon, "daemon_dgram": daemon, "planted_dgram": "EACCES", "planted_stream": "EACCES",
				"dotdot_dgram": "EACCES", "dotdot_own": "ok", "dotdot_daemon": daemon, "magic": "EACCES",
				"magic_bind": magicBind, "foreign_nondumpable": "EACCES", "absent_dgram": "ENOENT",
				"nondumpable": nondumpable, "nondumpable_listen": nondumpableListen} {
				if got[k] != want {
					t.Errorf("%s = %s, want %s (all: %v)", k, got[k], want, got)
				}
			}
			_ = ln.SetDeadline(time.Now().Add(200 * time.Millisecond))
			c, aerr := ln.Accept()
			if aerr == nil {
				c.Close()
			}
			if reached := aerr == nil; reached != declared {
				t.Errorf("the daemon's stream socket accepted a connection: %t, want %t", reached, declared)
			}
			_ = dg.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _, rerr := dg.ReadFrom(make([]byte, 4))
			if reached := rerr == nil; reached != declared {
				t.Errorf("the daemon's datagram socket received a datagram: %t, want %t", reached, declared)
			}
			for name, c := range reach {
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if _, _, err := c.ReadFrom(make([]byte, 4)); err == nil {
					t.Errorf("the socket outside every entry at x/%s received a datagram", name)
				}
			}
			_ = planted.SetDeadline(time.Now().Add(200 * time.Millisecond))
			if c, err := planted.Accept(); err == nil {
				c.Close()
				t.Error("the socket outside every entry at x/ps.sock accepted a connection")
			}
			lines := map[string]*record.Event{}
			builtinBinds := 0
			for _, e := range events(t, runDirs(t, f.root)[0]) {
				var p record.NetPayload
				if e.Kind == record.KindNet && e.DecodePayload(&p) == nil {
					lines[p.Dst] = e
					if p.Op == "bind" && e.Verdict == record.VerdictRefused && e.Rule == agent.BuiltinTegoSurface {
						builtinBinds++
					}
				}
			}
			for _, p := range []string{stream, dgram} {
				e := lines["unix:"+p]
				switch {
				case e == nil:
					t.Errorf("no net line for %s", p)
				case !declared && (e.Verdict != record.VerdictRefused || e.Rule != "unix-foreign"):
					t.Errorf("%s: line %s/%s, want refused/unix-foreign", p, e.Verdict, e.Rule)
				case declared && e.Verdict != record.VerdictAllow:
					t.Errorf("%s: line %s/%s, want allow", p, e.Verdict, e.Rule)
				}
			}
			for _, p := range []string{filepath.Join(f.out, "own.sock"), filepath.Join(f.out, "own.dg"), filepath.Join(f.out, "renamed.sock"),
				filepath.Join(f.out, "sub") + "/../own2.dg"} {
				if e := lines["unix:"+p]; e != nil && e.Verdict != record.VerdictAllow {
					t.Errorf("%s: line %s/%s, want allow: the run bound it", p, e.Verdict, e.Rule)
				}
			}
			switch e := lines["unix:"+filepath.Join(f.out, "sub")+"/../daemon.dg"]; {
			case e == nil:
				t.Error("no net line for sub/../daemon.dg")
			case !declared && (e.Verdict != record.VerdictRefused || e.Rule != "unix-foreign"):
				t.Errorf("sub/../daemon.dg: line %s/%s, want refused/unix-foreign", e.Verdict, e.Rule)
			case declared && e.Verdict != record.VerdictAllow:
				t.Errorf("sub/../daemon.dg: line %s/%s, want allow by its unix: entry", e.Verdict, e.Rule)
			}
			// Refused for what the name reaches, and the rule says why; what R11a cannot know is not called foreign: a name
			// that names nothing. Non-dumpable children are refused earlier, at bind, by C40.
			refusals := map[string]string{
				"pg.dg": "unmatched", "pg.sock": "unmatched", "lnk/../dd.dg": "unmatched", "me/mg.dg": "path-unreliable",
				"nd.sock": "unix-foreign", "absent.dg": "unix-absent",
			}
			for name, rule := range refusals {
				e := lines["unix:"+f.out+"/"+name]
				if e == nil || e.Verdict != record.VerdictRefused || e.Rule != rule {
					t.Errorf("%s: line %+v, want refused/%s", name, e, rule)
				}
			}
			wantBinds := 2
			if privileged {
				wantBinds = 0
			}
			if builtinBinds != wantBinds {
				t.Errorf("immutable unreadable-bind refusals = %d, want %d", builtinBinds, wantBinds)
			}
			if !privileged {
				for _, name := range []string{"agent.sock", "agent-listen.sock"} {
					if _, err := os.Stat(filepath.Join(f.out, name)); !os.IsNotExist(err) {
						t.Errorf("unreadable bind created %s: %v", name, err)
					}
				}
			}
			if privileged {
				if e := lines["unix:"+filepath.Join(f.out, "agent.sock")]; e == nil || e.Verdict != record.VerdictAllow {
					t.Errorf("agent.sock: line %+v, want allow: a supervisor with CAP_SYS_PTRACE read the bind", e)
				}
			}
		})
	}
}

// unixSocketNames are the names the sockets of every test on unixSocketProject take in the project's out/: TestUnixForeign's
// (the probe's and the test's), and the longest name the ask-unix spelling tests connect by, x/y/lnk/../../sub/app.sock,
// which a project under a 46-byte TMPDIR put past sun_path while every name of TestUnixForeign fitted (Python's connect
// then raised "AF_UNIX path too long" and the probe wrote None, 2026-10-19).
var unixSocketNames = []string{"own.sock", "own.dg", "bound.sock", "renamed.sock", "daemon.sock", "daemon.dg",
	"pg.dg", "pg.sock", "dd.dg", "lnk/../dd.dg", "own2.dg", "sub/../own2.dg", "sub/../daemon.dg", "me/mg.dg", "me/mb.dg",
	"mb.dg", "nd.sock", "absent.dg", "agent.sock", "x/y/lnk/../../sub/app.sock"}

// unixSocketProject is a project directory whose out/ holds every socket name of unixSocketNames within sun_path's
// 107 bytes whatever TMPDIR is: under TMPDIR when that fits, else under /tmp. Under t.TempDir the paths took
// TMPDIR, the test's name and two random parts, and bind failed EINVAL for any TMPDIR of 31 bytes or more (a lane's
// $HOME/.cache/w<LANE>, a CI runner's temporary directory) before the run began (2026-10-17). The directory is o+x,
// as newFixture's are made when the agent runs as the invoking user under sudo.
func unixSocketProject(t *testing.T) string {
	t.Helper()
	const sunPath = len(unix.RawSockaddrUnix{}.Path) - 1 // the NUL
	longest := 0
	for _, n := range unixSocketNames {
		longest = max(longest, len(n))
	}
	// <base>/eyuf<10 digits>/out/<name>
	fits := func(base string) bool { return len(base)+len("/eyuf0123456789/out/")+longest <= sunPath }
	base := os.TempDir()
	if !fits(base) {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "eyuf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	for _, n := range unixSocketNames {
		if p := filepath.Join(dir, "out", n); len(p) > sunPath {
			t.Fatalf("socket path %s is %d bytes, past sun_path's %d", p, len(p), sunPath)
		}
	}
	return dir
}
