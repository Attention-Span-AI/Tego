// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUnixConnectIsDecidedOnTheResolvedSocket is R11 and SEMANTICS §5 ("matched on the resolved socket")
// for a relayed unix connect. decideUnix matches the name the target passed, and the relay used to hand
// that name to connect(2) in this process, where the kernel followed any symlink in it: a symlink the agent
// made in its own write directory admitted every pathname socket on the machine, recorded allow against
// the write entry, and at tier 2 the connect was made as root. The relay now resolves the name as the
// task, admits the socket it resolves to against the same entries, and connects to that inode. The write
// entry's implicit admit holds only for a socket a process of the run bound (R11a): a socket there that the run
// did not bind — one that existed before the run, or that an outside daemon made, like the app-server control
// socket the interactive-codex POC reached — is refused unix-foreign, and one whose binder the kernel
// cannot report is refused unix-origin-unread.
func TestUnixConnectIsDecidedOnTheResolvedSocket(t *testing.T) {
	const addr = 0x40000
	write := []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite, Resolved: "/work"}}
	tests := []struct {
		name      string
		path      string
		declared  []agent.NetRule
		symlinks  map[string]string
		links     map[string]string
		runBound  []string // sockets a process of the run bound before the connect (R11a)
		closed    bool     // the run's sockets are gone again by the connect
		diagErr   error    // the kernel cannot say which socket is bound where
		wantErrno int32
		wantRule  string
		verdict   record.Verdict
		reached   string // "" for no connect
	}{
		{
			name: "a symlink in the write directory to a socket outside it", path: "/work/esc.sock",
			symlinks:  map[string]string{"/work/esc.sock": "/run/docker.sock"},
			wantErrno: -int32(refusalErrno), wantRule: ruleUnmatched, verdict: record.VerdictRefused,
		},
		{
			name: "a symlinked directory in the write directory", path: "/work/lnk/private",
			symlinks:  map[string]string{"/work/lnk/private": "/run/systemd/private"},
			wantErrno: -int32(refusalErrno), wantRule: ruleUnmatched, verdict: record.VerdictRefused,
		},
		{
			name: "a symlink that stays inside the write directory", path: "/work/alias.sock",
			symlinks: map[string]string{"/work/alias.sock": "/work/real.sock"}, runBound: []string{"/work/real.sock"},
			wantRule: "fs.write[/work/]", verdict: record.VerdictAllow, reached: "/work/real.sock",
		},
		{
			name: "a socket the run bound in the write directory", path: "/work/own.sock",
			runBound: []string{"/work/other.sock", "/work/own.sock"},
			wantRule: "fs.write[/work/]", verdict: record.VerdictAllow, reached: "/work/own.sock",
		},
		{
			// F6: a daemon's control socket under a write entry, made before the run or outside it.
			name: "a socket in the write directory the run did not bind", path: "/work/.codex/app-server-control.sock",
			runBound:  []string{"/work/own.sock"},
			wantErrno: -int32(refusalErrno), wantRule: ruleUnixForeign, verdict: record.VerdictRefused,
		},
		{
			name: "a symlink in the write directory to a socket there the run did not bind", path: "/work/alias.sock",
			symlinks:  map[string]string{"/work/alias.sock": "/work/daemon.sock"},
			runBound:  []string{"/work/alias.sock"},
			wantErrno: -int32(refusalErrno), wantRule: ruleUnixForeign, verdict: record.VerdictRefused,
		},
		{
			// The file outlives the socket; a socket that took the name since is not the run's.
			name: "a socket the run bound and closed", path: "/work/own.sock", runBound: []string{"/work/own.sock"}, closed: true,
			wantErrno: -int32(refusalErrno), wantRule: ruleUnixForeign, verdict: record.VerdictRefused,
		},
		{
			name: "no sock_diag to say who bound it", path: "/work/own.sock", runBound: []string{"/work/own.sock"},
			diagErr:   unix.EINVAL,
			wantErrno: -int32(refusalErrno), wantRule: ruleUnixOriginUnread, verdict: record.VerdictRefused,
		},
		{
			// /var/run is a symlink to /run on every current distribution: the declared spelling resolves,
			// once, to the socket the target's own spelling resolves to.
			name: "a declared entry spelled through a symlink", path: "/var/run/docker.sock",
			declared: []agent.NetRule{unixRuleOf("unix:/var/run/docker.sock", "/var/run/docker.sock", false)},
			symlinks: map[string]string{"/var/run/docker.sock": "/run/docker.sock"},
			links:    map[string]string{"/var/run": "/run"},
			wantRule: "net[unix:/var/run/docker.sock]", verdict: record.VerdictAllow, reached: "/run/docker.sock",
		},
		{
			// The entry resolved to itself when the loop was built. The agent can write where it lies, and
			// the symlink it puts there later does not move what the entry names.
			name: "a declared entry the agent repoints", path: "/work/app.sock",
			declared:  []agent.NetRule{unixRuleOf("unix:/work/app.sock", "/work/app.sock", false)},
			symlinks:  map[string]string{"/work/app.sock": "/run/docker.sock"},
			wantErrno: -int32(refusalErrno), wantRule: ruleUnmatched, verdict: record.VerdictRefused,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			sa := sockaddrUn(tc.path)
			f.put(addr, sa)
			for k, v := range tc.links {
				f.links[k] = v
			}
			l, sink := newTestLoop(t, f, testPolicy(tc.declared, write, nil))
			for k, v := range tc.symlinks {
				f.symlinks[k] = v
				// Planted after the loop was built, as an agent would: the declared entry keeps what it
				// resolved to then.
				f.links[k] = v
			}
			for i, p := range tc.runBound {
				f.bindsSocket(t, l, sockID{ino: uint64(9000 + i), cookie: uint64(1 + i)}, p)
			}
			if tc.closed {
				f.boundFiles = nil
			}
			f.diagErr = tc.diagErr
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
			got, _ := f.lastResp()
			if got.Error != tc.wantErrno || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Errorf("response = %+v, want error %d", got, tc.wantErrno)
			}
			switch {
			case tc.reached == "" && len(f.unixConnects) != 0:
				t.Errorf("reached %q, want no connect", f.unixConnects)
			case tc.reached != "" && (len(f.unixConnects) != 1 || f.unixConnects[0] != tc.reached):
				t.Errorf("reached %q, want %s", f.unixConnects, tc.reached)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.Rule != tc.wantRule || p.Dst != "unix:"+tc.path {
				t.Errorf("event = %s/%s dst %q, want %s/%s dst unix:%s", ev.Verdict, ev.Rule, p.Dst, tc.verdict, tc.wantRule, tc.path)
			}
			if len(f.tasksOpened) != 1 || f.tasksOpened[0] != 4242 {
				t.Errorf("task views opened for %v, want the trapping task 4242 once", f.tasksOpened)
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open (E28)", f.fdBalance())
			}
		})
	}
}

// TestUnixRelayFailsClosedWithoutTheTask: a relayed unix connect is made as the task or not at all. When
// the task's credentials cannot be read or taken, the connect is refused (relay-credentials) rather than
// made as this process, and a lookup that fails as the task is answered with that lookup's own errno.
//
// A walk this process cannot vouch for is refused path-unreliable, never answered as the task's own
// lookup: a magic link, which the relay refuses to follow where the task's lookup would have followed it,
// used to be answered with that ELOOP and recorded allow (I3: a relayed result is never fabricated); and a
// task in another mount tree could name, by an absolute path under a write entry, a socket whose inode lies
// anywhere, since the path the kernel reports for it was matched as if it were this process's own view.
func TestUnixRelayFailsClosedWithoutTheTask(t *testing.T) {
	const addr = 0x40000
	write := []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite}}
	sa := sockaddrUn("/work/app.sock")
	for _, tc := range []struct {
		name      string
		setup     func(f *fakeKernel)
		wantErrno int32
		wantRule  string
		verdict   record.Verdict
	}{
		{"the task's credentials cannot be read", func(f *fakeKernel) { f.taskErr = sys.ErrCredentials },
			-int32(refusalErrno), ruleRelayCredentials, record.VerdictRefused},
		{"no thread can take them", func(f *fakeKernel) { f.credsErr = sys.ErrCredentials },
			-int32(refusalErrno), ruleRelayCredentials, record.VerdictRefused},
		{"the lookup fails as the task", func(f *fakeKernel) { f.resolveErrs["/work/app.sock"] = unix.EACCES },
			-int32(unix.EACCES), "fs.write[/work/]", record.VerdictAllow},
		{"the socket does not exist", func(f *fakeKernel) { f.resolveErrs["/work/app.sock"] = unix.ENOENT },
			-int32(unix.ENOENT), "fs.write[/work/]", record.VerdictAllow},
		{"a magic link in the path", func(f *fakeKernel) { f.resolveErrs["/work/app.sock"] = unix.ELOOP },
			-int32(refusalErrno), rulePathUnreliable, record.VerdictRefused},
		{"another mount tree's socket, by an absolute name under the write entry", func(f *fakeKernel) {
			f.otherRoot = true
			f.otherView["/work/app.sock"] = true
		}, -int32(refusalErrno), rulePathUnreliable, record.VerdictRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, sa)
			tc.setup(f)
			l, sink := newTestLoop(t, f, testPolicy(nil, write, nil))
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
			if got, _ := f.lastResp(); got.Error != tc.wantErrno {
				t.Errorf("response = %+v, want error %d", got, tc.wantErrno)
			}
			if len(f.connects) != 0 {
				t.Errorf("connects = %q, want none", f.connects)
			}
			if ev := sink.one(t); ev.Verdict != tc.verdict || ev.Rule != tc.wantRule {
				t.Errorf("event = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.wantRule)
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open (E28)", f.fdBalance())
			}
		})
	}

	// R2: /proc/<tid> is keyed by a tid, so what TaskOf read is trusted only with the notification still
	// live after it. A target gone by then is not answered, and nothing it opened is left behind.
	f := newFake()
	f.put(addr, sa)
	l, sink := newTestLoop(t, f, testPolicy(nil, write, nil))
	g := &staleAfterTaskKernel{fakeKernel: f}
	l.k = g
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if f.respCount() != 0 || len(sink.all()) != 0 || len(f.connects) != 0 {
		t.Errorf("responses %d, events %d, connects %d after the target died across TaskOf, want none",
			f.respCount(), len(sink.all()), len(f.connects))
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open (E28)", f.fdBalance())
	}
}

// staleAfterTaskKernel makes the notification go stale the moment TaskOf has read the task.
type staleAfterTaskKernel struct{ *fakeKernel }

func (k *staleAfterTaskKernel) TaskOf(tid int) (taskView, error) {
	v, err := k.fakeKernel.TaskOf(tid)
	k.mu.Lock()
	k.stale[7] = true
	k.mu.Unlock()
	return v, err
}

// TestConnectUnixAsOnTheRealKernel drives the production relay against real sockets, unprivileged: the
// task is this process, so the credentials are its own and sys.RunAs runs inline. What it pins is the
// filesystem half — the walk, what admit is asked about, and which inode is connected.
func TestConnectUnixAsOnTheRealKernel(t *testing.T) {
	// Not t.TempDir: its test-named path does not fit in sun_path (108 bytes) once TMPDIR is as long as the
	// documented on-disk one, and the listeners bind by path.
	dir, outside := shortTempDir(t), shortTempDir(t)
	listen := func(p string) *countingListener {
		t.Helper()
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		c := &countingListener{accepted: make(chan struct{}, 16)}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				c.accepted <- struct{}{}
				_ = conn.Close()
			}
		}()
		t.Cleanup(func() { _ = ln.Close() })
		return c
	}
	inside := listen(filepath.Join(dir, "real.sock"))
	secret := listen(filepath.Join(outside, "secret.sock"))
	if err := os.Symlink(filepath.Join(outside, "secret.sock"), filepath.Join(dir, "esc.sock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.sock", filepath.Join(dir, "alias.sock")); err != nil {
		t.Fatal(err)
	}
	var k sysKernel
	task, err := k.TaskOf(os.Getpid())
	if err != nil {
		t.Fatalf("TaskOf: %v", err)
	}
	defer unix.Close(task.root) //nolint:errcheck // test cleanup
	defer unix.Close(task.cwd)  //nolint:errcheck // test cleanup
	if !task.sameRoot {
		t.Fatal("this process's own root does not compare equal to itself")
	}
	// A cwd that is not this process's: a relative path must be walked from the task's, not from here.
	cwd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(cwd) //nolint:errcheck // test cleanup
	task.cwd = cwd

	connect := func(sunPath string, admitIt bool) (string, unixOutcome, error) {
		t.Helper()
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // test cleanup
		asked := "(not asked)"
		// The sockaddr bytes are the abstract case's alone; a pathname is walked from sunPath.
		out, err := k.ConnectUnixAs(fd, task, nil, sunPath, func(resolved string, _ unixFile) bool {
			asked = resolved
			return admitIt
		})
		return asked, out, err
	}

	if asked, out, err := connect(filepath.Join(dir, "esc.sock"), false); asked != filepath.Join(outside, "secret.sock") || out != unixRefused || err != nil {
		t.Errorf("symlink out of the directory: admit asked about %q, outcome %d (%v); want the socket it points at, refused", asked, out, err)
	}
	if n := secret.count(); n != 0 {
		t.Errorf("the socket outside was connected %d time(s) though admit refused it", n)
	}
	if asked, out, err := connect("alias.sock", true); asked != filepath.Join(dir, "real.sock") || out != unixConnected || err != nil {
		t.Errorf("relative symlink from the task's cwd: admit asked about %q, outcome %d (%v)", asked, out, err)
	}
	if n := inside.count(); n != 1 {
		t.Errorf("the resolved socket accepted %d connection(s), want 1", n)
	}
	// A path longer than sun_path, relative to the task's cwd, is still reached through the descriptor.
	deep := dir
	for len(deep) < 2*sunPathMax {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	rel, _ := filepath.Rel(dir, filepath.Join(deep, "..", "..", "real.sock"))
	if err := os.Symlink(filepath.Join(dir, "real.sock"), filepath.Join(deep, "..", "..", "real.sock")); err != nil {
		t.Fatal(err)
	}
	if asked, out, err := connect(rel, true); asked != filepath.Join(dir, "real.sock") || out != unixConnected || err != nil {
		t.Errorf("long relative path: admit asked about %q, outcome %d (%v)", asked, out, err)
	}
	// Resolved here, /proc/self would be this process: a magic link in the path is refused before admit,
	// as unreliable — the task's own lookup would have followed it, so ELOOP is not its answer.
	pfd, err := unix.Open(filepath.Join(outside, "secret.sock"), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pfd) //nolint:errcheck // test cleanup
	if asked, out, err := connect("/proc/self/fd/"+strconv.Itoa(pfd), true); out != unixUnreliable || err != unix.ELOOP || asked != "(not asked)" {
		t.Errorf("magic link: admit asked about %q, outcome %d (%v), want unreliable with ELOOP before admit", asked, out, err)
	}
	if asked, out, err := connect(filepath.Join(dir, "missing.sock"), true); out != unixUnresolved || err != unix.ENOENT || asked != "(not asked)" {
		t.Errorf("missing socket: admit asked about %q, outcome %d (%v), want ENOENT", asked, out, err)
	}
	task.sameRoot = false
	if _, out, err := connect("real.sock", true); out != unixOtherRoot || err == nil {
		t.Errorf("relative path from a task with its own root: outcome %d (%v), want refused", out, err)
	}
	if n := secret.count(); n != 0 {
		t.Errorf("the socket outside was connected %d time(s)", n)
	}
}

// TestConnectUnixAsUnderSwapsConnectsOnlyTheInodeAdmitted is the relayed connect raced on the real kernel,
// unprivileged: while a sibling thread swaps what a name leads to — the last component's
// symlink exchanged between a socket inside the policy and one outside it, a directory's symlink exchanged the same
// way, and the directory a ".." climbs from moved between two parents by RENAME_EXCHANGE — each relayed connect asks
// admit about the inode its walk reached and connects that inode through /proc/self/fd/<n>, so whatever the swaps do,
// a connect is made only to the socket admit admitted: the outside listener accepts nothing, and the inside one
// accepts exactly the connects reported made. Admit sees both sockets in the symlink races, which shows the race ran.
func TestConnectUnixAsUnderSwapsConnectsOnlyTheInodeAdmitted(t *testing.T) {
	var k sysKernel
	for _, race := range []struct {
		name string
		// setup lays out dir, with its admitted socket at in and the other at out, and returns the name to connect
		// (relative to dir) and the two paths a RENAME_EXCHANGE swaps.
		setup func(t *testing.T, dir string) (name, x, y, in, out string)
	}{
		{"the last component's symlink", func(t *testing.T, dir string) (string, string, string, string, string) {
			mkdirs(t, dir, "a", "b")
			symlink(t, "a/s.sock", filepath.Join(dir, "s.sock"))
			symlink(t, "b/s.sock", filepath.Join(dir, "s.alt"))
			return "s.sock", filepath.Join(dir, "s.sock"), filepath.Join(dir, "s.alt"),
				filepath.Join(dir, "a", "s.sock"), filepath.Join(dir, "b", "s.sock")
		}},
		{"a directory's symlink", func(t *testing.T, dir string) (string, string, string, string, string) {
			mkdirs(t, dir, "a", "b")
			symlink(t, "a", filepath.Join(dir, "d"))
			symlink(t, "b", filepath.Join(dir, "d.alt"))
			return "d/s.sock", filepath.Join(dir, "d"), filepath.Join(dir, "d.alt"),
				filepath.Join(dir, "a", "s.sock"), filepath.Join(dir, "b", "s.sock")
		}},
		{"a .. through a directory moved to another parent", func(t *testing.T, dir string) (string, string, string, string, string) {
			// a/q and b/q each hold a chain of 8 directories, and the name walks down it and back up past q: when q is
			// exchanged with b's while the walk is below it, the last ".." climbs into b, where the spelling says a.
			mkdirs(t, dir, "a", "b")
			down, up := "", ""
			for i := range 8 {
				down += "/c" + strconv.Itoa(i)
				up += "../"
			}
			for _, q := range []string{"a/q", "b/q"} {
				if err := os.MkdirAll(filepath.Join(dir, q+down), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			return "a/q" + down + "/" + up + "../s.sock", filepath.Join(dir, "a", "q"), filepath.Join(dir, "b", "q"),
				filepath.Join(dir, "a", "s.sock"), filepath.Join(dir, "b", "s.sock")
		}},
		{"a .. through a directory renamed", func(t *testing.T, dir string) (string, string, string, string, string) {
			// a and b themselves are exchanged: the ".." climbs to the directory the walk looked up as a, under
			// whichever name it has by then.
			mkdirs(t, dir, "a", "b", "a/q", "b/q")
			return "a/q/../s.sock", filepath.Join(dir, "a"), filepath.Join(dir, "b"),
				filepath.Join(dir, "a", "s.sock"), filepath.Join(dir, "b", "s.sock")
		}},
	} {
		t.Run(race.name, func(t *testing.T) {
			dir := shortTempDir(t)
			name, x, y, in, out := race.setup(t, dir)
			inside, outside := listenCounting(t, in), listenCounting(t, out)
			var inID, outID unix.Stat_t
			if err := unix.Stat(in, &inID); err != nil {
				t.Fatal(err)
			}
			if err := unix.Stat(out, &outID); err != nil {
				t.Fatal(err)
			}
			task, err := k.TaskOf(os.Getpid())
			if err != nil {
				t.Fatalf("TaskOf: %v", err)
			}
			defer unix.Close(task.root) //nolint:errcheck // test cleanup
			defer unix.Close(task.cwd)  //nolint:errcheck // test cleanup
			cwd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(cwd) //nolint:errcheck // test cleanup
			task.cwd = cwd

			// The swapper is stopped and waited for before the subtest returns, whichever way it returns: a t.Fatalf
			// below would otherwise leave it renaming in a directory the test's cleanup removes, and its t.Errorf
			// after the subtest completed would panic the whole test binary.
			stop, done := make(chan struct{}), make(chan struct{})
			var halted sync.Once
			halt := func() { halted.Do(func() { close(stop); <-done }) }
			defer halt()
			go func() {
				defer close(done)
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if err := unix.Renameat2(unix.AT_FDCWD, x, unix.AT_FDCWD, y, unix.RENAME_EXCHANGE); err != nil {
						select {
						case <-stop: // stopped while the exchange ran: nothing to report
						default:
							t.Errorf("RENAME_EXCHANGE %s %s: %v", x, y, err)
						}
						return
					}
				}
			}()
			connected, askedIn, askedOut := 0, 0, 0
			deadline := time.Now().Add(3 * time.Second)
			for i := 0; i < 400 && time.Now().Before(deadline); i++ {
				fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				var asked unixFile
				outc, err := k.ConnectUnixAs(fd, task, nil, name, func(_ string, f unixFile) bool {
					asked = f
					return f.dev == inID.Dev && f.ino == inID.Ino
				})
				_ = unix.Close(fd)
				switch {
				case asked.dev == inID.Dev && asked.ino == inID.Ino:
					askedIn++
				case asked.dev == outID.Dev && asked.ino == outID.Ino:
					askedOut++
				}
				switch outc {
				case unixConnected:
					if err != nil {
						t.Fatalf("connect %d: connected with %v", i, err)
					}
					if asked.ino != inID.Ino || asked.dev != inID.Dev {
						t.Fatalf("connect %d: made after admit was asked about %+v, not the admitted socket", i, asked)
					}
					connected++
				case unixRefused, unixUnresolved, unixUnreliable:
					// Refused by admit, or a walk the swap broke (ENOENT, ELOOP, EAGAIN from a rename race): nothing
					// connected.
				default:
					t.Fatalf("connect %d: outcome %d (%v)", i, outc, err)
				}
			}
			halt()
			if n := outside.count(); n != 0 {
				t.Fatalf("the socket outside the policy accepted %d connection(s) while the names were swapped", n)
			}
			if n := inside.count(); n != connected {
				t.Fatalf("the admitted socket accepted %d connection(s), the relay reported %d made", n, connected)
			}
			t.Logf("%d connected; admit asked about the inside socket %d times and the outside one %d times", connected, askedIn, askedOut)
			// The walk below q is short, so the exchange lands inside it only sometimes; the other races alternate.
			if !strings.HasSuffix(race.name, "another parent") && (askedIn == 0 || askedOut == 0) {
				t.Fatalf("admit was asked about the inside socket %d and the outside one %d times: the swap was not raced", askedIn, askedOut)
			}
		})
	}
}

// mkdirs makes each of names under dir.
func mkdirs(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.Mkdir(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// symlink makes the symlink at p leading to target.
func symlink(t *testing.T, target, p string) {
	t.Helper()
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

// listenCounting is a stream listener at p whose accepted connections are counted and closed.
func listenCounting(t *testing.T, p string) *countingListener {
	t.Helper()
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	c := &countingListener{accepted: make(chan struct{}, 1024)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.accepted <- struct{}{}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

// shortTempDir is a temporary directory short enough to bind a socket in under any TMPDIR the house rules
// allow: os.MkdirTemp's own name, not t.TempDir's test-named one. It is returned resolved (realDir).
func shortTempDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "o")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return realDir(t, d)
}

// realDir is d with every symlink in it resolved. What these tests expect is the kernel's name for a file —
// the d_path a relayed connect's walk reports, and the symlink-free path sameInodeHere accepts — so a TMPDIR
// under a symlink (/home -> /var/home, say) must not reach an expectation unresolved.
func realDir(t testing.TB, d string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSameInodeHere pins the check a relayed unix connect's resolved path must pass before it is matched
// against the policy (R11): the path, walked in this process's own view with no symlink followed, reaches
// the inode the task's walk reached. The case it exists for — a task in another mount tree, for which the
// kernel reports a path that names another file here — needs a mount namespace, and is
// TestIntegrationUnixRelayOtherMountTree as root; this is the comparison itself on the real kernel.
func TestSameInodeHere(t *testing.T) {
	dir := realDir(t, t.TempDir())
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(a, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(a, &st); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{a, true},
		// Another file: the reported path names a different inode here.
		{b, false},
		// A symlink to it, or through a symlinked directory: a path the kernel reports has neither, so a
		// path that needs one to reach the inode is not this view's name for it.
		{filepath.Join(dir, "link"), false},
		{filepath.Join(dir, "dirlink", "a"), false},
		// Nothing there at all.
		{filepath.Join(dir, "missing"), false},
	} {
		if got := sameInodeHere(tc.path, &st); got != tc.want {
			t.Errorf("sameInodeHere(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// countingListener counts the connections a test listener accepted.
type countingListener struct{ accepted chan struct{} }

func (c *countingListener) count() int {
	deadline := time.After(50 * time.Millisecond)
	n := 0
	for {
		select {
		case <-c.accepted:
			n++
		case <-deadline:
			return n
		}
	}
}
