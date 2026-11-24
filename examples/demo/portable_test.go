// SPDX-License-Identifier: Apache-2.0

package demo

// These tests need no tego and no Landlock: they run demo.sh against a stand-in tego, in a stage and a resolver root of
// their own, and hold two things the kit promises to a presenter on any host. The contracts name the name-lookup
// sockets the host really has (C188), and the helpers the kit starts (the sink, the stand-in sockets) are known by
// the process itself, never by a pid number alone (C190).

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// plainKit is a stage, a stand-in tego and a free port, with the environment demo.sh runs under.
type plainKit struct {
	t     *testing.T
	stage string
	port  string
	env   []string
}

func newPlainKit(t *testing.T, extraEnv ...string) *plainKit {
	t.Helper()
	for _, tool := range []string{"python3", "sh", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "tego"), []byte("#!/bin/sh\necho tego stand-in\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	k := &plainKit{t: t, stage: filepath.Join(dir, "stage"), port: port}
	k.env = append([]string{"PATH=" + bin + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "DEMO_STAGE=" + k.stage,
		"DEMO_PORT=" + port, "LANG=C.UTF-8", "TERM=dumb"}, extraEnv...)
	t.Cleanup(func() { _, _ = k.demo("reset") })
	return k
}

func (k *plainKit) demo(args ...string) (string, error) {
	k.t.Helper()
	cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
	cmd.Env = k.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (k *plainKit) mustDemo(args ...string) string {
	k.t.Helper()
	out, err := k.demo(args...)
	if err != nil {
		k.t.Fatalf("demo.sh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// listen makes a unix socket at path, which stays up until the test ends.
func listen(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
}

// longestResolverSocket is the longest path, below the resolver root, that TestNameLookupSocketsAreTheHostsOwn binds a
// unix socket at.
const longestResolverSocket = "/run/systemd/userdb/io.systemd.DynamicUser"

// maxSocketPath is what a unix socket's path may hold: sun_path is 108 bytes with its NUL, and the test leaves a few
// bytes over.
const maxSocketPath = 100

// resolverRoot makes the folder the test lays the host's resolver sockets under (DEMO_RESOLVER_ROOT), removed when the
// test ends. The sockets sit at /run/systemd/... below it, so the root's own path must leave their length over: under a
// long TMPDIR (the public tree's cut test keeps its temporary files in a run folder of its own, 60 bytes before the
// test's own name) a socket's path passed sun_path and bind answered "invalid argument". The test then uses a short
// folder under /tmp, which the sockets need and nothing else of the test does.
func resolverRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "rr")
	if err != nil {
		t.Fatal(err)
	}
	if len(root)+len(longestResolverSocket) > maxSocketPath {
		_ = os.RemoveAll(root)
		if root, err = os.MkdirTemp("/tmp", "rr"); err != nil {
			t.Skipf("no folder with a short enough path for the resolver sockets: %v", err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

// TestNameLookupSocketsAreTheHostsOwn: the contracts that let curl through to the sink named one socket, nscd's, and
// a host whose C library asks systemd-resolved or the user database first showed net refusals the scene is not about.
// The kit now names the nscd socket (as it always did) and every resolver socket the host has, found under
// DEMO_RESOLVER_ROOT in these fixtures: a regular file or a socket with an unsafe name is never named.
func TestNameLookupSocketsAreTheHostsOwn(t *testing.T) {
	root := resolverRoot(t)
	k := newPlainKit(t, "DEMO_RESOLVER_ROOT="+root)
	const nscd = `"unix:/var/run/nscd/socket"`
	if got := strings.TrimSpace(k.mustDemo("lookup")); got != nscd {
		t.Errorf("a host with no resolver sockets: lookup = %s, want %s", got, nscd)
	}
	listen(t, filepath.Join(root, "run/systemd/resolve/io.systemd.Resolve"))
	listen(t, filepath.Join(root, "run/systemd/userdb/io.systemd.DynamicUser"))
	listen(t, filepath.Join(root, "run/systemd/userdb/io.systemd.Multiplexer"))
	listen(t, filepath.Join(root, "run/systemd/userdb/io.systemd.a b")) // a space would split the entry
	if err := os.WriteFile(filepath.Join(root, "run/systemd/userdb/io.systemd.NotASocket"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	want := nscd + `, "unix:/run/systemd/resolve/io.systemd.Resolve", "unix:/run/systemd/userdb/io.systemd.DynamicUser", ` +
		`"unix:/run/systemd/userdb/io.systemd.Multiplexer"`
	if got := strings.TrimSpace(k.mustDemo("lookup")); got != want {
		t.Errorf("lookup =\n%s\nwant\n%s", got, want)
	}
	// The stand-in agent's contract carries them, in place of the one line the file holds.
	k.mustDemo("setup")
	b, err := os.ReadFile(filepath.Join(k.stage, "project", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "allow: ["+want+"]") {
		t.Errorf("agent.yaml does not allow the host's lookup sockets:\n%s", b)
	}
}

// sleeper starts an unrelated process and returns its pid and its start time (field 22 of /proc/<pid>/stat).
func sleeper(t *testing.T) (int, string) {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	b, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat")
	if err != nil {
		t.Skip("no /proc")
	}
	rest := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	return cmd.Process.Pid, rest[19]
}

// alive says whether pid is a running process: one that ended and has not been waited for yet (a zombie of this
// test) is not.
func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	return strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))[0] != "Z"
}

// TestSinkIsKnownByTheProcessNotByItsPid: a pid file naming a live process that is not the sink was believed (kill -0
// said yes), so no sink was started and the act ran against a port nobody held; and a reset sent that process a TERM.
// Now the file holds the pid and the start time, and counts only for a process with that start time that runs sink.py
// and holds the listening socket.
func TestSinkIsKnownByTheProcessNotByItsPid(t *testing.T) {
	// sinkKit is a kit of its own for each case, whose sink is ended however the case ends.
	sinkKit := func(t *testing.T) (*plainKit, func() bool) {
		k := newPlainKit(t)
		t.Cleanup(func() { stopSinkOn(t, k.port) })
		return k, func() bool {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+k.port, time.Second)
			if err == nil {
				_ = c.Close()
			}
			return err == nil
		}
	}

	// The pid file as the kit used to write it (the pid alone) and as it writes it now (the pid and the start time): a
	// process that is no sink is no sink in either.
	forms := func(pid int, start string) map[string]string {
		return map[string]string{"pid alone": strconv.Itoa(pid) + "\n", "pid and start time": strconv.Itoa(pid) + " " + start + "\n"}
	}

	t.Run("a reset leaves an unrelated live process alone", func(t *testing.T) {
		for _, name := range []string{"pid alone", "pid and start time"} {
			t.Run(name, func(t *testing.T) {
				k, _ := sinkKit(t)
				other, start := sleeper(t)
				content := forms(other, start)[name]
				k.mustDemo("setup")
				if err := os.WriteFile(filepath.Join(k.stage, "sink.pid"), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				k.mustDemo("reset")
				if !alive(other) {
					t.Errorf("reset ended pid %d, an unrelated process the pid file (%s) named", other, name)
				}
			})
		}
	})

	t.Run("a pid file that names another process is not the sink", func(t *testing.T) {
		for _, name := range []string{"pid alone", "pid and start time"} {
			t.Run(name, func(t *testing.T) {
				k, listens := sinkKit(t)
				other, start := sleeper(t)
				content := forms(other, start)[name]
				k.mustDemo("setup")
				stopSinkOn(t, k.port) // the sink ends and a stranger holds its pid file
				if err := os.WriteFile(filepath.Join(k.stage, "sink.pid"), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				k.mustDemo("setup")
				if !listens() {
					t.Errorf("no sink listens on port %s: the live process the pid file named was taken for it", k.port)
				}
				if !alive(other) {
					t.Errorf("the unrelated process %d was ended", other)
				}
			})
		}
	})

	// forms is also what this case reads the file's own pid from.
	t.Run("a live pid with another start time is a reused pid", func(t *testing.T) {
		k, listens := sinkKit(t)
		k.mustDemo("setup")
		b, err := os.ReadFile(filepath.Join(k.stage, "sink.pid"))
		if err != nil {
			t.Fatal(err)
		}
		f := strings.Fields(string(b))
		if len(f) != 2 {
			t.Fatalf("sink.pid = %q, want a pid and a start time", b)
		}
		if err := os.WriteFile(filepath.Join(k.stage, "sink.pid"), []byte(f[0]+" 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := k.demo("setup"); err == nil || !strings.Contains(out, "it is not this demo's sink") {
			t.Errorf("setup with the sink's pid and a wrong start time: %v\n%s", err, out)
		}
		k.mustDemo("reset") // the file no longer proves the sink, so it is not stopped by it
		if !listens() {
			t.Error("reset stopped a process whose start time did not match the file")
		}
	})

	t.Run("a reset ends the sink it started even when DEMO_PORT has changed since", func(t *testing.T) {
		k, listens := sinkKit(t)
		k.mustDemo("setup")
		if !listens() {
			t.Fatal("setup did not start the sink")
		}
		other := newPlainKit(t) // a free port that is not the sink's
		k.env = append(k.env, "DEMO_PORT="+other.port)
		k.mustDemo("reset")
		time.Sleep(300 * time.Millisecond)
		if listens() {
			t.Error("the sink still listens after a reset under another DEMO_PORT")
		}
	})

	t.Run("a process that names sink.py and holds no port is not the sink", func(t *testing.T) {
		k, listens := sinkKit(t)
		script, err := filepath.Abs("sink.py")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("python3", "-c", "import time; time.sleep(300)", script, k.port)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		start := ""
		if b, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat"); err == nil {
			start = strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))[19]
		}
		k.mustDemo("setup") // lays the stage out (and starts a sink, ended next)
		stopSinkOn(t, k.port)
		for name, content := range forms(cmd.Process.Pid, start) {
			if err := os.WriteFile(filepath.Join(k.stage, "sink.pid"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			k.mustDemo("setup")
			if !listens() {
				t.Errorf("no sink listens on port %s: the idle process that only names sink.py was taken for it (%s)", k.port, name)
			}
			stopSinkOn(t, k.port)
		}
	})
}

// stopSinkOn ends the python3 process holding the loopback port, by the pid the kernel gives for the socket, for a test
// that has made the kit lose track of its sink.
func stopSinkOn(t *testing.T, port string) {
	t.Helper()
	out, err := exec.Command("python3", "-I", "-c", `import os, signal, sys
want = "0100007F:%04X" % int(sys.argv[1])
inodes = set()
for line in open("/proc/net/tcp").read().splitlines()[1:]:
    p = line.split()
    if p[1] == want and p[3] == "0A":
        inodes.add(p[9])
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        for fd in os.listdir("/proc/%s/fd" % pid):
            l = os.readlink("/proc/%s/fd/%s" % (pid, fd))
            if l.startswith("socket:[") and l[8:-1] in inodes and "sink.py" in open("/proc/%s/cmdline" % pid).read():
                os.kill(int(pid), signal.SIGTERM)
    except OSError:
        pass
`, port).CombinedOutput()
	if err != nil {
		t.Logf("stopSinkOn: %v %s", err, out)
	}
	time.Sleep(200 * time.Millisecond)
}
