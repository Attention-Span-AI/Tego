// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileTestUnixWalkAsTheRunGolden: a net.connect or net.send row to a unix pathname is landed with the run's own
// unix walk (supervisor.md R11, R11a: one lookup with every magic link refused, a landing on procfs refused), and a
// name that walk cannot land is answered as the run answers it. compile landed such
// names with the filesystem walk, which follows a magic link as compile itself, so a datagram and a connect through a
// link to /proc/self/cwd (rows 01, 02) or to /proc/self/root (03) read allow where the run refuses them
// path-unreliable; a name through a symlink loop (04, 05) or a file (06, 07) read the name's verdict, where the
// run refuses the datagram (path-unreliable, unix-absent) and the loop's connect (path-unreliable).
// A socket that does not exist yet is taken as the one the agent finds there when it calls, so a dangling link (08)
// and a missing socket beneath one (09) are answered where they lead. A datagram's absolute name that is not spelled
// canonically is refused rule unmatched at tiers cgroup and bpflsm (11, 12), where the run's kernel programs refuse
// it, and decided on its name and landing at tier landlock (10).
//
// A bind whose walk fails, with no listener policy,
// is the creation floor's (14), since the run continues it with no line, and is refused path-unreliable only under one
// (L1), where the run's bindUnix decides it; both read path-unreliable. A name through /proc/self/fd that the agent
// opens later (15, 16) is refused path-unreliable, as the run's walk meets the agent's magic link: it read allow or
// unix-absent, as compile itself held that descriptor or not.
//
// Design (ADR 0019's note of that date): a name is answered on the tree as
// it is plus what the agent makes for it, every directory its walk needs and the socket at a final name nothing needs
// as a directory. A name that ends on a directory, or on a file already there that is no socket, reaches no socket the
// run bound, and is decided there as the run decides it: refused unix-foreign through the write entry (17 to 27), the
// declared entry's where one resolves to it (28). A missing name ending in "/" or "/." (17 to 19), a dangling final
// link whose body does (20), a missing part the name walks into and back out of (21, 22), a directory already there by
// any name (23 to 26) and a regular file there (27) read allow, unix-absent or the name's verdict, where the run refuses
// them unix-foreign once the directory is there, and never admits a datagram to them in any state. A bind whose walk
// fails under a listener policy is bindUnix's path-unreliable at tiers landlock and cgroup (L1, L1c); in the bpflsm
// column the supervisor hands the bind to the plane, which never decides one whose lookup fails, so the row is answered
// on its spelling, as every row whose walk fails is (L1p; -2s4-3). The tree is built in a short
// temporary directory, so every bind and listen name fits sun_path whatever TMPDIR is (-2c4-2).
//
// Listen.yaml declared the listener beneath the file itself, a contract
// no decision-plane run starts under (the plane holds each declared listener's directory at prepare and refuses one
// that is not a directory), so L1p answered for a run that cannot exist. Its listener is now out/b.sock, a directory's
// name, and L1, L1c and L1p ask the bind beneath the file that no entry declares, the shape the run's half
// (TestPlaneRunBindLookupFailureIsTheKernels) binds: every column describes a run that starts.
//
// Spec: docs/p0/limits-check-doctor-cli.md R28.
func TestCompileTestUnixWalkAsTheRunGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	if _, err := os.Stat("/proc/self/root"); err != nil {
		t.Skip("no /proc: the walk cannot be made")
	}
	golden, err := filepath.Abs(filepath.Join("testdata", "compile-test-unix-walk.golden"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(golden)
	if err != nil && !*updateGolden {
		t.Fatal(err)
	}
	// The longest socket name the contracts and rows give a schema to check is <dir>/out/file/b.sock.
	dir := sunPathDir(t, "uw", len("/out/file/b.sock"))
	contract := fmt.Sprintf(`version: 0
name: unix-walk
command: ["sh", "agent.sh"]
fs:
  write: ["./out/"]
net:
  allow: ["127.0.0.1:8080", "unix:%[1]s/run/d.sock"]
record: summary
`, dir)
	table := fmt.Sprintf(`version: 0
tests:
  - {name: "01 a datagram through a link to /proc/self/cwd", action: net.send, path: "unix:%[1]s/out/cw/out/s.sock", expect: refused, rule: path-unreliable}
  - {name: "02 a connect through it", action: net.connect, path: "unix:%[1]s/out/cw/out/s.sock", expect: refused, rule: path-unreliable}
  - {name: "03 a datagram through a link to /proc/self/root", action: net.send, path: "unix:%[1]s/out/rt/s.sock", expect: refused, rule: path-unreliable}
  - {name: "04 a connect through a symlink loop", action: net.connect, path: "unix:%[1]s/out/loop/s.sock", expect: refused, rule: path-unreliable}
  - {name: "05 a datagram through it", action: net.send, path: "unix:%[1]s/out/loop/s.sock", expect: refused, rule: path-unreliable}
  - {name: "06 a datagram beneath a file", action: net.send, path: "unix:%[1]s/out/file/s.sock", expect: refused, rule: unix-absent}
  - {name: "07 a connect beneath it keeps the name's verdict", action: net.connect, path: "unix:%[1]s/out/file/s.sock", expect: allow, rule: "fs.write[./out/]"}
  - {name: "08 a connect to a dangling link, taken to its target", action: net.connect, path: "unix:%[1]s/out/dangle.sock", expect: refused, rule: unmatched}
  - {name: "09 a datagram to a missing socket beneath a link", action: net.send, path: "unix:%[1]s/out/lk/missing.sock", expect: refused, rule: unmatched}
  - {name: "10 a datagram to a name not spelled canonically, tier landlock", action: net.send, path: "unix:%[1]s/out/./s.sock", tier: landlock, expect: allow, rule: "fs.write[./out/]"}
  - {name: "11 the same at tier cgroup", action: net.send, path: "unix:%[1]s/out/./s.sock", tier: cgroup, expect: refused, rule: unmatched}
  - {name: "12 the same at tier bpflsm", action: net.send, path: "unix:%[1]s/out/./s.sock", tier: bpflsm, expect: refused, rule: unmatched}
  - {name: "13 control, a datagram through a symlink in the write entry to the declared socket", action: net.send, path: "unix:%[1]s/out/to-run/d.sock", expect: allow, rule: "net[unix:%[1]s/run/d.sock]"}
  - {name: "14 a bind beneath a file with no listener policy is the creation floor's, the kernel answering it", action: net.bind, path: "unix:%[1]s/out/file/b.sock", expect: allow, rule: unmatched}
  - {name: "15 a datagram to a name through /proc/self/fd that the agent opens later", action: net.send, path: "unix:%[1]s/out/fdl/987", expect: refused, rule: path-unreliable}
  - {name: "16 a connect to it", action: net.connect, path: "unix:%[1]s/out/fdl/987", expect: refused, rule: path-unreliable}
  - {name: "17 a datagram to a missing name ending in a slash, a directory once made", action: net.send, path: "unix:%[1]s/out/new.sock/", expect: refused, rule: unix-foreign}
  - {name: "18 a connect to it", action: net.connect, path: "unix:%[1]s/out/new.sock/", expect: refused, rule: unix-foreign}
  - {name: "19 a datagram to a missing name in a missing directory, ending in /.", action: net.send, path: "unix:%[1]s/out/sub/new.sock/.", expect: refused, rule: unix-foreign}
  - {name: "20 a datagram through a dangling link whose target ends in a slash", action: net.send, path: "unix:%[1]s/out/tsl", expect: refused, rule: unix-foreign}
  - {name: "21 a datagram to a missing directory the name walks into and back out of", action: net.send, path: "unix:%[1]s/out/x/y/..", expect: refused, rule: unix-foreign}
  - {name: "22 a connect to it", action: net.connect, path: "unix:%[1]s/out/x/y/../", expect: refused, rule: unix-foreign}
  - {name: "23 a datagram to a directory already there, named with a slash", action: net.send, path: "unix:%[1]s/out/d/", expect: refused, rule: unix-foreign}
  - {name: "24 a connect to it", action: net.connect, path: "unix:%[1]s/out/d/.", expect: refused, rule: unix-foreign}
  - {name: "25 a datagram to that directory by its plain name", action: net.send, path: "unix:%[1]s/out/d", expect: refused, rule: unix-foreign}
  - {name: "26 a datagram climbing out of a missing part back to it", action: net.send, path: "unix:%[1]s/out/d/z/..", expect: refused, rule: unix-foreign}
  - {name: "27 a datagram to a regular file already there", action: net.send, path: "unix:%[1]s/out/keep", expect: refused, rule: unix-foreign}
  - {name: "28 a directory the declared socket's name makes is the declared entry's", action: net.send, path: "unix:%[1]s/out/to-run/d.sock/", tier: landlock, expect: allow, rule: "net[unix:%[1]s/run/d.sock]"}
  - {name: "28c a connect to it, in every column", action: net.connect, path: "unix:%[1]s/out/to-run/d.sock/", expect: allow, rule: "net[unix:%[1]s/run/d.sock]"}
  - {name: "29 control, a missing plain name in a missing directory is the socket the agent binds", action: net.connect, path: "unix:%[1]s/out/x/y.sock", expect: allow, rule: "fs.write[./out/]"}
`, dir)
	listen := fmt.Sprintf(`version: 0
name: unix-walk-listen
command: ["sh", "agent.sh"]
fs:
  write: ["./out/"]
net:
  allow: ["127.0.0.1:8080"]
  listen: ["unix:%[1]s/out/b.sock"]
record: summary
`, dir)
	listenTable := fmt.Sprintf(`version: 0
tests:
  - {name: "L1 a bind beneath a file under a listener policy is refused path-unreliable, as bindUnix refuses it", action: net.bind, path: "unix:%[1]s/out/file/b.sock", tier: landlock, expect: refused, rule: path-unreliable}
  - {name: "L1c the same at tier cgroup", action: net.bind, path: "unix:%[1]s/out/file/b.sock", tier: cgroup, expect: refused, rule: path-unreliable}
  - {name: "L1p in the bpflsm column the plane never decides it: its spelling, which no listen entry names", action: net.bind, path: "unix:%[1]s/out/file/b.sock", tier: bpflsm, expect: refused, rule: unmatched}
  - {name: "L2 control, a declared bind in the write entry", action: net.bind, path: "unix:%[1]s/out/b.sock", expect: allow}
`, dir)
	for name, body := range map[string]string{"agent.yaml": contract, "verdicts.yaml": table, "listen.yaml": listen,
		"listen-verdicts.yaml": listenTable, "out/keep": "x", "out/file": "x", "out/d/keep": "x", "elsewhere/keep": "x",
		"run/keep": "x"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"out/cw": "/proc/self/cwd", "out/rt": "/proc/self/root" + dir + "/out",
		"out/loop": "loop", "out/lk": "../elsewhere", "out/dangle.sock": "../elsewhere/nothing.sock", "out/to-run": "../run",
		"out/fdl": "/proc/self/fd", "out/tsl": "nothing.sock/"} {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitOK {
		t.Errorf("exit %d, want %d\nstderr %s", code, identity.ExitOK, errs)
	}
	code, lout, errs := run(t, "compile", "--offline", "listen.yaml", "--test", "listen-verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	out = strings.ReplaceAll(out+"== listen.yaml\n"+lout, dir+"/", "<dir>/")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if code != identity.ExitOK {
		t.Errorf("exit %d, want %d\nstderr %s", code, identity.ExitOK, errs)
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// sunPathDir is a temporary directory, removed when t ends, every symlink in its name resolved, short enough that a
// socket name tail bytes long beneath it fits sun_path (107 bytes, which the contract's schema holds every unix: entry
// and bind name to): beneath TMPDIR when that leaves room, else beneath /tmp. A test's own TempDir name outgrew it
// beneath a TMPDIR of 40 bytes, and one beneath TMPDIR alone beneath one of 80 (-2c4-2).
func sunPathDir(t *testing.T, prefix string, tail int) string {
	t.Helper()
	const sunPathMax = 107
	for _, base := range []string{"", "/tmp"} {
		tmp, err := os.MkdirTemp(base, prefix)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(tmp) })
		dir, err := filepath.EvalSymlinks(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(dir)+tail <= sunPathMax {
			return dir
		}
	}
	t.Fatalf("no temporary directory leaves room for a %d-byte socket name in sun_path", tail)
	return ""
}

// TestCompileTestUnixJoinsThePhysicalCwd: a relative unix row is joined to compile's working directory as getcwd(2)
// reports it, every symlink resolved, as the run joins a relative sun_path to readlink /proc/<pid>/cwd (supervisor.md
// R6, R11); the name step then matches unix: entries by their declared spelling, the run's and compile's alike. From a
// directory reached through a symlink, compile joined $PWD's spelling, so a relative datagram or connect matched an
// entry spelled through that symlink and read allow where the run refuses it, rule unmatched.
//
// Spec: docs/p0/limits-check-doctor-cli.md R28.
func TestCompileTestUnixJoinsThePhysicalCwd(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	// The entry's socket name, <dir>/link/run/d.sock, must fit sun_path.
	dir := sunPathDir(t, "u", len("/link/run/d.sock"))
	for _, d := range []string{"real/run", "real/out"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	contract := fmt.Sprintf(`version: 0
name: unix-cwd
command: ["sh", "agent.sh"]
fs:
  write: ["./out/"]
net:
  allow: ["127.0.0.1:8080", "unix:%[1]s/run/d.sock"]
record: summary
`, link)
	table := fmt.Sprintf(`version: 0
tests:
  - {name: "01 a relative datagram", action: net.send, path: "unix:run/d.sock", expect: refused, rule: unmatched}
  - {name: "02 a relative connect", action: net.connect, path: "unix:run/d.sock", expect: refused, rule: unmatched}
  - {name: "03 control, the entry's own spelling", action: net.send, path: "unix:%[1]s/run/d.sock", expect: allow, rule: "net[unix:%[1]s/run/d.sock]"}
`, link)
	for name, body := range map[string]string{"agent.yaml": contract, "verdicts.yaml": table} {
		if err := os.WriteFile(filepath.Join(dir, "real", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(link) // and $PWD with it, which os.Getwd answers
	if wd, err := os.Getwd(); err != nil || wd != link {
		t.Fatalf("os.Getwd() = %q, %v; the test needs $PWD through the symlink, %q", wd, err, link)
	}
	buildsTiers(t, backend.TierLandlock)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock")
	if code != identity.ExitOK || !strings.Contains(out, "3 rows: 3 passed, 0 failed") {
		t.Errorf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitOK, out, errs)
	}
}
