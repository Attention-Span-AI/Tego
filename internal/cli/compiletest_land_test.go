// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileTestLandsAsTheKernelGolden: compile --test lands each row's path with the run's own walk (ADR 0019's
// 2026-10-17 design note), so a rename or a link through a dangling symlink to a directory the agent makes later, a
// write through a dangling final symlink, and a new name written with ".." after a symlink are answered where the
// kernel's walk lands them, in every column. compile answered them at the link's own spelling, or on the lexically
// cleaned path: allow for moves and links the kernel refuses with EXDEV (rows 01, 02, 07 to 10, 13), refused for a
// write the run allows (06), allow for one it refuses (04). A
// link's old name is looked up whole and not followed (link(2)'s
// filename_lookup), so one ending in "/." or "/.." after a symlink out of the write entry lands outside it and is
// refused (rows 15, 16), while a link of the symlink itself links the symlink (17); compile asked the old name as a
// name-making end, evaluated the symlink or the lexical clean, and answered rows 15 and 16 allow (design). An end a
// syscall makes or removes spelled with a trailing slash is the
// name in its directory, never followed (mkdir EEXIST, unlink, rmdir and a rename onto it ENOTDIR), so rows 18 to 21 are
// asked at the links out/dsym and out/el/ob inside the write entry; compile followed them out of it and answered refused
// where the run's line allows.
//
// Spec: docs/p0/agent-contract.md R15; docs/p0/limits-check-doctor-cli.md R28.
func TestCompileTestLandsAsTheKernelGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	golden, err := filepath.Abs(filepath.Join("testdata", "compile-test-kernel-walk.golden"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(golden)
	if err != nil && !*updateGolden {
		t.Fatal(err)
	}
	table, err := os.ReadFile(filepath.Join("testdata", "compile-test-kernel-walk.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := kernelWalkTree(t, string(table))
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitOK, out, errs)
	}
	out = strings.ReplaceAll(out, real+"/", "<dir>/")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// kernelWalkTree is compile-test-kernel-walk.yaml's project: fs.write out/, the exec.allow directory out/realbin/, and
// the links the table's comment names.
func kernelWalkTree(t *testing.T, table string) string {
	t.Helper()
	dir := t.TempDir()
	contract := `version: 0
name: kernel-walk
command: ["sh", "agent.sh"]
fs:
  write: ["./out/"]
exec:
  allow: ["sh", "./out/realbin/"]
record: summary
`
	files := map[string]string{"agent.yaml": contract, "verdicts.yaml": table, "out/x": "x", "out/y": "x", "out/z": "x",
		"out/w": "x", "out/realbin/sub/t": "x", "out/rb/t": "x", "out/el/t": "x", "ro/t": "x", "outside/t": "x", "outside/sub/t": "x"}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"out/dx": "realbin/later", "out/u": "realbin", "out/dsym": "../outside/new",
		"ro/dl": "../out/created", "out/lk": "realbin/sub", "out/el/bl": "../rb", "out/el/ob": "../../outside/sub"} {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestCompileTestSaysWhenARowCannotBeWalked: a row whose path the walk cannot land for this process's own sake (no
// /proc, EMFILE) is evaluated as written, and compile says so once on stderr, since its answer then rests on the
// spelling alone; a walk that fails as the agent's own lookup would (ENOTDIR) is the run's answer too and says
// nothing. Rows were resolved with filepath.EvalSymlinks where /proc was not mounted, a second resolver with
// its own answers (ADR 0019's 2026-10-17 design note).
//
// Spec: docs/p0/agent-contract.md R15.
func TestCompileTestSaysWhenARowCannotBeWalked(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	table := "version: 0\ntests:\n  - {action: fs.rename, path: out/x, dest: out/lk/../x, expect: allow}\n  - {action: fs.write, path: out/w, expect: allow}\n"
	for _, tc := range []struct {
		name string
		err  error
		note bool
	}{
		{"this process's EMFILE", unix.EMFILE, true},
		{"a lookup the agent's fails too", unix.ENOTDIR, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := kernelWalkTree(t, table)
			saved := land
			land = func(string, agent.Lookup) (string, error) { return "", tc.err }
			t.Cleanup(func() { land = saved })
			t.Chdir(dir)
			code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock")
			if code != identity.ExitOK {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
			// Evaluated as written: out/lk/../x cleans to out/x, which the write entry covers.
			if strings.Contains(out, "resolved to") || strings.Count(out, "PASS") != 2 {
				t.Errorf("rows not evaluated as written:\n%s", out)
			}
			note := "could not be walked as the kernel walks it"
			if got := strings.Count(errs, note); (got == 1) != tc.note || got > 1 {
				t.Errorf("stderr says %q %d times, want once: %v\n%s", note, got, tc.note, errs)
			}
		})
	}
}

// TestCompileTestSaysWhenAUnixNameCannotBeWalked: a connect's or a datagram's name the run's unix walk cannot be made
// for (this process's EMFILE) is decided on its spelling, and compile says so once on stderr, as for a filesystem row's
// path; a walk that met what the run refuses (a magic link) is the run's own answer, and says nothing. The contract
// has no net: section, so the run is in ADR 0070's unix-only state and decides the
// datagram's name as under a write entry: the walk the run refuses is refused path-unreliable, as the run refuses it.
//
// Spec: docs/p0/limits-check-doctor-cli.md R28.
func TestCompileTestSaysWhenAUnixNameCannotBeWalked(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	for _, tc := range []struct {
		name   string
		walk   agent.UnixWalk
		err    error
		note   bool
		expect string
	}{
		{"this process's EMFILE", agent.UnixWalkLookup, unix.EMFILE, true, "allow"},
		{"a walk the run refuses", agent.UnixWalkUnreliable, nil, false, "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := "version: 0\ntests:\n  - {action: net.send, path: \"unix:out/s.sock\", expect: " + tc.expect + "}\n"
			dir := kernelWalkTree(t, table)
			saved := landUnix
			landUnix = func(string) (agent.UnixLanding, error) { return agent.UnixLanding{Walk: tc.walk}, tc.err }
			t.Cleanup(func() { landUnix = saved })
			t.Chdir(dir)
			code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock")
			if code != identity.ExitOK || strings.Count(out, "PASS") != 1 {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
			note := "could not be walked as the kernel walks it"
			if got := strings.Count(errs, note); (got == 1) != tc.note || got > 1 {
				t.Errorf("stderr says %q %d times, want once: %v\n%s", note, got, tc.note, errs)
			}
		})
	}
}

// TestCompileExecJoinsThePhysicalCwd: compile --exec joins a relative command path to the working directory as
// getcwd(2) reports it, every symlink resolved, the directory the run joins the agent's relative exec path to
// (readlink /proc/<pid>/cwd), not $PWD, which spells it through the symlink the shell came by. Where the path's walk
// fails (ENOTDIR beneath a file) it is decided as written, joined to that directory: a deny_read entry spelled
// physically refuses it, and the logical spelling matched none. An earlier fix joined getcwd(2)'s directory here, and
// nothing held it.
//
// Spec: docs/p0/limits-check-doctor-cli.md R28; ADR 0048 (4).
func TestCompileExecJoinsThePhysicalCwd(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realDir, link := filepath.Join(dir, "real"), filepath.Join(dir, "link")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"f": "x", "agent.yaml": `version: 0
name: exec-cwd
command: ["sh", "agent.sh"]
fs:
  deny_read: ["` + realDir + `/f"]
net: {}
record: summary
`} {
		if err := os.WriteFile(filepath.Join(realDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	t.Chdir(link) // and $PWD with it, which os.Getwd answers
	if wd, err := os.Getwd(); err != nil || wd != link {
		t.Fatalf("os.Getwd() = %q, %v; the test needs $PWD through the symlink, %q", wd, err, link)
	}
	buildsTiers(t, backend.TierLandlock)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--exec", "./f/x", "--tier", "landlock")
	// The #! line is read at the path as joined, and the image floor decides it.
	if code != identity.ExitOK || !strings.Contains(out, "#! line not read: open "+realDir+"/") ||
		!strings.Contains(out, "landlock: refused fs.deny_read[") {
		t.Errorf("exit %d, want %d, the path joined to %s and refused by the deny_read entry spelled so\nstdout %s\nstderr %s",
			code, identity.ExitOK, realDir, out, errs)
	}
}
