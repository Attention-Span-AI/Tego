// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// shLoader is the PT_INTERP of the system shell, the dynamic binary every box has.
func shLoader(t *testing.T) string {
	t.Helper()
	interp, err := agent.ReadInterp("/bin/sh")
	if err != nil || interp == "" {
		t.Skipf("/bin/sh has no readable PT_INTERP: %q %v", interp, err)
	}
	return interp
}

func execRule(path, source string) agent.ExecRule {
	return agent.ExecRule{Raw: filepath.Base(path), Path: path, Basename: filepath.Base(path), Source: source, Verdict: agent.VerdictAllow}
}

// TestExecGrants asserts docs/p0/enforce-landlock.md E18.
func TestExecGrants(t *testing.T) {
	loader := shLoader(t)
	root := tempDir(t)
	mkTree(t, root, "tools/", "tools/t1")
	staticELF(t, filepath.Join(root, "static"))
	if err := os.WriteFile(filepath.Join(root, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "run.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data.bin"), []byte("not a script"), 0o755); err != nil {
		t.Fatal(err)
	}
	dirRule := execRule(filepath.Join(root, "tools"), agent.ExecSourceAllow)
	dirRule.IsDir = true
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		Exec: []agent.ExecRule{
			execRule("/bin/sh", agent.ExecSourceCommand+","+agent.ExecSourceAllow),
			execRule(filepath.Join(root, "run.sh"), agent.ExecSourceMCP+":tool"),
			execRule(filepath.Join(root, "run.py"), agent.ExecSourceAllow),
			execRule("/usr/bin/env", agent.ExecSourceInterpreter+":run.py"),
			execRule("/usr/bin/python3", agent.ExecSourceInterpreter+":run.py"),
			dirRule,
			execRule(filepath.Join(root, "static"), agent.ExecSourceAllow),
			execRule(filepath.Join(root, "data.bin"), agent.ExecSourceAllow),
		},
	}
	h, _ := prepare(t, 7, rt)
	cases := []struct {
		path string
		kind entryKind
		acc  accessFS
	}{
		{"/bin/sh", kindAgentCommand, execAccess},
		{loader, kindExecLoader, execAccess},
		{filepath.Join(root, "run.sh"), kindMCPCommand, execAccess},
		{filepath.Join(root, "run.py"), kindExecBinary, execAccess},
		{"/usr/bin/env", kindExecInterp, execAccess},
		{"/usr/bin/python3", kindExecInterp, execAccess},
		{filepath.Join(root, "tools"), kindExecDir, execAccess | accessReadDir},
		{filepath.Join(root, "static"), kindExecBinary, execAccess},
		{filepath.Join(root, "data.bin"), kindExecBinary, execAccess},
	}
	for _, tc := range cases {
		e, ok := h.entry(tc.path)
		if !ok || e.Kind != tc.kind || e.Access != tc.acc {
			t.Errorf("%s = %+v (held %v), want kind %s access %#x", tc.path, e, ok, kindName(tc.kind), tc.acc)
		}
	}
	// E18: no loader pre-scan inside a directory grant.
	if _, ok := h.entry(filepath.Join(root, "tools", "t1")); ok {
		t.Error("directory grant pre-scanned its contents")
	}
}

// TestExecInterpreterMissing is R5/E14: a script whose #! is not granted fails closed, naming both.
//
// Spec: docs/p0/enforce-landlock.md E14.
func TestExecInterpreterMissing(t *testing.T) {
	root := tempDir(t)
	script := filepath.Join(root, "run.py")
	direct := filepath.Join(root, "direct.py")
	blob := filepath.Join(root, "blob")
	crlf := filepath.Join(root, "crlf.py")       // binfmt_script execs "/usr/bin/python3\r": ENOENT
	crlfArg := filepath.Join(root, "crlfarg.py") // env gets "python3\r"
	twoWords := filepath.Join(root, "two.py")    // env gets "python3 -u", one argument
	for p, body := range map[string]string{script: "#!/usr/bin/env python3\n", direct: "#!/usr/bin/python3\n", blob: "no shebang here",
		crlf: "#!/usr/bin/python3\r\n", crlfArg: "#!/usr/bin/env python3\r\n", twoWords: "#!/usr/bin/env python3 -u\n"} {
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		rules []agent.ExecRule
		want  error
	}{
		{"no interpreter at all", []agent.ExecRule{execRule(script, agent.ExecSourceAllow)}, ErrInterpreterMissing},
		{"env but not python3", []agent.ExecRule{execRule(script, agent.ExecSourceAllow), execRule("/usr/bin/env", agent.ExecSourceAllow)}, ErrInterpreterMissing},
		{"python3 by basename elsewhere", []agent.ExecRule{execRule(script, agent.ExecSourceAllow), execRule("/usr/bin/env", agent.ExecSourceAllow), {Path: "/usr/bin/python3", Basename: "python3", Source: agent.ExecSourceAllow}}, nil},
		{"directory grant covers env, not the basename argument (same as compile)", []agent.ExecRule{execRule(script, agent.ExecSourceAllow), {Path: "/usr/bin", Basename: "bin", IsDir: true, Source: agent.ExecSourceAllow}}, ErrInterpreterMissing},
		{"directory grant covers a path interpreter", []agent.ExecRule{execRule(direct, agent.ExecSourceAllow), {Path: "/usr/bin", Basename: "bin", IsDir: true, Source: agent.ExecSourceAllow}}, nil},
		{"a CRLF #! names another file than the granted one", []agent.ExecRule{execRule(crlf, agent.ExecSourceAllow), {Path: "/usr/bin/python3", Basename: "python3", Source: agent.ExecSourceAllow}}, ErrInterpreterMissing},
		{"a CRLF #! gives env another argument than the granted one", []agent.ExecRule{execRule(crlfArg, agent.ExecSourceAllow), execRule("/usr/bin/env", agent.ExecSourceAllow), {Path: "/usr/bin/python3", Basename: "python3", Source: agent.ExecSourceAllow}}, ErrInterpreterMissing},
		{"env gets the whole remainder as one argument", []agent.ExecRule{execRule(twoWords, agent.ExecSourceAllow), execRule("/usr/bin/env", agent.ExecSourceAllow), {Path: "/usr/bin/python3", Basename: "python3", Source: agent.ExecSourceAllow}}, ErrInterpreterMissing},
		{"non-script non-ELF is left to execve", []agent.ExecRule{execRule(blob, agent.ExecSourceAllow)}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Contract: contractWith(true, true), Exec: tc.rules}
			if tc.want == nil {
				prepare(t, 7, rt)
				return
			}
			err := prepareErr(t, 7, rt, nil)
			if !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
		})
	}
}

// TestExecCoversResolved is R5's interpreter check asked where the kernel asks it. execve follows the
// #! path's symlinks and hold follows each rule's, so coverage is a question about resolved paths: a
// script under a symlinked exec.allow directory is granted by the recursive rule on the directory's
// target, an interpreter named through a symlinked file rule is that rule's inode, and an interpreter
// that is a symlink out of a granted directory lands where no rule reaches (E14: Prepare names it
// instead of execve failing with EACCES). A grant that shares only the basename changes none of that for
// an absolute #!: the tier cannot match by name (SEMANTICS §4), so a basename covers env's bare argument
// alone.
func TestExecCoversResolved(t *testing.T) {
	root, err := filepath.EvalSymlinks(tempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	mkTree(t, root, "real/bin/", "tools/", "elsewhere/", "other/", "linked/")
	interp := filepath.Join(root, "real", "bin", "interp")
	staticELF(t, interp)
	staticELF(t, filepath.Join(root, "elsewhere", "py"))
	otherPy := filepath.Join(root, "other", "py") // shares only the basename with tools/py's target
	staticELF(t, otherPy)
	if err := os.Link(otherPy, filepath.Join(root, "linked", "py")); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(root, "bin"):         filepath.Join(root, "real", "bin"),
		filepath.Join(root, "py3"):         interp,
		filepath.Join(root, "tools", "py"): filepath.Join(root, "elsewhere", "py"),
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	script := func(name, shebang string) agent.ExecRule {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("#!"+shebang+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return execRule(p, agent.ExecSourceAllow)
	}
	dir := func(p string) agent.ExecRule {
		r := execRule(p, agent.ExecSourceAllow)
		r.IsDir = true
		return r
	}
	cases := []struct {
		name  string
		rules []agent.ExecRule
		want  error
	}{
		{"#! under a symlinked exec.allow directory", []agent.ExecRule{script("a.sh", interp), dir(filepath.Join(root, "bin"))}, nil},
		{"#! is a file rule's target, named another way", []agent.ExecRule{script("b.sh", interp), execRule(filepath.Join(root, "py3"), agent.ExecSourceAllow)}, nil},
		{"#! is a symlink out of a granted directory", []agent.ExecRule{script("c.sh", filepath.Join(root, "tools", "py")), dir(filepath.Join(root, "tools"))}, ErrInterpreterMissing},
		{"#! is a symlink out of a granted directory, and another py is granted", []agent.ExecRule{script("e.sh", filepath.Join(root, "tools", "py")), dir(filepath.Join(root, "tools")), execRule(otherPy, agent.ExecSourceAllow)}, ErrInterpreterMissing},
		{"#! shares only its basename with a file rule", []agent.ExecRule{script("f.sh", filepath.Join(root, "elsewhere", "py")), execRule(otherPy, agent.ExecSourceAllow)}, ErrInterpreterMissing},
		{"env's bare argument still matches by basename", []agent.ExecRule{script("d.sh", "/usr/bin/env interp"), execRule("/usr/bin/env", agent.ExecSourceAllow), execRule(interp, agent.ExecSourceAllow)}, nil},
		// env execvp()s an argument with a slash as a cwd-relative path, not by PATH: a same-basename
		// grant is a match by name, and Prepare cannot know the cwd the exec runs in.
		{"env's relative argument with a slash is not a bare name", []agent.ExecRule{script("g.sh", "/usr/bin/env sub/py"), execRule("/usr/bin/env", agent.ExecSourceAllow), execRule(otherPy, agent.ExecSourceAllow)}, ErrInterpreterMissing},
		// The same inode under another name is refused on purpose: agent.Evaluate cannot see inodes and
		// reports the script refused, so Prepare agrees with it.
		{"#! is a hardlink of a granted file under another name", []agent.ExecRule{script("h.sh", filepath.Join(root, "linked", "py")), execRule(otherPy, agent.ExecSourceAllow)}, ErrInterpreterMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Contract: contractWith(true, true), Exec: tc.rules}
			if tc.want == nil {
				prepare(t, 7, rt)
				return
			}
			if err := prepareErr(t, 7, rt, nil); !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
		})
	}
}

// TestExecShadowedBasename is E16/E17: two same-named binaries at different inodes are two grants; a
// symlink to one of them is the same inode and adds nothing.
//
// Spec: docs/p0/enforce-landlock.md E16, E17.
func TestExecShadowedBasename(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "venv/bin/", "shim/")
	staticELF(t, filepath.Join(root, "shim", "python"))
	if err := os.Symlink("/bin/sh", filepath.Join(root, "venv", "bin", "python")); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: contractWith(true, true), Exec: []agent.ExecRule{
		execRule("/bin/sh", agent.ExecSourceAllow),
		execRule(filepath.Join(root, "shim", "python"), agent.ExecSourceAllow),
		execRule(filepath.Join(root, "venv", "bin", "python"), agent.ExecSourceAllow),
	}}
	h, _ := prepare(t, 7, rt)
	if _, ok := h.entry(filepath.Join(root, "shim", "python")); !ok {
		t.Error("shim not granted separately")
	}
	if _, ok := h.entry(filepath.Join(root, "venv", "bin", "python")); ok {
		t.Error("venv symlink held as a separate inode")
	}
	sh, _ := h.entry("/bin/sh")
	if sh.Access != execAccess {
		t.Errorf("/bin/sh = %+v", sh)
	}
}

func TestExecVanished(t *testing.T) {
	rt := &agent.RuleTable{Contract: contractWith(true, true), Exec: []agent.ExecRule{execRule("/nonexistent/binary", agent.ExecSourceAllow)}}
	if err := prepareErr(t, 7, rt, nil); !errors.Is(err, ErrPathVanished) {
		t.Errorf("vanished exec: %v", err)
	}
}

// TestExecAllowOnAFIFOOrDeviceFailsTheBuild is LL-E21: an exec.allow entry naming a FIFO or a device node is
// no binary; Prepare fails with ErrRulesetBuild rather than granting EXECUTE on it (or blocking on the FIFO's
// open while it reads the entry's ELF header).
//
// Spec: docs/p0/enforce-landlock.md E21.
func TestExecAllowOnAFIFOOrDeviceFailsTheBuild(t *testing.T) {
	fifo := filepath.Join(tempDir(t), "pipe")
	if err := unix.Mkfifo(fifo, 0o755); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	for _, target := range []string{fifo, "/dev/null"} {
		t.Run(filepath.Base(target), func(t *testing.T) {
			rt := &agent.RuleTable{Contract: contractWith(true, true), Exec: []agent.ExecRule{execRule(target, agent.ExecSourceAllow)}}
			done := make(chan error, 1)
			go func() {
				h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{})
				if err == nil {
					_ = h.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrRulesetBuild) {
					t.Errorf("exec.allow %s: Prepare = %v, want ErrRulesetBuild", target, err)
				} else if !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("exec.allow %s: Prepare = %v, want it to name the file type", target, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("exec.allow %s: Prepare did not return in 5 s (blocked opening it?)", target)
			}
		})
	}
}

func TestExecKind(t *testing.T) {
	cases := []struct {
		src  string
		dir  bool
		want entryKind
	}{
		{agent.ExecSourceCommand, false, kindAgentCommand},
		{agent.ExecSourceCommand + "," + agent.ExecSourceAllow, false, kindAgentCommand},
		{agent.ExecSourceMCP + ":db", false, kindMCPCommand},
		{agent.ExecSourceInterpreter + ":agent.py", false, kindExecInterp},
		{agent.ExecSourceAllow, false, kindExecBinary},
		{agent.ExecSourceAllow, true, kindExecDir},
		{"", false, kindExecBinary},
	}
	for _, tc := range cases {
		if got := execKind(agent.ExecRule{Source: tc.src, IsDir: tc.dir}); got != tc.want {
			t.Errorf("execKind(%q, dir=%v) = %s, want %s", tc.src, tc.dir, kindName(got), kindName(tc.want))
		}
	}
}

// TestExecLoaderRefused is R5/E29: the PT_INTERP string is read out of the binary at Prepare time
// (E14, live), so an agent that can write a granted binary chooses which path receives
// EXECUTE|READ_FILE on the next run. Every choice that lands on ground the contract governs, or on
// something that is not a regular file, fails closed instead of becoming a rule.
func TestExecLoaderRefused(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secrets/id_ed25519", "proj/evil", "lib/ld.so", "bin/")
	secrets, proj := filepath.Join(root, "secrets"), filepath.Join(root, "proj")
	secretFile := filepath.Join(secrets, "id_ed25519")
	alias := filepath.Join(root, "alias")
	if err := os.Link(secretFile, alias); err != nil {
		t.Skipf("hardlink unsupported here: %v", err)
	}
	bin := filepath.Join(root, "bin", "tool")
	cases := []struct {
		name   string
		interp string
		fs     []agent.FSRule
		want   error
	}{
		{"loader inside a deny_read target", secretFile, []agent.FSRule{fsRule(agent.FSDenyRead, secrets)}, ErrLoaderRefused},
		{"loader is the deny_read target itself", secrets, []agent.FSRule{fsRule(agent.FSDenyRead, secrets)}, ErrLoaderRefused},
		{"loader reaches the target through a hardlink", alias, []agent.FSRule{fsRule(agent.FSDenyRead, secretFile)}, ErrLoaderRefused},
		{"loader aliases a child of a denied directory", alias, []agent.FSRule{fsRule(agent.FSDenyRead, secrets)}, ErrLoaderRefused},
		{"multiply linked loader without denials", alias, nil, nil},
		{"multiply linked loader with unrelated file denial", alias, []agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(proj, "evil"))}, nil},
		{"loader under a write entry", filepath.Join(proj, "evil"), []agent.FSRule{fsRule(agent.FSWrite, proj)}, ErrLoaderRefused},
		{"loader is a directory", filepath.Join(root, "lib"), nil, ErrLoaderRefused},
		// fs.write "/" covers every loader: the whole filesystem is agent-writable, so the loader is refused as
		// under any narrower write entry, never passed because "/"+"/" prefixes no path.
		{"loader under a write entry of /", filepath.Join(root, "lib", "ld.so"), []agent.FSRule{fsRule(agent.FSWrite, "/")}, ErrLoaderRefused},
		{"loader under an ask entry of /", filepath.Join(root, "lib", "ld.so"), []agent.FSRule{fsRule(agent.FSAsk, "/")}, ErrLoaderRefused},
		{"ordinary loader", filepath.Join(root, "lib", "ld.so"), []agent.FSRule{fsRule(agent.FSDenyRead, secrets)}, nil},
		// Opened here, /proc/self/exe is tego's own executable (agent-contract.md R8a).
		{"loader is /proc/self/exe", "/proc/self/exe", nil, ErrLoaderRefused},
		{"loader leads through /proc", filepath.Join(root, "selfexe"), nil, ErrLoaderRefused},
	}
	if err := os.Symlink("/proc/self/exe", filepath.Join(root, "selfexe")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dynamicELF(t, bin, tc.interp)
			rt := &agent.RuleTable{Contract: contractWith(true, true), FS: tc.fs, Exec: []agent.ExecRule{execRule(bin, agent.ExecSourceAllow)}}
			if tc.want != nil {
				if err := prepareErr(t, 7, rt, nil); !errors.Is(err, tc.want) {
					t.Errorf("error %v, want %v", err, tc.want)
				}
				return
			}
			h, _ := prepare(t, 7, rt)
			if e, ok := h.entry(tc.interp); !ok || e.Access != execAccess {
				t.Errorf("loader %s = %+v (held %v), want effective access %#x", tc.interp, e, ok, execAccess)
			}
		})
	}
}

// TestDeputyExecGrant is ADR 0041 D2's runtime exec grant: a table whose held opens need the open deputy
// (gate.completion: held with an escalating fs rule) and whose domain handles EXECUTE holds tego's own binary with
// EXECUTE|READ_FILE, so the child stage can exec the deputy after landlock_restrict_self. A table that holds nothing,
// and one with no exec: section (which executes what it reads), get no grant.
func TestDeputyExecGrant(t *testing.T) {
	root := tempDir(t)
	bin := filepath.Join(root, "tego")
	staticELF(t, bin)
	prev := deputyExecutable
	deputyExecutable = func() (string, error) { return bin, nil }
	t.Cleanup(func() { deputyExecutable = prev })
	g, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "*.env", Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	table := func(held, execSection bool) *agent.RuleTable {
		p := g
		if held {
			p = g.WithHeldCompletion()
		}
		return &agent.RuleTable{Contract: contractWith(execSection, true), Gate: p,
			Exec: []agent.ExecRule{execRule("/bin/sh", agent.ExecSourceCommand)}}
	}
	h, _ := prepare(t, 7, table(true, true))
	if e, ok := h.entry(bin); !ok || e.Kind != kindDeputy || e.Access != execAccess {
		t.Fatalf("tego binary = %+v (held %v), want kind %s access %#x", e, ok, kindName(kindDeputy), execAccess)
	}
	h, _ = prepare(t, 7, table(false, true))
	if _, ok := h.entry(bin); ok {
		t.Fatal("copied completion granted the deputy's exec")
	}
	h, _ = prepare(t, 7, table(true, false))
	if e, ok := h.entry(bin); ok && e.Kind == kindDeputy {
		t.Fatal("an unrestricted exec table held a deputy grant it does not need")
	}
}
