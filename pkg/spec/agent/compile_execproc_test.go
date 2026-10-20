// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompileRefusesProcExecEntries is R8a, the Codex POC's F3: exec.allow /proc/self/exe compiled without a word
// and resolved, in compile's process, to tego's own executable, so a contract whose only entry was it let the agent
// start `tego version`. An exec entry that is, or leads through, a /proc path is an exec-proc error, whatever
// spelling reaches it: the path itself, a link to it (/dev/stdin is one), or a PATH directory that is one.
func TestCompileRefusesProcExecEntries(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.root, "self-exe")
	if err := os.Symlink("/proc/self/exe", link); err != nil {
		t.Fatal(err)
	}
	procBin := filepath.Join(f.root, "procbin")
	if err := os.Symlink("/proc/self/cwd", procBin); err != nil {
		t.Fatal(err)
	}
	chain := dotDotChain(t, f.root)
	// An ELF whose PT_INTERP is /proc/self/exe, or a link to it: compile, Landlock's holdLoader and the cgroup
	// listener resolve the loader in tego's own process.
	procLoader := filepath.Join(f.root, "elf")
	if err := os.WriteFile(procLoader, elf64("/proc/self/exe", 2), 0o755); err != nil {
		t.Fatal(err)
	}
	linkLoader := filepath.Join(f.root, "elf-link")
	if err := os.WriteFile(linkLoader, elf64(link, 2), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, yaml string
		extra      []CompileOption
	}{
		{"exec.allow /proc/self/exe", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [/proc/self/exe]\n", nil},
		{"exec.allow /proc/<pid>/exe", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [/proc/1/exe]\n", nil},
		{"the command", "version: 0\nname: a\ncommand: [/proc/self/exe, version]\n", nil},
		{"a link to /proc/self/exe", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [" + link + "]\n", nil},
		{"a command pattern's word", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"/proc/self/exe version\"]\n", nil},
		// s/a -> b/../proc with s/b -> /: the kernel follows b before it applies "..", a lexical clean does not.
		{"a link chain through ..", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [" + chain + "]\n", nil},
		{"an ELF loader that is /proc/self/exe", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [" + procLoader + "]\n", nil},
		{"an ELF loader that links to /proc/self/exe", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [" + linkLoader + "]\n", nil},
		{"the command's ELF loader", "version: 0\nname: a\ncommand: [" + procLoader + "]\n", nil},
		// A bare name found in a PATH directory that is /proc/self/cwd: the program's directory is the opener's.
		{"a PATH directory through /proc", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [agent.yaml]\n",
			[]CompileOption{WithPATH(procBin)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := f.load(tc.yaml)
			opts := tc.extra
			if tc.name == "a PATH directory through /proc" {
				// compile's own cwd is the project, where agent.yaml lies; make it executable so PATH would find it.
				if err := os.Chmod(filepath.Join(f.project, "agent.yaml"), 0o755); err != nil {
					t.Fatal(err)
				}
				t.Chdir(f.project)
			}
			rt, ds, err := Compile(c, f.machine, f.opts(opts...)...)
			if err == nil || rt != nil || !hasCode(ds, CodeExecProc) || !HasErrors(ds) {
				t.Fatalf("no exec-proc error (err=%v):\n%s", err, render(ds))
			}
			for _, d := range ds {
				if d.Code == CodeExecProc && (!strings.Contains(d.Message, "/proc") || d.Fix == "") {
					t.Errorf("the refusal does not name the /proc path or a fix: %+v", d)
				}
			}
		})
	}
}

// dotDotChain makes dir/s/b -> / and dir/s/a -> b/../proc and returns dir/s/a/self/exe, a spelling of
// /proc/self/exe only a walk that follows b before it applies ".." finds.
func dotDotChain(t *testing.T, dir string) string {
	t.Helper()
	s := filepath.Join(dir, "s")
	if err := os.Mkdir(s, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(s, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b/../proc", filepath.Join(s, "a")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s, "a", "self", "exe")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the chain does not reach /proc/self/exe: %v", err)
	}
	return p
}
