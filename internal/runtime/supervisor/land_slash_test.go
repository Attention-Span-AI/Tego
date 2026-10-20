// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestNameEndEndingInSlashIsTheNameInItsDirectory: an end a syscall makes, removes or renames in its directory
// (agent.LookupParent: filename_parentat, filename_create) is that directory's walk joined with the final name, a
// trailing slash or not. The kernel strips the slash and looks the name up in its directory without following it
// (lookup_one_qstr_excl): mkdir of a symlink spelled "lk/" is EEXIST, rmdir, unlink and a rename onto it are ENOTDIR,
// and Landlock's rmdir and rename hooks are asked at the symlink in its own directory. FSTarget took the whole-path
// walk for every end ending in "/", the rule of a path_lookupat end (an O_NOFOLLOW open of "lk/" opens where lk
// leads); compile's Land then followed a dangling out/dl/ to the target it takes as made later while the run's walk
// fell back to out/dl, and both decided out/lk/ on the link's target, out/ write entry or not. The kernel's own
// answers are asserted first: they are the reason.
//
// Spec: docs/p0/supervisor.md R15b; docs/p0/limits-check-doctor-cli.md R28.
func TestNameEndEndingInSlashIsTheNameInItsDirectory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	j := func(p ...string) string { return filepath.Join(append([]string{dir}, p...)...) }
	for _, d := range []string{"out/sub", "outside/d", "outside/d2"} {
		if err := os.MkdirAll(j(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(j("out", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"out/lk": "../outside/d", "out/dl": "../outside/new", "out/loop": "loop"} {
		if err := os.Symlink(target, j(link)); err != nil {
			t.Fatal(err)
		}
	}

	// The kernel acts on the name in its directory: nothing is made, removed or moved where a link leads.
	for _, k := range []struct {
		what string
		err  error
		want error
	}{
		{"mkdir out/dl/", unix.Mkdir(j("out", "dl")+"/", 0o755), unix.EEXIST},
		{"mkdir out/lk/", unix.Mkdir(j("out", "lk")+"/", 0o755), unix.EEXIST},
		{"mkdir out/loop/", unix.Mkdir(j("out", "loop")+"/", 0o755), unix.EEXIST},
		{"rmdir out/lk/", unix.Rmdir(j("out", "lk") + "/"), unix.ENOTDIR},
		{"unlink out/lk/", unix.Unlink(j("out", "lk") + "/"), unix.ENOTDIR},
		{"rename outside/d2 out/lk/", unix.Rename(j("outside", "d2"), j("out", "lk")+"/"), unix.ENOTDIR},
	} {
		if !errors.Is(k.err, k.want) {
			t.Fatalf("%s: the kernel answers %v, want %v", k.what, k.err, k.want)
		}
	}
	for _, p := range []string{j("outside", "d"), j("outside", "d2")} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s: %v after the kernel refused every call", p, err)
		}
	}
	if _, err := os.Lstat(j("outside", "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mkdir out/dl/ made the link's target: %v", err)
	}

	for _, tc := range []struct{ p, at string }{
		{j("out", "dl") + "/", j("out", "dl")},
		{j("out", "lk") + "/", j("out", "lk")},
		{j("out", "lk") + "//", j("out", "lk")},
		{j("out", "loop") + "/", j("out", "loop")},
		{j("out", "f") + "/", j("out", "f")},
		{j("out", "sub") + "/", j("out", "sub")},
		{j("out", "new") + "/", j("out", "new")},
		{j("out", "sub") + "/../lk/", j("out", "lk")},
	} {
		if at, err := Land(tc.p, agent.LookupParent); err != nil || at != tc.at {
			t.Errorf("compile's Land(%q) as a name-making end = %q, %v; the kernel acts on %q", tc.p, at, err, tc.at)
		}
		q := pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: tc.p, joined: cleanPath(tc.p)}.as(agent.LookupParent)
		if l, err := (sysKernel{}).FSTarget(q); err != nil || l.at != tc.at {
			t.Errorf("the run's walk of %q as a name-making end lands %q, %v; the kernel acts on %q", tc.p, l.at, err, tc.at)
		}
	}
}
