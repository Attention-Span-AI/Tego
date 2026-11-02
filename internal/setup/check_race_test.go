// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestApplyRefusesALinkSwappedInAfterTheCheck: Draft checks the project and names the folders to make; a process of
// the same uid then swaps a path component for a symbolic link to a folder outside the project, before Apply. Apply
// refuses with an error naming the link, makes no folder outside the project (where the link leads), and leaves none
// of its own behind in it.
func TestApplyRefusesALinkSwappedInAfterTheCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		// swap replaces a component of dir with a link to outside and returns the link's path.
		swap func(t *testing.T, dir, outside string) string
	}{
		{"a folder inside the project", func(t *testing.T, dir, outside string) string {
			return swapForLink(t, filepath.Join(dir, "src"), outside)
		}},
		{"a folder Create would make", func(t *testing.T, dir, outside string) string {
			link := filepath.Join(dir, ".tego")
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		// Making folders by path, Create made nothing outside here either: os.Mkdir answered EEXIST for the link, in an
		// error that named no link. The other four cases made folders where the link led.
		{"a dangling link where Create would make a folder", func(t *testing.T, dir, outside string) string {
			link := filepath.Join(dir, ".tego")
			if err := os.Symlink(filepath.Join(outside, "not-yet"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{"the project folder itself", func(t *testing.T, dir, outside string) string {
			return swapForLink(t, dir, outside)
		}},
		{"a folder above the project", func(t *testing.T, dir, outside string) string {
			return swapForLink(t, filepath.Dir(dir), outside)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(project(t, "parent/proj/src/"), "parent", "proj") // a folder above it to swap too
			outside := t.TempDir()
			env := CheckEnv{Options: []agent.CompileOption{agent.WithPATH("/usr/bin:/bin"), agent.WithHome(t.TempDir())}}
			r, err := Draft(Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src/deep"}, Name: "p", Dir: dir, Command: "sh -c true"}, env)
			if err != nil || !r.OK {
				t.Fatalf("Draft: %v %v", err, r.Diagnostics)
			}
			if want := []string{filepath.Join(dir, "src", "deep"), filepath.Join(dir, ".tego", "tmp")}; !slices.Equal(r.MakeDirs, want) {
				t.Fatalf("MakeDirs = %q, want %q", r.MakeDirs, want)
			}

			link := tc.swap(t, dir, outside)
			made, _, ok, err := Apply(r, dir, env)
			if err == nil || ok || made != nil {
				t.Fatalf("Apply through a swapped-in link: made %q, ok %v, err %v", made, ok, err)
			}
			if !strings.Contains(err.Error(), link+" is a symbolic link") {
				t.Errorf("the error does not name the link %s: %v", link, err)
			}
			if strings.Contains(err.Error(), "yourself") { // made by hand through the link, the folder lands where it leads
				t.Errorf("the error offers to make the folder through the link: %v", err)
			}
			if es, _ := os.ReadDir(outside); len(es) > 0 {
				t.Errorf("a folder was made outside the project, in %s where the link leads: %v", outside, es)
			}
			if _, err := os.Lstat(filepath.Join(dir, "src", "deep")); err == nil {
				t.Error("Apply left src/deep behind in the project")
			}
		})
	}
}

// swapForLink moves the folder p aside (to p.moved) and puts a symbolic link to target in its place, as a process of
// the same uid could between a check and a use; it returns p.
func swapForLink(t *testing.T, p, target string) string {
	t.Helper()
	if err := os.Rename(p, p+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCreateMakesNothingThroughAFile: a component that is a file, not a folder, stops Create with an error naming
// it, and nothing is made.
func TestCreateMakesNothingThroughAFile(t *testing.T) {
	dir := project(t, "notes")
	made, err := Create(&Result{MakeDirs: []string{filepath.Join(dir, "notes", "deep")}}, dir)
	if err == nil || made != nil || !strings.Contains(err.Error(), filepath.Join(dir, "notes")+" is not a folder") {
		t.Fatalf("Create through a file: made %q, err %v", made, err)
	}
}

// TestCreateOutsideTheProject: a folder outside the project (Claude Code's socket folder under the runtime directory)
// is made beneath its nearest existing parent, which may be reached through a link of its own: no check came before,
// so that parent is resolved once. Every folder made is returned by its absolute path, parent first. A link where
// Create would make a folder is refused, and nothing is made where it leads.
func TestCreateOutsideTheProject(t *testing.T) {
	dir := project(t)
	base := t.TempDir()
	viaLink := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink(base, viaLink); err != nil {
		t.Fatal(err)
	}
	made, err := Create(&Result{MakeDirs: []string{filepath.Join(viaLink, "a", "b")}}, dir)
	if want := []string{filepath.Join(viaLink, "a"), filepath.Join(viaLink, "a", "b")}; err != nil || !slices.Equal(made, want) {
		t.Fatalf("Create = %q, %v; want %q", made, err, want)
	}
	if fi, err := os.Stat(filepath.Join(base, "a", "b")); err != nil || !fi.IsDir() {
		t.Fatalf("a/b not made in %s: %v", base, err)
	}

	elsewhere := t.TempDir()
	if err := os.Symlink(filepath.Join(elsewhere, "not-yet"), filepath.Join(base, "socks")); err != nil {
		t.Fatal(err)
	}
	made, err = Create(&Result{MakeDirs: []string{filepath.Join(base, "socks", "sub")}}, dir)
	if err == nil || made != nil || !strings.Contains(err.Error(), filepath.Join(base, "socks")+" is a symbolic link") {
		t.Fatalf("Create through a link outside the project: made %q, err %v", made, err)
	}
	if es, _ := os.ReadDir(elsewhere); len(es) > 0 {
		t.Errorf("a folder was made where the link leads: %v", es)
	}
}

// TestRemoveNeverThroughALinkNorAFile: Remove takes away what Create made while it is still an empty folder where
// Create made it, the deepest first, and nothing else. A folder swapped since for a file is left (a removal by path
// unlinked the file), and so is everything past a link swapped in on the way (it removed the empty folders of the
// same names where the link leads); a folder that holds anything stays, as one that was there before does. A folder
// made outside the project through a link of its own is removed beneath that link's target, as it was made.
func TestRemoveNeverThroughALinkNorAFile(t *testing.T) {
	dir := project(t, "src/")
	made, err := Create(&Result{MakeDirs: []string{filepath.Join(dir, "src", "deep"), filepath.Join(dir, ".tego", "tmp"),
		filepath.Join(dir, ".tego", "claude"), filepath.Join(dir, "kept", "full")}}, dir)
	if want := []string{"src/deep", ".tego", ".tego/tmp", ".tego/claude", "kept", "kept/full"}; err != nil || !slices.Equal(made, want) {
		t.Fatalf("Create = %q, %v; want %q", made, err, want)
	}
	outside := t.TempDir()
	for _, d := range []string{"tmp", "claude"} { // the empty folders a removal through the link would take
		if err := os.Mkdir(filepath.Join(outside, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	swapForLink(t, filepath.Join(dir, ".tego"), outside)
	deep := filepath.Join(dir, "src", "deep")
	if err := os.Remove(deep); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deep, []byte("not a folder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kept", "full", "note"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	Remove(made, dir)
	for _, p := range []string{filepath.Join(outside, "tmp"), filepath.Join(outside, "claude")} {
		if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
			t.Errorf("Remove took %s, past the link swapped in at .tego: %v", p, err)
		}
	}
	if b, err := os.ReadFile(deep); err != nil || string(b) != "not a folder\n" {
		t.Errorf("Remove took the file swapped in at src/deep: %q, %v", b, err)
	}
	for _, p := range []string{filepath.Join(dir, ".tego"), filepath.Join(dir, ".tego.moved", "tmp"), filepath.Join(dir, "src"),
		filepath.Join(dir, "kept", "full")} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("Remove took %s: %v", p, err)
		}
	}

	// Nothing swapped: every folder made goes, outside the project too, and what was there before stays.
	dir = project(t, "src/")
	base := t.TempDir()
	viaLink := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink(base, viaLink); err != nil {
		t.Fatal(err)
	}
	made, err = Create(&Result{MakeDirs: []string{filepath.Join(dir, "src", "deep"), filepath.Join(dir, ".tego", "tmp"),
		filepath.Join(viaLink, "a", "b")}}, dir)
	if err != nil || len(made) != 5 {
		t.Fatalf("Create = %q, %v", made, err)
	}
	Remove(made, dir)
	for _, p := range []string{filepath.Join(dir, "src", "deep"), filepath.Join(dir, ".tego"), filepath.Join(base, "a")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("Remove left %s", p)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "src")); err != nil {
		t.Errorf("Remove took src, which was there before: %v", err)
	}
}
