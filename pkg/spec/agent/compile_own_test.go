// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"golang.org/x/sys/unix"
)

// ownInstall makes an install directory under the fixture holding tego and tego-control, and returns it. A target
// under fixture bin would refuse nothing of use: the contract's own tools live there.
func ownInstall(f *fixture) string {
	dir := filepath.Join(f.root, "opt", "tego", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	f.file(filepath.Join(dir, "tego"), "tego", 0o755)
	f.file(filepath.Join(dir, "tego-control"), "control", 0o755)
	return dir
}

func writeSection(entries ...string) string {
	return "version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + strings.Join(entries, "\", \"") + "\"]\n"
}

// wantRefused compiles c and wants R10's contradiction, naming want.
func wantRefused(t *testing.T, f *fixture, c *Contract, want string, opts ...CompileOption) {
	t.Helper()
	_, ds, err := Compile(c, f.machine, f.opts(opts...)...)
	if err == nil || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeContradiction && d.Severity == SeverityError && strings.Contains(d.Message, want)
	}) {
		t.Fatalf("no contradiction naming %q (err=%v):\n%s", want, err, render(ds))
	}
}

// shadowWarnings is the path-shadow diagnostics of a compile that must pass.
func shadowWarnings(t *testing.T, f *fixture, c *Contract, opts ...CompileOption) []Diagnostic {
	t.Helper()
	_, ds := f.compile(c, opts...)
	return slices.DeleteFunc(slices.Clone(ds), func(d Diagnostic) bool { return d.Code != CodePathShadow })
}

// TestCompileRefusesWritesOverTegosBinaries: an entry over the install directory compiled, and the agent replaced the
// tego binary, so the next run ran its code outside any contract. R10 refuses an entry at or over tego or tego-control,
// found as the running file or on the launcher's PATH, and one holding a name a walk to them reads.
func TestCompileRefusesWritesOverTegosBinaries(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	exe := filepath.Join(dir, "tego")
	if err := os.Symlink(dir, filepath.Join(f.project, "tools")); err != nil {
		t.Fatal(err)
	}
	onPATH := WithPATH(f.bin + ":" + dir)
	for name, c := range map[string]struct {
		entry string
		opts  []CompileOption
		want  string
	}{
		"the file":                   {exe, []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"its directory":              {dir, []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"a directory above":          {filepath.Join(f.root, "opt"), []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"a link to its directory":    {"./tools", []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"tego-control beside it":     {filepath.Join(dir, "tego-control"), []CompileOption{WithOwnBinaries(exe)}, "the tego-control binary"},
		"found on PATH":              {dir, []CompileOption{WithOwnBinaries(""), onPATH}, "the tego binary on PATH"},
		"tego-control found on PATH": {filepath.Join(dir, "tego-control"), []CompileOption{WithOwnBinaries(""), onPATH}, "the tego-control binary"},
	} {
		t.Run(name, func(t *testing.T) {
			wantRefused(t, f, f.load(writeSection(c.entry)), c.want, c.opts...)
		})
	}
	t.Run("tego-control not there yet", func(t *testing.T) {
		// The agent would fill the name beside a running tego that has none.
		other := filepath.Join(f.root, "other")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(other, "tego"), "tego", 0o755)
		wantRefused(t, f, f.load(writeSection(filepath.Join(other, "tego-control"))), "tego-control",
			WithOwnBinaries(filepath.Join(other, "tego")))
	})
	t.Run("tego-control alone on PATH", func(t *testing.T) {
		other := filepath.Join(f.root, "other2")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(other, "tego-control"), "control", 0o755)
		wantRefused(t, f, f.load(writeSection(other)), "the tego-control binary on PATH", WithOwnBinaries(""), WithPATH(other+":"+f.bin))
	})
	t.Run("an ask scope over it", func(t *testing.T) {
		wantRefused(t, f, f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  ask: [\""+dir+"\"]\n"), "the tego binary",
			WithOwnBinaries(exe))
	})
}

// TestCompileRefusesWritesOverALinkToTego: tego is found by what a person types, so where PATH holds a link to the real
// file (ln -s /opt/tego/bin/tego ~/.local/bin/), an entry over the link's directory lets the agent point it elsewhere,
// and the os.Executable name alone never sees that. The tego-control the real file hands off to lies beside it.
func TestCompileRefusesWritesOverALinkToTego(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	links := filepath.Join(f.home, ".local", "bin")
	if err := os.MkdirAll(links, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "tego"), filepath.Join(links, "tego")); err != nil {
		t.Fatal(err)
	}
	opts := []CompileOption{WithOwnBinaries(filepath.Join(dir, "tego")), WithPATH(links + ":" + f.bin)}
	wantRefused(t, f, f.load(writeSection(links)), "holds the symlink "+filepath.Join(links, "tego"), opts...)
	wantRefused(t, f, f.load(writeSection(filepath.Join(f.home, ".local"))), "the tego binary", opts...)
	opts = []CompileOption{WithOwnBinaries(""), WithPATH(links + ":" + f.bin)}
	wantRefused(t, f, f.load(writeSection(filepath.Join(dir, "tego-control"))), "the tego-control binary", opts...)
}

// TestCompileKeepsWritesBesideTegosBinaries: only what reaches a binary is refused. An entry beside the install
// directory, or one inside it that holds no name on the way, leaves tego where it is, and a compile not told of any
// binary, a library's, refuses nothing.
func TestCompileKeepsWritesBesideTegosBinaries(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	exe := filepath.Join(dir, "tego")
	opts := []CompileOption{WithOwnBinaries(exe), WithPATH(f.bin + ":" + dir)}
	for _, d := range []string{filepath.Join(f.root, "opt", "data"), filepath.Join(dir, "cache")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		f.compile(f.load(writeSection(d)), opts...)
	}
	f.compile(f.load(writeSection(filepath.Join(f.project, "out"))), opts...)
	f.compile(f.load(writeSection(dir)), WithPATH(f.bin+":"+dir))
	t.Run("a running file that is not there", func(t *testing.T) {
		f.compile(f.load(writeSection(dir)), WithOwnBinaries(filepath.Join(f.root, "gone", "tego")), WithPATH(f.bin))
	})
}

// TestCompileWarnsAboutPATHBeforeTego is the shell's other way to tego: a write entry over a directory PATH searches
// first lets the agent plant a tego that a person's next `tego` runs. The directory holds nothing of tego's, and an
// activated .venv/bin is the common case, so the contract compiles, and the warning says what to change.
func TestCompileWarnsAboutPATHBeforeTego(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	out := filepath.Join(f.project, "out")
	venv := filepath.Join(out, ".venv", "bin")
	if err := os.MkdirAll(venv, 0o755); err != nil {
		t.Fatal(err)
	}
	c := f.load(writeSection(out))
	got := shadowWarnings(t, f, c, WithOwnBinaries(""), WithPATH(venv+":"+dir+":"+f.bin))
	if len(got) != 1 || got[0].Severity != SeverityWarning || !strings.Contains(got[0].Message, venv) ||
		!strings.Contains(got[0].Message, filepath.Join(dir, "tego")) || !strings.Contains(got[0].Message, "outside the contract") ||
		!strings.Contains(got[0].Fix, dir) {
		t.Fatalf("path-shadow warnings: %+v", got)
	}
	t.Run("an empty PATH element is the working directory", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithOwnBinaries(""), WithPATH(":"+dir+":"+f.bin), WithCwd(out)); len(got) != 1 {
			t.Fatalf("path-shadow warnings: %+v", got)
		}
	})
	t.Run("a directory after tego", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithOwnBinaries(""), WithPATH(dir+":"+venv+":"+f.bin)); len(got) != 0 {
			t.Fatalf("warned about a directory searched after tego: %+v", got)
		}
	})
	t.Run("tego not on PATH", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithOwnBinaries(filepath.Join(dir, "tego")), WithPATH(venv+":"+f.bin)); len(got) != 0 {
			t.Fatalf("warned with no tego for the name to shadow: %+v", got)
		}
	})
	t.Run("not asked", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithPATH(venv+":"+dir+":"+f.bin)); len(got) != 0 {
			t.Fatalf("warned with no WithOwnBinaries: %+v", got)
		}
	})
}

// fakeMountInfo writes a mount table for the fixture: the root filesystem on 8:1, then each extra line, and returns the
// WithMountInfo option that reads it.
func fakeMountInfo(f *fixture, extra ...string) CompileOption {
	lines := []string{"1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw"}
	for _, line := range extra {
		if line == "" {
			continue
		}
		// An explicit root replaces the default; duplicate IDs and blank
		// rows are not valid kernel snapshots.
		if m, ok := parseMountLine(line); ok && m.id == "1" && m.point == "/" {
			lines[0] = line
			continue
		}
		lines = append(lines, line)
	}
	p := filepath.Join(f.root, "mountinfo")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return WithMountInfo(p)
}

// TestCompileRefusesWritesOverTegosOtherNames: R10 holds tego's binaries by what the kernel knows them by, not only by
// the running file's and PATH's names (ADR 0059, amendment 2026-11-11). A tego installed in a usual place that this
// compile neither runs from nor finds on PATH (a systemd unit's ExecStart, a second install), a bind mount that shows
// the install directory at another place, and an overlay layer that holds its content are each refused; a file with a
// second hard link, whose other name no table lists, refuses every entry that reaches its filesystem; and a mount
// table that cannot be read refuses every write entry, since no comparison then shows one stays off tego.
func TestCompileRefusesWritesOverTegosOtherNames(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	exe := filepath.Join(dir, "tego")
	out := filepath.Join(f.project, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("a unit's ExecStart at a usual install place", func(t *testing.T) {
		// This compile runs from another tego and finds none on PATH; the unit's tego is installed where tego goes.
		running := filepath.Join(f.root, "elsewhere", "tego")
		if err := os.MkdirAll(filepath.Dir(running), 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(running, "tego", 0o755)
		opts := []CompileOption{WithOwnBinaries(running), WithPATH(f.bin), withInstallDirs(dir)}
		wantRefused(t, f, f.load(writeSection(dir)), "the tego binary installed at "+exe, opts...)
		wantRefused(t, f, f.load(writeSection(filepath.Join(dir, "tego-control"))), "tego-control", opts...)
		// Not looked for there: the old R10 knew only the running file and PATH, and compiled it.
		f.compile(f.load(writeSection(dir)), WithOwnBinaries(running), WithPATH(f.bin), withInstallDirs())
	})
	t.Run("a second install in the installer's prefix", func(t *testing.T) {
		second := filepath.Join(f.home, ".local", "bin")
		if err := os.MkdirAll(second, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(second, "tego"), "tego", 0o755)
		t.Cleanup(func() { _ = os.Remove(filepath.Join(second, "tego")) })
		// The fixture's default looks in the compile's home's .local/bin, as the product's does.
		wantRefused(t, f, f.load(writeSection(filepath.Join(f.home, ".local"))), "the tego binary installed at", WithOwnBinaries(exe))
	})
	t.Run("a bind mount of the install directory", func(t *testing.T) {
		bind := filepath.Join(f.project, "tools-bind")
		if err := os.MkdirAll(bind, 0o755); err != nil {
			t.Fatal(err)
		}
		mi := fakeMountInfo(f, "2 1 8:1 "+dir+" "+bind+" rw,relatime - ext4 /dev/sda1 rw")
		wantRefused(t, f, f.load(writeSection(bind)), "mounted again at another place, "+exe, WithOwnBinaries(exe), mi)
		f.compile(f.load(writeSection(out)), WithOwnBinaries(exe), mi) // an entry beside the bind stays legal
	})
	t.Run("a bind mount of the file alone", func(t *testing.T) {
		alias := filepath.Join(out, "t")
		mi := fakeMountInfo(f, "3 1 8:1 "+exe+" "+alias+" rw,relatime - ext4 /dev/sda1 rw")
		wantRefused(t, f, f.load(writeSection(out)), "mounted again at another place, "+exe, WithOwnBinaries(exe), mi)
	})
	t.Run("an overlay layer holding it", func(t *testing.T) {
		layer := filepath.Join(f.root, "layers", "lower")
		if err := os.MkdirAll(filepath.Join(layer, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		mi := WithMountInfo(filepath.Join(f.root, "mountinfo-overlay"))
		if err := os.WriteFile(filepath.Join(f.root, "mountinfo-overlay"), []byte("1 0 0:40 / / rw - overlay overlay rw,lowerdir="+
			layer+",upperdir="+filepath.Join(f.root, "layers", "up")+",workdir="+filepath.Join(f.root, "layers", "work")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, f, f.load(writeSection(filepath.Join(layer, "sub"))), "a layer of the overlay holding tego's binaries", WithOwnBinaries(exe), mi)
	})
	t.Run("a hard link", func(t *testing.T) {
		other := filepath.Join(f.root, "hidden")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		// Group-writable, so the file is one a user may write whoever runs the test (as root in the guest, a file
		// only root may write has no name a non-root agent can write through, and is not refused).
		if err := os.Chmod(exe, 0o775); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(exe, 0o755) })
		if err := os.Link(exe, filepath.Join(other, "x")); err != nil {
			t.Skipf("no hard links here: %v", err)
		}
		t.Cleanup(func() { _ = os.Remove(filepath.Join(other, "x")) })
		wantRefused(t, f, f.load(writeSection(out)), "the tego binary "+exe+" has 2 hard links, whose other names compile cannot list",
			WithOwnBinaries(exe), WithMountInfo(""))
		// A compile told of no binary, a library's, counts no links.
		f.compile(f.load(writeSection(out)))
	})
	t.Run("a mount table it cannot read", func(t *testing.T) {
		missing := WithMountInfo(filepath.Join(f.root, "no-such-mountinfo"))
		wantRefused(t, f, f.load(writeSection(out)), "the mount table cannot be read whole", WithOwnBinaries(exe), missing)
		f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"), WithOwnBinaries(exe), missing) // no write entry, nothing to show
	})
}

// TestCompileRefusesWritesReachingAControlFilesystem: R10 keeps every write grant off the kernel's control
// filesystems by what the mount table says they are, not by their usual path: a bind mount of the cgroup tree inside a
// write entry, a second cgroup2 or proc mount there, and an entry inside such a mount are refused, at fs.write and
// fs.ask alike, while an entry beside one stays legal. A table larger than compile reads refuses every write entry.
func TestCompileRefusesWritesReachingAControlFilesystem(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.project, "out")
	cg := filepath.Join(out, "cg")
	if err := os.MkdirAll(filepath.Join(cg, "user.slice"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		line, entry string
	}{
		"a bind of the cgroup tree": {"5 1 0:30 /user.slice " + cg + " rw - cgroup2 cgroup2 rw", out},
		"a second cgroup2 mount":    {"5 1 0:30 / " + cg + " rw - cgroup2 cgroup2 rw", out},
		"a proc mount":              {"5 1 0:22 / " + cg + " rw - proc proc rw", out},
		"a resctrl group":           {"5 1 0:31 / " + cg + " rw - resctrl resctrl rw", out},
		"an mqueue mount":           {"5 1 0:19 / " + cg + " rw - mqueue mqueue rw", out},
		"an entry inside it":        {"5 1 0:30 / " + cg + " rw - cgroup2 cgroup2 rw", filepath.Join(cg, "user.slice")},
	} {
		t.Run(name, func(t *testing.T) {
			mi := fakeMountInfo(f, c.line)
			wantRefused(t, f, f.load(writeSection(c.entry)), "a kernel control filesystem", mi)
			wantRefused(t, f, f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  ask: [\""+c.entry+"\"]\n"), "a kernel control filesystem", mi)
		})
	}
	t.Run("the canonical devpts mount is not refused", func(t *testing.T) {
		f.compile(f.load(writeSection("/dev/pts")), fakeMountInfo(f, "5 1 0:24 / /dev/pts rw - devpts devpts rw"))
	})
	t.Run("an entry beside it", func(t *testing.T) {
		side := filepath.Join(f.project, "side")
		if err := os.MkdirAll(side, 0o755); err != nil {
			t.Fatal(err)
		}
		f.compile(f.load(writeSection(side)), fakeMountInfo(f, "5 1 0:30 / "+cg+" rw - cgroup2 cgroup2 rw"))
	})
	t.Run("a table past the bound", func(t *testing.T) {
		lines := make([]string, maxMountRows+1)
		for i := range lines {
			lines[i] = strconv.Itoa(i+2) + " 1 8:1 / /m" + strconv.Itoa(i) + " rw - ext4 /dev/sda1 rw"
		}
		wantRefused(t, f, f.load(writeSection(out)), "larger than 8388608 bytes or 32768 mounts", fakeMountInfo(f, lines...))
	})
}

// TestCompileHoldsTheLayerClosure: the layers of an overlay holding tego are followed for their own other places: a
// bind mount of the upper layer elsewhere, inside a write entry, is refused as the layer is; a layer on an unnamed
// stacking filesystem warns about unplaced backing while protecting visible layers.
func TestCompileHoldsTheLayerClosure(t *testing.T) {
	f := newFixture(t)
	merged := filepath.Join(f.root, "merged", "bin")
	upper := filepath.Join(f.root, "layers", "up")
	lower := filepath.Join(f.root, "layers", "low")
	alias := filepath.Join(f.project, "out", "layer-alias")
	for _, d := range []string{merged, upper, lower, alias, filepath.Join(f.root, "layers", "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(merged, "tego")
	f.file(exe, "tego", 0o755)
	// tego runs from an overlay at merged's parent; its layers lie on the root filesystem (8:1, fakeMountInfo's).
	overlay := "2 1 0:40 / " + filepath.Dir(merged) + " rw - overlay overlay rw,lowerdir=" + lower + ",upperdir=" + upper +
		",workdir=" + filepath.Join(f.root, "layers", "work")
	out := filepath.Join(f.project, "out")
	t.Run("a bind of the upper layer", func(t *testing.T) {
		mi := fakeMountInfo(f, overlay, "3 1 8:1 "+upper+" "+alias+" rw - ext4 /dev/sda1 rw")
		wantRefused(t, f, f.load(writeSection(out)), "a layer of the overlay holding tego's binaries,", WithOwnBinaries(exe), mi)
		// Without the bind the same entry compiles: the layers lie outside it.
		f.compile(f.load(writeSection(out)), WithOwnBinaries(exe), fakeMountInfo(f, overlay))
	})
	t.Run("a layer on an unnamed stacking filesystem", func(t *testing.T) {
		mi := fakeMountInfo(f, overlay, "3 1 0:50 / "+upper+" rw - fuse.sshfs remote rw")
		_, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), mi)...)
		if err != nil {
			t.Fatalf("ordinary nested FUSE grant refused: %v\n%s", err, render(ds))
		}
		var warnings []string
		for _, d := range ds {
			if d.Code == CodeOverlayBackingUnknown {
				warnings = append(warnings, backingWarningSummary(d.Message))
			}
		}
		if !slices.Equal(warnings, []string{runtimeBackingWarning("write", out, "/", "fuse.sshfs")}) {
			t.Errorf("nested FUSE warning=%q", warnings)
		}
		wantRefused(t, f, f.load(writeSection(upper)), "a layer of the overlay holding tego's binaries", WithOwnBinaries(exe), mi)
	})
}

// TestCompileHoldsProtectedDirectoriesThroughMounts: R10's rules that refuse a write grant inside one of tego's own
// directories hold by file identity, not only by spelling: a grant on a folder inside a bind mount of the profiles
// directory, a grant over a mount that shows part of it, a grant inside a bind of the directory holding the chain anchor,
// and a grant over or inside a bind of the ledger root's run directories are refused, as their originals are.
func TestCompileHoldsProtectedDirectoriesThroughMounts(t *testing.T) {
	f := newFixture(t)
	profiles := filepath.Join(f.root, "srv", "profiles")
	run := filepath.Join(f.ledger, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	out := filepath.Join(f.project, "out")
	for _, d := range []string{filepath.Join(profiles, "base"), run, out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	machine := *f.machine
	machine.Profiles = config.Setting[string]{Value: profiles}
	compile := func(entry string, mi CompileOption) error {
		_, _, err := Compile(f.load(writeSection(entry)), &machine, f.opts(mi)...)
		return err
	}
	want := func(t *testing.T, entry, line, wantText string) {
		t.Helper()
		if err := os.MkdirAll(entry, 0o755); err != nil {
			t.Fatal(err)
		}
		_, ds, err := Compile(f.load(writeSection(entry)), &machine, f.opts(fakeMountInfo(f, line))...)
		if err == nil || !strings.Contains(render(ds), wantText) {
			t.Fatalf("a grant at %s with %q compiled, or was refused for another reason (want %q):\n%s", entry, line, wantText, render(ds))
		}
	}
	t.Run("a folder inside a bind of the profiles directory", func(t *testing.T) {
		alias := filepath.Join(out, "pbind")
		want(t, filepath.Join(alias, "base"), "5 1 8:1 "+profiles+" "+alias+" rw - ext4 /dev/sda1 rw", "the profiles directory "+profiles+", through another mount of it")
	})
	t.Run("a grant over a mount showing part of the profiles directory", func(t *testing.T) {
		want(t, out, "5 1 8:1 "+filepath.Join(profiles, "base")+" "+filepath.Join(out, "pb")+" rw - ext4 /dev/sda1 rw", "the profiles directory "+profiles+", through another mount of it")
	})
	t.Run("a folder inside a bind of the anchor's directory", func(t *testing.T) {
		alias := filepath.Join(out, "tg")
		want(t, filepath.Join(alias, "sub"), "5 1 8:1 "+filepath.Join(f.home, ".tego")+" "+alias+" rw - ext4 /dev/sda1 rw", "tego's own directory")
	})
	t.Run("a run directory through a bind of the ledger root", func(t *testing.T) {
		alias := filepath.Join(out, "lr")
		// The fixture's ledger root lies in the anchor's directory, whose rule names it first.
		want(t, filepath.Join(alias, filepath.Base(run), "x"), "5 1 8:1 "+f.ledger+" "+alias+" rw - ext4 /dev/sda1 rw", ", through another mount of it")
		want(t, alias, "5 1 8:1 "+f.ledger+" "+alias+" rw - ext4 /dev/sda1 rw", "through another mount of its filesystem")
	})
	t.Run("a run directory through a bind of a ledger root outside the anchor's directory", func(t *testing.T) {
		ledger := filepath.Join(f.root, "srv", "runs")
		if err := os.MkdirAll(filepath.Join(ledger, filepath.Base(run)), 0o755); err != nil {
			t.Fatal(err)
		}
		m := machine
		m.LedgerRoot = config.Setting[string]{Value: ledger}
		// By its own path first: this compiled before review round 2 (the rule compared the ledger root's parent).
		direct := filepath.Join(ledger, filepath.Base(run), "y")
		if err := os.MkdirAll(direct, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, ds, err := Compile(f.load(writeSection(direct)), &m, f.opts(fakeMountInfo(f))...); err == nil ||
			!strings.Contains(render(ds), "a run directory under the ledger root "+ledger) {
			t.Fatalf("a grant inside a run directory under a ledger root outside the anchor's directory:\n%s", render(ds))
		}
		alias := filepath.Join(out, "lr2")
		entry := filepath.Join(alias, filepath.Base(run), "x")
		if err := os.MkdirAll(entry, 0o755); err != nil {
			t.Fatal(err)
		}
		_, ds, err := Compile(f.load(writeSection(entry)), &m, f.opts(fakeMountInfo(f, "5 1 8:1 "+ledger+" "+alias+" rw - ext4 /dev/sda1 rw"))...)
		if err == nil || !strings.Contains(render(ds), "a run directory under the ledger root "+ledger+", through another mount of it") {
			t.Fatalf("a grant inside a run directory through a bind of the ledger root:\n%s", render(ds))
		}
	})
	t.Run("the same grants with no such mount", func(t *testing.T) {
		if err := compile(filepath.Join(out, "pbind", "base"), fakeMountInfo(f)); err != nil {
			t.Fatalf("a grant beside every protected directory was refused: %v", err)
		}
	})
}

// TestCompileAllowsUnplacedLayers: absent host layer paths are a stated limit,
// while a layer exposed through a visible mount still receives ordinary protection.
func TestCompileAllowsUnplacedLayers(t *testing.T) {
	f := newFixture(t)
	merged := filepath.Join(f.root, "merged", "bin")
	out := filepath.Join(f.project, "out")
	alias := filepath.Join(out, "la")
	for _, d := range []string{merged, alias} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(merged, "tego")
	f.file(exe, "tego", 0o755)
	overlay := "2 1 0:40 / " + filepath.Dir(merged) + " rw - overlay overlay rw,lowerdir=/var/lib/elsewhere/l1,upperdir=/var/lib/elsewhere/up,workdir=/var/lib/elsewhere/work"
	t.Run("no external mount under the grant", func(t *testing.T) {
		if _, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), fakeMountInfo(f, overlay))...); err != nil {
			t.Fatalf("absent layers refused: %v\n%s", err, render(ds))
		}
	})
	t.Run("a sibling mount root does not place the layer", func(t *testing.T) {
		mi := fakeMountInfo(f, overlay, "3 1 8:9 /var/lib/elsewhere/up-other "+alias+" rw - ext4 /dev/sdb1 rw")
		if _, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), mi)...); err != nil {
			t.Fatalf("sibling root refused: %v\n%s", err, render(ds))
		}
	})
	t.Run("a covered layer mount does not expose it", func(t *testing.T) {
		mi := fakeMountInfo(f, overlay, "3 1 8:9 /var/lib/elsewhere/up "+alias+" rw - ext4 /dev/sdb1 rw", "4 3 0:50 / "+alias+" rw - tmpfs tmpfs rw")
		if _, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), mi)...); err != nil {
			t.Fatalf("covered layer mount refused: %v\n%s", err, render(ds))
		}
	})
	t.Run("a parent bind whose layer candidate is covered", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(alias, "up"), 0o755); err != nil {
			t.Fatal(err)
		}
		mi := fakeMountInfo(f, overlay, "3 1 8:9 /var/lib/elsewhere "+alias+" rw - ext4 /dev/sdb1 rw",
			"4 3 0:50 / "+filepath.Join(alias, "up")+" rw - tmpfs tmpfs rw")
		if _, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), mi)...); err != nil {
			t.Fatalf("covered parent-bind candidate refused: %v\n%s", err, render(ds))
		}
	})

	t.Run("a bind of a layer parent", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(alias, "up"), 0o755); err != nil {
			t.Fatal(err)
		}
		mi := fakeMountInfo(f, overlay, "3 1 8:9 /var/lib/elsewhere "+alias+" rw - ext4 /dev/sdb1 rw")
		wantRefused(t, f, f.load(writeSection(out)), "a layer of the overlay holding tego's binaries", WithOwnBinaries(exe), mi)
	})
	t.Run("an absent layer's visible bind", func(t *testing.T) {
		mi := fakeMountInfo(f, overlay, "3 1 8:9 /var/lib/elsewhere/up "+alias+" rw - ext4 /dev/sdb1 rw")
		wantRefused(t, f, f.load(writeSection(out)), "a layer of the overlay holding tego's binaries", WithOwnBinaries(exe), mi)
	})
	t.Run("ENOTDIR is absence", func(t *testing.T) {
		layer := filepath.Join(f.root, "not-directory")
		f.file(layer, "file", 0o644)
		mi := fakeMountInfo(f, "2 1 0:40 / / rw - overlay overlay rw,lowerdir="+layer+"/lower")
		_, ds, err := Compile(f.load(writeSection(out)), f.machine, f.opts(WithOwnBinaries(exe), mi)...)
		if err != nil {
			t.Fatalf("ENOTDIR layer refused: %v\n%s", err, render(ds))
		}
		for _, d := range ds {
			if d.Code == "overlay-backing-unknown" {
				t.Errorf("ENOTDIR with no storage mount got warning: %s", render(ds))
			}
		}
	})

	t.Run("an unreadable present layer still refuses", func(t *testing.T) {
		loop := filepath.Join(f.root, "loop")
		if err := os.Symlink(loop, loop); err != nil {
			t.Fatal(err)
		}
		mi := fakeMountInfo(f, "2 1 0:40 / "+filepath.Dir(merged)+" rw - overlay overlay rw,lowerdir="+loop)
		wantRefused(t, f, f.load(writeSection(out)), "cannot be examined", WithOwnBinaries(exe), mi)
	})
}

// TestCompileHoldsWalkDirectoriesThroughMounts holds names read before symlinks and
// before .. even when a write grant reaches their directory through another mount.
func TestCompileHoldsWalkDirectoriesThroughMounts(t *testing.T) {
	for _, beforeDotDot := range []bool{false, true} {
		t.Run(fmt.Sprint("before-dotdot=", beforeDotDot), func(t *testing.T) {
			f := newFixture(t)
			configDir := filepath.Join(f.home, ".config")
			registry := filepath.Join(f.root, "srv", "registry")
			held := configDir
			if beforeDotDot {
				held = filepath.Join(configDir, "sub")
			}
			alias := filepath.Join(f.project, "config-alias")
			for _, d := range []string{held, registry, alias} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			m := *f.machine
			if beforeDotDot {
				if err := os.MkdirAll(filepath.Join(held, "x"), 0o755); err != nil {
					t.Fatal(err)
				}
				m.Registry.Value = held + "/x/../../registry"
			} else {
				m.Registry.Value = filepath.Join(configDir, "tego")
				if err := os.Symlink(registry, m.Registry.Value); err != nil {
					t.Fatal(err)
				}
			}
			mi := fakeMountInfo(f, "5 1 8:1 "+held+" "+alias+" rw - ext4 /dev/sda1 rw")
			for _, field := range []string{"write", "ask"} {
				body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [" + alias + "]}\n"
				_, ds, err := Compile(f.load(body), &m, f.opts(mi)...)
				if err == nil || !strings.Contains(render(ds), "on the way to the user registry") {
					t.Errorf("fs.%s over mount of walk directory compiled or missed held name:\n%s", field, render(ds))
				}
			}
		})
	}
}

// Root ownership of the merged paths gives no assurance about hidden lower
// directories and receives no special treatment for missing layers or visible aliases.
func TestCompileUnplacedLayersIgnoreMergedOwnership(t *testing.T) {
	f := newFixture(t)
	exe := "/usr/bin/true"
	var st unix.Stat_t
	if err := unix.Stat(exe, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		t.Fatal("fixture requires a root-owned non-writable /usr/bin/true")
	}
	t.Setenv("SUDO_UID", "1000")
	out := filepath.Join(f.project, "out")
	alias := filepath.Join(out, "lower")
	if err := os.MkdirAll(alias, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(alias, 0o777); err != nil {
		t.Fatal(err)
	}
	overlay := "2 1 0:40 / /usr rw - overlay overlay rw,lowerdir=/unplaced-layers/lower,upperdir=/unplaced-layers/upper,workdir=/unplaced-layers/work"
	for _, field := range []string{"write", "ask"} {
		t.Run(field, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [" + out + "]}\n")
			if _, ds, err := Compile(c, f.machine, f.opts(WithOwnBinaries(exe), fakeMountInfo(f, overlay), withInstallDirs())...); err != nil {
				t.Fatalf("merged ownership must not change missing-layer policy: %v\n%s", err, render(ds))
			}
			for _, root := range []string{"/unplaced-layers/lower", "/unplaced-layers/lower/sub"} {
				mi := fakeMountInfo(f, overlay, "3 1 8:9 "+root+" "+alias+" rw - ext4 /dev/sdb1 rw")
				wantRefused(t, f, c, "a layer of the overlay holding tego's binaries", WithOwnBinaries(exe), mi, withInstallDirs())
			}
		})
	}
}

// Candidate collection stops one past the closure's refusal bound; a namespace
// with many matching mounts must not perform unlimited candidate lookups.
func TestCompileLayerCandidatesAreBounded(t *testing.T) {
	f := newFixture(t)
	var rows []string
	for i := range maxLayerPlaces + 20 {
		alias := filepath.Join(f.project, fmt.Sprintf("layer-%d", i))
		if err := os.MkdirAll(alias, 0o755); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, fmt.Sprintf("%d 1 8:9 /missing-layer %s rw - ext4 /dev/sdb1 rw", i+2, alias))
	}
	var opts compileOptions
	fakeMountInfo(f, rows...)(&opts)
	mt, err := loadMountTable(opts.mountInfo)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(mt.layerCandidates("/missing-layer")); got != maxLayerPlaces+1 {
		t.Fatalf("collected %d candidates, want the refusal bound plus one (%d)", got, maxLayerPlaces+1)
	}
}
