// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestOtherNamesOnWSL: on WSL's mount table (testdata/wsl-mountinfo, reconstructed from the guest's measured rows)
// WSLg's /mnt/wslg/distro is the distribution's root filesystem a second time, so every path on it has a second name
// there, a denied secret in the home included; paths on other filesystems (the Windows drive, the runtime folder)
// have none.
func TestOtherNamesOnWSL(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "wsl-mountinfo", "ubuntu-24.04.mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	mt, err := ParseMountTableStrict(b)
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string][]aliasName{
		"/home/probe/.ssh":                  {{"/mnt/wslg/distro/home/probe/.ssh", "/home/probe/.ssh"}},
		"/home/probe/.ssh/tego-proof-decoy": {{"/mnt/wslg/distro/home/probe/.ssh/tego-proof-decoy", "/home/probe/.ssh/tego-proof-decoy"}},
		"/home/probe/.tego":                 {{"/mnt/wslg/distro/home/probe/.tego", "/home/probe/.tego"}},
		"/mnt/wslg/distro/home/probe/.ssh":  {{"/home/probe/.ssh", "/mnt/wslg/distro/home/probe/.ssh"}},
		"/mnt/c/Users/probe/.ssh":           nil,
		"/run/user/1000/gnupg":              nil,
		"/usr/lib/wsl/drivers/x":            nil,
	} {
		got, uncertain := mt.t.otherNames(p)
		if uncertain != "" || !slices.Equal(got, want) {
			t.Errorf("otherNames(%q) = %v, %q; want %v", p, got, uncertain, want)
		}
	}
}

// TestOtherNamesOfBinds: a bind of the home elsewhere gives every path in it a second name; a bind of a part of a
// denied tree elsewhere gives that part one, paired with the name it shows; a bind on another filesystem gives none;
// a path whose mount cannot be placed makes the list uncertain, never short in silence.
func TestOtherNamesOfBinds(t *testing.T) {
	table := "1 0 8:1 / / rw - ext4 disk rw\n" +
		"2 1 8:1 /home/u /srv/u rw - ext4 disk rw\n" +
		"3 1 8:1 /home/u/.ssh /mnt/keys rw - ext4 disk rw\n" +
		"4 1 0:40 / /data rw - xfs other rw\n" +
		"5 1 0:40 /data /mnt/data rw - xfs other rw\n"
	mt, err := ParseMountTableStrict([]byte(table))
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string][]aliasName{
		"/home/u/.ssh": {{"/srv/u/.ssh", "/home/u/.ssh"}, {"/mnt/keys", "/home/u/.ssh"}},
		"/home/u":      {{"/srv/u", "/home/u"}, {"/mnt/keys", "/home/u/.ssh"}},
		"/home/u/.ssh/id_ed25519": {{"/srv/u/.ssh/id_ed25519", "/home/u/.ssh/id_ed25519"},
			{"/mnt/keys/id_ed25519", "/home/u/.ssh/id_ed25519"}},
		"/home/other": nil,
		"/data/x":     nil,
	} {
		got, uncertain := mt.t.otherNames(p)
		slices.SortFunc(got, func(a, b aliasName) int { return cmpAlias(a, b) })
		slices.SortFunc(want, func(a, b aliasName) int { return cmpAlias(a, b) })
		if uncertain != "" || !slices.Equal(got, want) {
			t.Errorf("otherNames(%q) = %v, %q; want %v", p, got, uncertain, want)
		}
	}
	// A supplied table cannot be checked by statx, so its unlinked root of unknown type (a runtime's single-file bind,
	// as nspawn's boot_id) adds no doubt there; this process's own table establishes the type (unlinkedMountType).
	unlinked, err := ParseMountTableStrict([]byte(table + "6 1 8:1 /gone//deleted /mnt/gone rw - ext4 disk rw\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, uncertain := unlinked.t.otherNames("/home/u/.ssh"); uncertain != "" || len(got) != 2 {
		t.Errorf("a supplied table's unlinked root: %v, %q", got, uncertain)
	}
	// A path whose mount cannot be placed within a filesystem (a namespace file's): the list is uncertain, never
	// short in silence.
	ns, err := ParseMountTableStrict([]byte(table + "6 1 0:4 net:[4026532008] /home/u/netns rw - nsfs nsfs rw\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, uncertain := ns.t.otherNames("/home/u/netns"); uncertain == "" {
		t.Errorf("a namespace file's mount: %v with no doubt", got)
	}
}

func cmpAlias(a, b aliasName) int {
	switch {
	case a.alias < b.alias:
		return -1
	case a.alias > b.alias:
		return 1
	}
	return 0
}

// testID is a device and inode a test gives a name (bindStandIn).
type testID struct{ dev, ino uint64 }

// bindStandIn makes alias a stand-in for a bind of dir, as the kernel shows one: a real directory tree with the same
// names as dir's (no symlink, so each name resolves to itself, as a bind's names do), and an identity under which
// every name beneath alias reaches the device AND inode of the same name beneath dir (stat(2) through a bind). ids
// gives other names identities of their own (a covered mount's, or one that differs in the device or the inode
// alone). The returned option gives compile those identities; every other name is stat(2)'s.
func bindStandIn(t *testing.T, dir, alias string, ids map[string]testID) CompileOption {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out := filepath.Join(alias, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(out, 0o755)
		case d.Type().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(out, data, 0o600)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return withFileIdentity(func(p string) (uint64, uint64, error) {
		if id, ok := ids[p]; ok {
			return id.dev, id.ino, nil
		}
		if p == alias || strings.HasPrefix(p, alias+"/") {
			if _, err := os.Stat(p); err != nil {
				return 0, 0, err // a name the stand-in does not have
			}
			p = dir + strings.TrimPrefix(p, alias)
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			return 0, 0, &os.PathError{Op: "stat", Path: p, Err: err}
		}
		return uint64(st.Dev), st.Ino, nil //nolint:unconvert // st.Dev is a uint32 on some architectures
	})
}

// identityOf is the device and inode stat(2) gives p.
func identityOf(t *testing.T, p string) testID {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return testID{dev: uint64(st.Dev), ino: st.Ino} //nolint:unconvert // st.Dev is a uint32 on some architectures
}

// mountTableFile writes a mount table of the given rows (one ext4 filesystem 8:1 mounted at /, then binds of it) under
// the fixture and returns its path.
func mountTableFile(t *testing.T, f *fixture, binds ...[2]string) string {
	t.Helper()
	table := "1 0 8:1 / / rw - ext4 disk rw\n"
	for i, b := range binds {
		table += fmt.Sprintf("%d 1 8:1 %s %s rw - ext4 disk rw\n", i+2, b[0], b[1])
	}
	mi := filepath.Join(f.root, "mountinfo")
	if err := os.WriteFile(mi, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	return mi
}

// TestCompileDeniesEveryName (ADR 0011, amended 2026-11-19, rounds 4 and 5; the guest row W-E4-ALIAS): a refusal is
// about the file. With the home shown a second time by a bind (the stand-in gives every name beneath the bind the
// same device and inode as the name it shows, and resolves to itself, as a bind's does), every deny entry gets the
// second name too: the built-in ~/.ssh, a declared deny_read and an absent built-in row, each with the original's
// rule name; a read at the second name is refused by the entry; a second name that reaches another file now (a
// covered mount) is left out, and so are names whose identity differs in the device alone or in the inode alone; and
// with no mount table nothing is added.
func TestCompileDeniesEveryName(t *testing.T) {
	f := newFixture(t)
	for _, d := range []string{filepath.Join(f.home, ".ssh"), filepath.Join(f.home, "notes")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(f.home, ".ssh", "id_ed25519"), "k", 0o600)
	alias := filepath.Join(f.root, "second-home")
	covered := filepath.Join(f.root, "covered")
	devOnly := filepath.Join(f.root, "other-device")
	inoOnly := filepath.Join(f.root, "other-inode")
	for _, d := range []string{covered, devOnly, inoOnly} {
		for _, name := range []string{".ssh", "notes"} {
			if err := os.MkdirAll(filepath.Join(d, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	ids := map[string]testID{}
	for _, name := range []string{".ssh", "notes"} {
		orig := identityOf(t, filepath.Join(f.home, name))
		ids[filepath.Join(devOnly, name)] = testID{dev: orig.dev + 1, ino: orig.ino}
		ids[filepath.Join(inoOnly, name)] = testID{dev: orig.dev, ino: orig.ino + 1}
	}
	same := bindStandIn(t, f.home, alias, ids)
	mi := mountTableFile(t, f, [2]string{f.home, alias}, [2]string{f.home, covered}, [2]string{f.home, devOnly}, [2]string{f.home, inoOnly})
	c := f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  deny_read: [\"" + filepath.Join(f.home, "notes") + "\"]\n")
	rt, ds := f.compile(c, WithMountInfo(mi), same)
	if rt == nil {
		t.Fatalf("compile failed:\n%s", render(ds))
	}
	byPath := map[string]FSRule{}
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead {
			byPath[r.Path] = r
		}
	}
	for _, name := range []string{".ssh", "notes"} {
		orig, ok := byPath[filepath.Join(f.home, name)]
		if !ok {
			t.Fatalf("no deny_read of ~/%s:\n%v", name, rt.FS)
		}
		second, ok := byPath[filepath.Join(alias, name)]
		if !ok {
			t.Errorf("~/%s: no deny_read at its second name %s", name, filepath.Join(alias, name))
			continue
		}
		if second.AliasOf != orig.Path || second.RuleName() != orig.RuleName() || second.BuiltIn != orig.BuiltIn ||
			second.Canonical() != filepath.Join(alias, name) {
			t.Errorf("~/%s: second name %+v; want the rule %s at its own name", name, second, orig.RuleName())
		}
		for _, other := range []string{covered, devOnly, inoOnly} {
			if _, ok := byPath[filepath.Join(other, name)]; ok {
				t.Errorf("~/%s: %s, a name that reaches another file, was denied", name, filepath.Join(other, name))
			}
		}
	}
	got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(alias, ".ssh", "id_ed25519")}, backend.TierLandlock)
	if got.Verdict == VerdictAllow || got.Rule != byPath[filepath.Join(f.home, ".ssh")].RuleName() {
		t.Errorf("a read at the second name: %+v; want refused by %s", got, byPath[filepath.Join(f.home, ".ssh")].RuleName())
	}
	absent := 0
	for _, a := range rt.AbsentDenyRead {
		if isAncestorOrSelf(alias, a.At) {
			absent++
		}
	}
	if absent == 0 {
		t.Errorf("no absent built-in row at the second name: %v", rt.AbsentDenyRead)
	}
	if rt, _ := f.compile(c, WithMountInfo(""), same); rt != nil {
		for _, r := range rt.FS {
			if r.AliasOf != "" {
				t.Errorf("with no mount table, compile added %s", r.Path)
			}
		}
	}
}

// writeAliasFixture compiles a contract that writes the whole project, with a .env in it (so a deny_read target lies
// inside the write entry), a git repository's hooks and config (built-in deny_write targets) and a declared deny_read
// glob, on a machine whose mount table shows the project a second time (a read-write bind at alias). The contract
// file lies outside the project. reads is fs.reads ("" for the default).
func writeAliasFixture(t *testing.T, reads string) (f *fixture, alias string, rt *RuleTable, ds []Diagnostic) {
	t.Helper()
	f = newFixture(t)
	for _, d := range []string{filepath.Join(f.project, ".git", "hooks"), filepath.Join(f.project, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(f.project, ".git", "HEAD"), "ref: refs/heads/main\n", 0o644)
	f.file(filepath.Join(f.project, ".git", "config"), "[core]\n", 0o644)
	alias = filepath.Join(f.root, "srv-project")
	same := bindStandIn(t, f.project, alias, nil)
	mi := mountTableFile(t, f, [2]string{f.project, alias})
	contracts := filepath.Join(f.root, "contracts")
	if err := os.MkdirAll(contracts, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"" + f.project + "/\"]\n  deny_read: [\"" +
		f.project + "/secrets/*.pem\"]\n"
	if reads != "" {
		yaml += "  reads: " + reads + "\n"
	}
	path := filepath.Join(contracts, "agent.yaml")
	f.file(path, yaml, 0o644)
	c, lds, err := Load(path, nil)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(lds))
	}
	// An invalid contract is an error here; the caller reads the diagnostics.
	rt, ds, _ = Compile(c, f.machine, f.opts(WithMountInfo(mi), same, WithTiers(backend.TierLandlock))...)
	return f, alias, rt, ds
}

// TestCompileWriteEntryOtherNames (ADR 0011, amended 2026-11-19, round 5; review F1, F2, F6): Landlock keys a write
// grant to the inode, so another name of a write entry is granted too, and compile models it so: the write entry's
// other name is a write entry of the same rule; a deny_read target inside it is nested under its other name too
// (unenforced at tier landlock and held); every deny_write target inside it gets its other name, which the
// supervisor's floor (DenyWriteTarget) matches; the decision model allows a write through the other name and refuses
// a write of a target there; and a file a name rule covers that is made during the run is refused under the other
// name as under its own.
func TestCompileWriteEntryOtherNames(t *testing.T) {
	f, alias, rt, ds := writeAliasFixture(t, "")
	if rt == nil {
		t.Fatalf("compile failed:\n%s", render(ds))
	}
	var write, aliasWrite *FSRule
	for i := range rt.FS {
		if r := &rt.FS[i]; r.Kind == FSWrite && r.Canonical() == f.project {
			write = r
		} else if r.Kind == FSWrite && r.Canonical() == alias {
			aliasWrite = r
		}
	}
	if write == nil || aliasWrite == nil {
		t.Fatalf("write entries: %v; want %s and its other name %s", rt.FS, f.project, alias)
	}
	if aliasWrite.AliasOf != write.Path || aliasWrite.RuleName() != write.RuleName() || aliasWrite.Access != write.Access {
		t.Errorf("the other name's write entry %+v; want the rule %s", *aliasWrite, write.RuleName())
	}
	// The .env inside the write entry, under its other name: nested, so held at tier landlock.
	aliasEnv := filepath.Join(alias, ".env")
	nested := false
	for _, n := range rt.Reads.Nested {
		nested = nested || n.Path == aliasEnv
	}
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.Path == aliasEnv && (!r.Unenforced || !nested) {
			t.Errorf("deny_read %s: unenforced %v, nested %v; want both (a write grant reaches it by inode)", aliasEnv, r.Unenforced, nested)
		}
	}
	if !rt.ReadsHeldAt(backend.TierLandlock) {
		t.Fatalf("reads not held at tier landlock: %+v", rt.Reads)
	}
	// Every deny_write target inside it, under its other name, with the original's rule.
	for _, target := range []string{filepath.Join(".git", "hooks", "pre-commit"), filepath.Join(".git", "config")} {
		own, ok := rt.DenyWriteTarget(filepath.Join(f.project, target), false)
		if !ok {
			t.Fatalf("no deny_write target at %s: %v", target, rt.DenyWrite)
		}
		other, ok := rt.DenyWriteTarget(filepath.Join(alias, target), false)
		if !ok || other.RuleName() != own.RuleName() || !other.Unenforced {
			t.Errorf("deny_write at the other name of %s: %+v, %v; want %s, unenforced", target, other, ok, own.RuleName())
		}
		res := rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(alias, target)}, backend.TierLandlock)
		if res.Verdict != VerdictRefused || res.Rule != own.RuleName() {
			t.Errorf("a write of %s under the other name: %+v; want refused by %s", target, res, own.RuleName())
		}
	}
	// A write the kernel allows (Landlock grants the inode) is no refusal in the model.
	for _, p := range []string{filepath.Join(alias, "new.txt"), filepath.Join(alias, "sub", "x")} {
		res := rt.Evaluate(Action{Kind: ActionFSWrite, Path: p}, backend.TierLandlock)
		if res.Verdict != VerdictAllow || res.Rule != write.RuleName() {
			t.Errorf("a write of %s: %+v; want allow %s", p, res, write.RuleName())
		}
	}
	// Reads: the existing .env and a .env or a matching .pem made during the run, under both names.
	for _, p := range []string{".env", filepath.Join("sub", ".env"), filepath.Join("secrets", "new.pem")} {
		for _, base := range []string{f.project, alias} {
			res := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(base, p)}, backend.TierLandlock)
			if res.Verdict != VerdictRefused {
				t.Errorf("a read of %s: %+v; want refused", filepath.Join(base, p), res)
			}
		}
	}
}

// TestCompileRefusesAnOtherNameNothingRefuses (Y1): under fs.reads: direct the run reads direct at tier landlock, so
// nothing refuses the read of the .env through the write entry's other name there; compile refuses the contract,
// naming the file, the other name and the setting that makes it enforceable. The entry's own name keeps its warning.
func TestCompileRefusesAnOtherNameNothingRefuses(t *testing.T) {
	f, alias, rt, ds := writeAliasFixture(t, "direct")
	if rt != nil {
		t.Fatalf("compiled under fs.reads: direct with an other name nothing refuses:\n%s", render(ds))
	}
	want := filepath.Join(alias, ".env")
	for _, d := range ds {
		if d.Severity == SeverityError && d.Code == CodeUnenforced && strings.Contains(d.Message, want) &&
			strings.Contains(d.Message, filepath.Join(f.project, ".env")) && strings.Contains(d.Fix, "fs.reads") {
			return
		}
	}
	t.Errorf("no refusal naming %s, its other name and fs.reads:\n%s", filepath.Join(f.project, ".env"), render(ds))
}

// TestCompileFailsClosedOnTheMountTable (Y5, review F5): a mount table that cannot be read whole, or one that cannot
// list every other name of a deny entry, refuses the contract with the reason, whatever the contract; it never
// compiles with a warning and fewer names.
func TestCompileFailsClosedOnTheMountTable(t *testing.T) {
	f := newFixture(t)
	notes := filepath.Join(f.home, "notes")
	if err := os.MkdirAll(notes, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(f.root, "bad-mountinfo")
	f.file(bad, "this is not a mount table\n", 0o600)
	unplaced := filepath.Join(f.root, "unplaced-mountinfo")
	f.file(unplaced, "1 0 8:1 / / rw - ext4 disk rw\n2 1 0:4 net:[4026532008] "+notes+" rw - nsfs nsfs rw\n", 0o600)
	for _, tc := range []struct{ name, table, fs, want string }{
		{"unreadable, no fs section", bad, "", "cannot be read whole"},
		{"unreadable, fs: {}", bad, "fs: {}\n", "cannot be read whole"},
		{"a deny entry it cannot place", unplaced, "fs:\n  deny_read: [\"" + notes + "\"]\n", "cannot list every other name"},
	} {
		c := f.load("version: 0\nname: t\ncommand: [\"python\"]\n" + tc.fs)
		rt, ds, _ := Compile(c, f.machine, f.opts(WithMountInfo(tc.table))...)
		refused := false
		for _, d := range ds {
			refused = refused || d.Severity == SeverityError && d.Code == CodeMountWarning && strings.Contains(d.Message, tc.want)
		}
		if rt != nil || !refused {
			t.Errorf("%s: compiled %v; want refused with %q:\n%s", tc.name, rt != nil, tc.want, render(ds))
		}
	}
}

// TestCompileRefusesAnAbsentRowUnderAnExecDirectorysOtherName (round 6, review G4): the home is an exec.allow directory
// and a bind shows it a second time. The grant's READ_FILE sits on the directory's inode, so a built-in protected file
// that does not exist yet (here every one: the fixture's home holds none) is readable when it is made under the second
// name; the row beneath the directory's own name is dropped (execDirs), but the row compile placed beneath the other
// name stayed and the decision model said "refused". Compile now refuses the contract with one sentence naming the
// file, the other name and what to change, as it does for an existing deny_read entry there.
func TestCompileRefusesAnAbsentRowUnderAnExecDirectorysOtherName(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{".ssh", ".aws", ".netrc"} { // the fixture's protected files: only absent rows are left
		if err := os.RemoveAll(filepath.Join(f.home, n)); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(f.root, "second-home")
	same := bindStandIn(t, f.home, alias, nil)
	mi := mountTableFile(t, f, [2]string{f.home, alias})
	c := f.load("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  allow: [\"" + f.home + "\"]\n")
	rt, ds, _ := Compile(c, f.machine, f.opts(WithMountInfo(mi), same, WithTiers(backend.TierLandlock))...)
	if rt != nil {
		for _, a := range rt.AbsentDenyRead {
			if isAncestorOrSelf(alias, a.At) {
				got := rt.Evaluate(Action{Kind: ActionFSRead, Path: a.At}, backend.TierLandlock)
				t.Errorf("compiled with the absent row %s under the exec directory's other name: a read there is %+v", a.At, got)
				break
			}
		}
		t.Fatalf("compiled; want a refusal:\n%s", render(ds))
	}
	for _, d := range ds {
		if d.Severity == SeverityError && d.Code == CodeUnenforced && strings.Contains(d.Message, alias) &&
			strings.Contains(d.Message, "same directory as "+alias) && strings.Contains(d.Message, "protected file") && d.Fix != "" {
			return
		}
	}
	t.Errorf("no refusal naming the absent row under %s:\n%s", alias, render(ds))
}
