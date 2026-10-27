// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// TestANameIsAPathOnlyThroughTegosOwnMounts: whether /proc's name for a held file can be asked of the rules
// (Unnamed) is decided by the mount the file was opened through, never by the name alone. A mount of no place in
// tego's namespace (a detached clone, a lazily unmounted bind: its id is in no line of tego's mountinfo), a mount id
// the kernel did not give, and a name that now leads to another file or to none leave the file unnamed; a deleted file
// is named by its former path. Another mount of the same filesystem that shows the file's directory gives the path
// through it (Aliases); one of another filesystem, or showing another directory, does not.
func TestANameIsAPathOnlyThroughTegosOwnMounts(t *testing.T) {
	dir := t.TempDir()
	held, other := filepath.Join(dir, "held"), filepath.Join(dir, "other")
	for _, p := range []string{held, other} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id, err := statHeld(held)
	if err != nil {
		t.Fatal(err)
	}
	if !id.mntKnown {
		t.Skip("this kernel's statx gives no mount id (STATX_MNT_ID, Linux 5.8)")
	}
	fsDev := devID{8, 1}
	table := func(extra ...mountEntry) mountTable {
		m := mountTable{id.mnt: {dev: fsDev, root: "/", at: "/"}}
		for i, e := range extra {
			m[id.mnt+1000+uint64(i)] = e
		}
		return m
	}
	for _, c := range []struct {
		name    string
		mounts  mountTable
		path    string
		deleted bool
		id      heldID
		want    naming
	}{
		{"through a mount of tego's", table(), held, false, id, naming{}},
		{"through a mount tego's namespace does not hold", mountTable{id.mnt + 1: {dev: fsDev, root: "/", at: "/"}},
			held, false, id, naming{unnamed: true}},
		{"deleted, through a mount tego's namespace does not hold", mountTable{id.mnt + 1: {dev: fsDev, root: "/", at: "/"}},
			"/held", true, id, naming{unnamed: true}},
		{"no mount id given", table(), held, false, heldID{dev: id.dev, ino: id.ino, mnt: id.mnt}, naming{unnamed: true}},
		{"its name leads to another file", table(), other, false, id, naming{unnamed: true}},
		{"its name leads to none", table(), filepath.Join(dir, "gone"), false, id, naming{unnamed: true}},
		{"a relative name", table(), "held", false, id, naming{unnamed: true}},
		{"deleted, by its former path", table(), filepath.Join(dir, "gone"), true, id, naming{}},
		{"and through a bind of its directory", table(mountEntry{dev: fsDev, root: dir, at: "/srv/b"}), held, false, id,
			naming{aliases: []string{"/srv/b/held"}}},
		{"and through a bind of a directory above it", table(mountEntry{dev: fsDev, root: filepath.Dir(dir), at: "/srv/c"}),
			held, false, id, naming{aliases: []string{filepath.Join("/srv/c", filepath.Base(dir), "held")}}},
		{"not through another filesystem's mount nor another directory's",
			table(mountEntry{dev: devID{8, 2}, root: dir, at: "/srv/d"}, mountEntry{dev: fsDev, root: filepath.Join(dir, "x"), at: "/srv/e"}),
			held, false, id, naming{}},
	} {
		got := (&namer{mounts: c.mounts, seen: map[namingKey]naming{}}).name(c.path, c.deleted, c.id)
		if got.unnamed != c.want.unnamed || !slices.Equal(got.aliases, c.want.aliases) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if got := (&namer{broken: true}).name(held, false, id); !got.unnamed {
		t.Error("a mount table that could not be read names a file")
	}
	if got := (*namer)(nil).name("/x", false, heldID{}); got.unnamed {
		t.Error("a nil namer (an FS with no mount table) leaves a file unnamed")
	}
	var many []mountEntry
	for i := range maxAliases + 1 {
		many = append(many, mountEntry{dev: fsDev, root: dir, at: "/srv/m" + strconv.Itoa(i)})
	}
	if got := (&namer{mounts: table(many...), seen: map[namingKey]naming{}}).name(held, false, id); !got.unnamed {
		t.Errorf("past %d aliases: %+v, want unnamed", maxAliases, got)
	}

	mi := "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		"40 22 8:1 /home/u/my\\040dir /srv/a\\134b rw shared:1 - ext4 /dev/sda1 rw\n"
	got, err := parseMountinfo([]byte(mi))
	if err != nil || len(got) != 2 || got[40] != (mountEntry{dev: devID{8, 1}, root: "/home/u/my dir", at: `/srv/a\b`}) {
		t.Errorf("parseMountinfo = %+v %v", got, err)
	}
	for _, bad := range []string{"", "x 1 8:1 / /\n", "22 1 z:1 / /\n"} {
		if _, err := parseMountinfo([]byte(bad)); err == nil {
			t.Errorf("parseMountinfo(%q) accepted", bad)
		}
	}
	if real, err := readOwnMounts(); err != nil || len(real) == 0 {
		t.Errorf("tego's own mount table: %d mounts, %v", len(real), err)
	} else if _, ok := real[id.mnt]; !ok {
		t.Errorf("the mount of %s (id %d) is not in tego's own mount table", held, id.mnt)
	}
}

// TestFSNamesWhatItListsThroughTegosMounts: FS.FDs and FS.Maps mark each held file, a descriptor through
// /proc/<pid>/fd and a mapping through /proc/<pid>/map_files, from the mount it was opened through. Over a fake /proc
// whose links lead to real files: one on a mount of the table is named, with its alias; with no such mount, the
// file is unnamed; a mapping whose map_files entry cannot be followed is unnamed; a closed descriptor too.
func TestFSNamesWhatItListsThroughTegosMounts(t *testing.T) {
	dir := t.TempDir()
	held := filepath.Join(dir, "held.db")
	if err := os.WriteFile(held, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := statHeld(held)
	if err != nil {
		t.Fatal(err)
	}
	if !id.mntKnown {
		t.Skip("this kernel's statx gives no mount id (STATX_MNT_ID, Linux 5.8)")
	}
	root := t.TempDir()
	pdir := filepath.Join(root, "42")
	for _, d := range []string{"fd", "fdinfo", "map_files"} {
		if err := os.MkdirAll(filepath.Join(pdir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pdir, "stat"), []byte(fakeStatLine(42, 'S', 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{"fd/3": held, "fd/4": filepath.Join(dir, "closed-since"), "map_files/7f00-7f10": held}
	for n, target := range links {
		if err := os.Symlink(target, filepath.Join(pdir, n)); err != nil {
			t.Fatal(err)
		}
	}
	// 7f10-7f20 has no map_files entry: one tego may not follow (no CAP_SYS_ADMIN), or unmapped since. smaps pads an
	// address to eight hex digits (a non-PIE binary's text at 0x400000 is "00400000") and map_files does not: that
	// mapping of held.db is named only when its entry is found by map_files' own spelling.
	if err := os.Symlink(held, filepath.Join(pdir, "map_files", "400000-401000")); err != nil {
		t.Fatal(err)
	}
	smaps := fmt.Sprintf("00400000-00401000 r-xp 00000000 08:01 %d %s\nVmFlags: rd ex mr mw me\n", id.ino, held) +
		fmt.Sprintf("7f00-7f10 rw-s 00000000 08:01 %d %s\nVmFlags: rd wr sh mr mw me ms\n", id.ino, held) +
		fmt.Sprintf("7f20-7f30 r--s 00000000 08:01 %d %s\nVmFlags: rd sh mr me ms\n", id.ino, held+"2") +
		fmt.Sprintf("7f30-7f40 r--s 00000000 08:01 %d %s\nVmFlags: rd sh mr me ms\n", id.ino, held)
	if err := os.WriteFile(filepath.Join(pdir, "smaps"), []byte(smaps), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(held, filepath.Join(pdir, "map_files", "7f30-7f40")); err != nil {
		t.Fatal(err)
	}
	read := func(mounts mountTable) (map[int]FD, map[string]Mapping) {
		t.Helper()
		fs := NewFS(root)
		fs.internal = func() map[devID]bool { return nil }
		fs.mounts = func() (mountTable, error) { return mounts, nil }
		fds, err := fs.FDs(42)
		if err != nil {
			t.Fatal(err)
		}
		byNum := map[int]FD{}
		for _, fd := range fds {
			byNum[fd.Num] = fd
		}
		ms, err := fs.Maps(42)
		if err != nil {
			t.Fatal(err)
		}
		byPath := map[string]Mapping{}
		for _, m := range ms {
			byPath[m.Path] = m
		}
		return byNum, byPath
	}
	fsDev := devID{8, 1}
	fds, maps := read(mountTable{id.mnt: {dev: fsDev, root: "/", at: "/"}, id.mnt + 1: {dev: fsDev, root: dir, at: "/srv/b"}})
	alias := []string{"/srv/b/held.db"}
	if fd := fds[3]; fd.Unnamed || !slices.Equal(fd.Aliases, alias) {
		t.Errorf("a descriptor through a mount of tego's: %+v, want named with aliases %v", fd, alias)
	}
	if fd := fds[4]; !fd.Unnamed {
		t.Errorf("a descriptor closed since the listing: %+v, want unnamed", fd)
	}
	if m := maps[held]; m.Unnamed || !slices.Equal(m.Aliases, alias) || !m.SharedWritable {
		t.Errorf("a mapping through a mount of tego's: %+v, want named, shared writable, aliases %v", m, alias)
	}
	if m := maps[held+"2"]; !m.Unnamed {
		t.Errorf("a mapping whose map_files entry cannot be followed: %+v, want unnamed", m)
	}
	fds, maps = read(mountTable{id.mnt + 1: {dev: fsDev, root: "/", at: "/"}})
	if fd := fds[3]; !fd.Unnamed {
		t.Errorf("a descriptor through a mount tego's namespace does not hold: %+v, want unnamed", fd)
	}
	if m := maps[held]; !m.Unnamed {
		t.Errorf("a mapping through a mount tego's namespace does not hold: %+v, want unnamed", m)
	}
}
