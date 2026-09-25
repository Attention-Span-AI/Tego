// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Mounts stacked on one point are listed bottom first; a path there reaches the last, and the print names its
// file system type, not the one it hides.
func TestMountTableTakesTheTopOfStackedMounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	rows := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		"2 1 0:30 / /work rw - ext4 /dev/sda2 rw\n" +
		"3 2 0:31 / /work rw - tmpfs tmpfs rw\n" +
		"4 3 0:32 / /work rw - overlay overlay rw\n"
	if err := os.WriteFile(path, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := loadMountTable(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/work", "/work/src"} {
		m, _, ok := tbl.lookup(p)
		if !ok || m.fstype != "overlay" {
			t.Errorf("lookup(%s) = %+v, want the top mount, overlay", p, m)
		}
	}
	if m, _, _ := tbl.lookup("/etc"); m.fstype != "ext4" {
		t.Errorf("lookup(/etc) = %+v, want the root's ext4", m)
	}
}

// TestWithMountInfoEmptyDisablesProbe: WithMountInfo("") disables the mount probe, as it says, so a hermetic
// compile names no mount of the machine it runs on. The default replaced "" with /proc/self/mountinfo, so the
// callers passing "" for exactly that still read the host's mount table.
func TestWithMountInfoEmptyDisablesProbe(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"./out/\"]\n"), WithMountInfo(""))
	for _, r := range rt.FS {
		if r.Mount != "" || r.Filesystem != "" {
			t.Errorf("rule %s names mount %q (%s) with the probe disabled", r.Path, r.Mount, r.Filesystem)
		}
	}
}

// TestMountOf: the other places a mount table shows a file at (ADR 0064 D2). A bind
// mount of a directory above the file, or of its whole filesystem, shows it below that mount's point; a mount of
// another device, a mount of the same device whose root does not hold the file, a sibling whose root only shares a
// prefix, and the file's own mount show none. A mount point with an escaped space is unescaped. A table that shows no
// mount holding the file (empty, or a chroot's, which skips the mount above its root) says so, Held
// false, even where it lists a bind of the file's directory: the file's place in its filesystem is unknown. For a
// directory, a bind of a directory strictly beneath it shows part of its tree elsewhere (Beneath).
func TestMountOf(t *testing.T) {
	binds := "2 1 8:2 /home/u/.local/bin /home/u/ws/bin rw - ext4 /dev/sda2 rw\n" +
		"3 1 8:2 / /mnt/whole\\040fs rw - ext4 /dev/sda2 rw\n" +
		"4 1 8:2 /home/u/.local/binx /home/u/ws/binx rw - ext4 /dev/sda2 rw\n" +
		"5 1 8:2 /etc /home/u/ws/etc rw - ext4 /dev/sda2 rw\n" +
		"6 1 0:40 /home/u/.local/bin /home/u/ws/other rw - tmpfs tmpfs rw\n"
	rows := "1 0 8:2 / / rw - ext4 /dev/sda2 rw\n" + binds
	fm := MountOf([]byte(rows), "/home/u/.local/bin/tego")
	slices.Sort(fm.Aliases)
	if want := []string{"/home/u/ws/bin/tego", "/mnt/whole fs/home/u/.local/bin/tego"}; !fm.Held || !slices.Equal(fm.Aliases, want) ||
		len(fm.Beneath) != 0 || fm.Device != "8:2" || fm.Source != "/dev/sda2" || fm.Layers != nil || fm.Unmapped != "" {
		t.Errorf("MountOf = %+v, want aliases %q, held, on 8:2 from /dev/sda2", fm, want)
	}
	// The file seen from inside the bind: its own mount is the bind, and the original place is another name of it.
	fm = MountOf([]byte(rows), "/home/u/ws/bin/tego")
	slices.Sort(fm.Aliases)
	if want := []string{"/home/u/.local/bin/tego", "/mnt/whole fs/home/u/.local/bin/tego"}; !fm.Held || !slices.Equal(fm.Aliases, want) {
		t.Errorf("MountOf from the bind = %+v, want aliases %q, held", fm, want)
	}
	// A directory: the binds of /home/u/.local/bin and /home/u/.local/binx lie beneath /home/u, and /etc's does not.
	fm = MountOf([]byte(rows), "/home/u")
	slices.Sort(fm.Beneath)
	if want := []string{"/home/u/ws/bin", "/home/u/ws/binx"}; !slices.Equal(fm.Beneath, want) {
		t.Errorf("MountOf(/home/u).Beneath = %q, want %q", fm.Beneath, want)
	}
	for name, table := range map[string]string{"an empty table": "", "a table without the root's mount": binds} {
		if fm := MountOf([]byte(table), "/home/u/.local/bin/tego"); fm.Held || len(fm.Aliases) != 0 {
			t.Errorf("%s: MountOf = %+v, want none and not held", name, fm)
		}
	}
}

// TestMountOfStackingLayers (ADR 0064 D2): an overlay shows its layers' files,
// whose names its options give as seq_show_option escapes them (octal for ',', '=', space, tab, newline and
// backslash; lowerdir a ':' list in which a backslash keeps the next byte and "::" comes before data-only layers;
// lowerdir+ and datadir+ one layer each). A relative layer, or none, cannot be placed; FUSE, eCryptfs, aufs and shiftfs
// name no layer at all; other filesystems have none.
func TestMountOfStackingLayers(t *testing.T) {
	row := func(fstype, super string) []byte {
		return []byte("1 0 8:2 / / rw - ext4 /dev/sda2 rw\n3 1 0:50 / /m rw - " + fstype + " src rw," + super + "\n")
	}
	for _, c := range []struct {
		fstype, super string
		layers        []string
		unmapped      string
	}{
		{"overlay", `lowerdir=/l1:/l\134:2::/d1,upperdir=/up\040per,workdir=/w\054x,redirect_dir=on`,
			[]string{"/l1", "/l:2", "/d1", "/up per", "/w,x"}, ""},
		{"overlay", "lowerdir+=/a,lowerdir+=/b/,datadir+=/c,upperdir=/u,workdir=/w", []string{"/a", "/b", "/c", "/u", "/w"}, ""},
		{"overlay", "lowerdir=l1,upperdir=/u", nil, `overlay (a layer "l1" it cannot place)`},
		{"overlay", "upperdir=/u,workdir=/w", nil, "overlay (no lower layer named in its options)"},
		{"fuse.sshfs", "user_id=1000", nil, "fuse.sshfs"},
		{"fuse", "user_id=1000", nil, "fuse"},
		{"ecryptfs", "ecryptfs_sig=x", nil, "ecryptfs"},
		{"ext4", "lowerdir=/l1", nil, ""},
	} {
		fm := MountOf(row(c.fstype, c.super), "/m/bin/tego")
		if !fm.Held || !slices.Equal(fm.Layers, c.layers) || fm.Unmapped != c.unmapped || fm.Device != "0:50" || fm.Source != "src" {
			t.Errorf("%s %s: MountOf = %+v, want layers %q, unmapped %q", c.fstype, c.super, fm, c.layers, c.unmapped)
		}
	}
}
