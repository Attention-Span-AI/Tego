// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// MountOf is the strict table's answer for supplied bytes (ParseMountTableStrict, then MountTable.Of), for the
// tests of supplied rows: a table the parser refuses says nothing, Held false.
func MountOf(mountinfo []byte, p string) FileMount {
	mt, err := ParseMountTableStrict(mountinfo)
	if err != nil {
		return FileMount{}
	}
	return mt.Of(p)
}

// parseMountLine reads one mountinfo line leniently, for building test fixtures only: a line it cannot read is
// skipped. Every product reader goes through parseMountRecord. Fields are split on spaces alone.
func parseMountLine(line string) (mount, bool) {
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' })
	if len(fields) < 7 {
		return mount{}, false
	}
	// The separator follows the mount options (field 5) and any optional fields; a root or mount point that
	// is "-" itself comes before it and is not the separator.
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(fields) {
		return mount{}, false
	}
	m := mount{id: fields[0], parent: fields[1], point: unescapeMount(fields[4]), fstype: fields[sep+1], dev: fields[2], root: unescapeMount(fields[3])}
	if sep+2 < len(fields) {
		m.source = unescapeMount(fields[sep+2])
	}
	if sep+3 < len(fields) {
		m.super = fields[sep+3]
	}
	return m, true
}

// readMountSnapshot parses what r gives (at most one byte past the bound) as ReadMountSnapshot parses a file, and
// returns compile's view of it: the parsed table, or an empty probed table carrying the error.
func readMountSnapshot(r io.Reader, name string, live bool) (*mountTable, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxMountTableBytes+1))
	if err == nil {
		var mt *MountTable
		if mt, err = parseMountSnapshot(b, name, live); err == nil {
			return &mt.t, nil
		}
	}
	return &mountTable{probed: true, live: live, err: err}, err
}

// This fixture lists a same-point stack bottom first. Lookup and the print
// identify its top filesystem using parent edges, independently of row order.
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
		{"overlay", "lowerdir=l1,upperdir=/u", []string{"/u"}, "overlay (layers named relative to a folder the mount table does not record)"},
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

// TestTreeAliases: every place other than a directory itself where a mount table shows its tree or part of it, the
// places a reader reaches its files through without naming it: a bind of the directory beside it and beneath a
// sibling, a bind of its parent, a bind of one directory and of one file inside it, and the whole filesystem bound
// elsewhere. A mount of another device with the same root, a sibling whose root only shares a prefix and the
// directory's own mount add nothing, and neither does a filesystem mounted beneath it where it is mounted elsewhere
// too, the root filesystem bound beneath it among them, which would make "/" an alias. DetachedParts is the binds of a
// part of the tree outside it, the places a walk across mounts reaches without passing the directory. A table that
// holds no mount of the directory cannot list them (ok false).
func TestTreeAliases(t *testing.T) {
	binds := strings.Join([]string{
		"2 1 8:1 /p/secret /p/alias rw - ext4 /dev/sda1 rw",
		"3 1 8:1 /p/secret /p/pub/alias rw - ext4 /dev/sda1 rw",
		"4 1 8:1 /p /mnt/parent rw - ext4 /dev/sda1 rw",
		"5 1 8:1 /p/secret/deep /mnt/deep rw - ext4 /dev/sda1 rw",
		"6 1 8:1 /p/secret/key /mnt/key rw - ext4 /dev/sda1 rw",
		"7 1 8:1 / /mnt/whole rw - ext4 /dev/sda1 rw",
		"8 1 8:1 /p/secretive /mnt/near rw - ext4 /dev/sda1 rw",
		"9 1 0:40 /p/secret /mnt/othertmp rw - tmpfs tmpfs rw",
		"10 1 0:41 / /p/secret/sub rw - tmpfs tmpfs rw",
		"11 1 0:41 /x /mnt/subx rw - tmpfs tmpfs rw",
		"12 1 8:1 /p/secret/deep /p/secret/inner rw - ext4 /dev/sda1 rw",
		"13 1 8:1 / /p/secret/rootfs rw - ext4 /dev/sda1 rw",
	}, "\n")
	rows := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" + binds
	mt, err := ParseMountTableStrict([]byte(rows))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := mt.TreeAliases("/p/secret")
	slices.Sort(got)
	want := []string{"/mnt/deep", "/mnt/key", "/mnt/parent/secret", "/mnt/whole/p/secret", "/p/alias", "/p/pub/alias",
		"/p/secret/inner", "/p/secret/rootfs/p/secret"}
	if !ok || !slices.Equal(got, want) {
		t.Errorf("TreeAliases(/p/secret) = %q, %v, want %q, true", got, ok, want)
	}
	got, ok = mt.DetachedParts("/p/secret")
	slices.Sort(got)
	if want := []string{"/mnt/deep", "/mnt/key"}; !ok || !slices.Equal(got, want) {
		t.Errorf("DetachedParts(/p/secret) = %q, %v, want %q, true", got, ok, want)
	}
	if got, ok := mt.TreeAliases("/q"); !ok || len(got) != 2 || !slices.Contains(got, "/mnt/whole/q") || !slices.Contains(got, "/p/secret/rootfs/q") {
		t.Errorf("TreeAliases(/q) = %q, %v, want the whole filesystem's two binds", got, ok)
	}
	// A table without the root's mount places nothing: no parser keeps part of it for a security decision.
	if mt, err := ParseMountTableStrict([]byte(binds)); mt != nil || !errors.Is(err, ErrMountSnapshot) {
		t.Errorf("a table without the root's mount: %v, %v, want no table and ErrMountSnapshot", mt, err)
	}
	// MountOf is the parsed table's answer.
	if a, b := MountOf([]byte(rows), "/p/secret/key"), mt.Of("/p/secret/key"); !slices.Equal(a.Aliases, b.Aliases) || !b.Held {
		t.Errorf("MountOf = %+v, MountTable.Of = %+v, want one answer", a, b)
	}
}

// TestMountTableFollowsTheMountTree is the review's topology (fix round 1): a tmpfs at /p/secret, then /src bound over
// /p, which hides that tmpfs, then /p/secret/deep, which is /src's by then, bound at /pub/part. The longest mount point
// text picked the hidden tmpfs for /p/secret and missed /pub/part; the mount tree picks the bind over /p, and
// /pub/part is a detached part of /p/secret. A mount stacked on a point is the child of the one it covers.
func TestMountTableFollowsTheMountTree(t *testing.T) {
	rows := strings.Join([]string{
		"22 1 8:1 / / rw - ext4 /dev/sda1 rw",
		"30 22 0:40 / /p/secret rw - tmpfs tmpfs rw",
		"31 22 8:1 /src /p rw - ext4 /dev/sda1 rw",
		"32 22 8:1 /src/secret/deep /pub/part rw - ext4 /dev/sda1 rw",
		"33 22 0:41 / /stack rw - tmpfs tmpfs rw",
		"34 33 0:42 / /stack rw - tmpfs tmpfs rw",
	}, "\n")
	mt, err := ParseMountTableStrict([]byte(rows))
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := mt.MountID("/p/secret/deep/key"); !ok || id != 31 {
		t.Errorf("MountID(/p/secret/deep/key) = %d, %v; want 31, the bind over /p, not the hidden tmpfs", id, ok)
	}
	if got, ok := mt.DetachedParts("/p/secret"); !ok || !slices.Equal(got, []string{"/pub/part"}) {
		t.Errorf("DetachedParts(/p/secret) = %q, %v; want [/pub/part]", got, ok)
	}
	if id, _ := mt.MountID("/stack/x"); id != 34 {
		t.Errorf("MountID(/stack/x) = %d, want 34, the mount stacked on top", id)
	}
	if ma, mi, ok := mt.Device("/p/secret"); !ok || ma != 8 || mi != 1 {
		t.Errorf("Device(/p/secret) = %d:%d, %v; want 8:1", ma, mi, ok)
	}
	// Two mounts of one parent at one point cannot be ordered: the path is not placed.
	tie := rows + "\n35 22 0:43 / /q rw - tmpfs tmpfs rw\n36 22 0:44 / /q rw - tmpfs tmpfs rw"
	if mt, err := ParseMountTableStrict([]byte(tie)); err != nil {
		t.Fatal(err)
	} else if _, ok := mt.MountID("/q/x"); ok {
		t.Errorf("two siblings at /q: placed, want not")
	} else if _, ok := mt.MountID("/p/x"); !ok {
		t.Errorf("a path the tie does not touch: not placed")
	}
}

// TestParseMountTableStrict: enforcement never decides on part of a table. A malformed row after a valid root, a row
// whose ids are no numbers, a relative mount point, a table with no root or two, and one past the byte bound are
// errors; no reader keeps the rest of such a table. An nsfs bind's root that is no path is a well-formed row.
func TestParseMountTableStrict(t *testing.T) {
	root := "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
	for name, table := range map[string]string{
		"a malformed row":    root + "30 22 8:1 /p/secret /pub/alias rw ext4 /dev/sda1 rw\n",
		"ids that are words": root + "x 22 8:1 /p /q rw - ext4 /dev/sda1 rw\n",
		"a relative point":   root + "30 22 8:1 /p q rw - ext4 /dev/sda1 rw\n",
		"no root":            "30 22 8:1 /p /q rw - ext4 /dev/sda1 rw\n",
		"two roots":          root + "23 2 8:2 / / rw - ext4 /dev/sda2 rw\n",
		"past the bound":     root + strings.Repeat("#", maxMountTableBytes),
	} {
		if _, err := ParseMountTableStrict([]byte(table)); !errors.Is(err, ErrMountSnapshot) {
			t.Errorf("%s: %v, want ErrMountSnapshot", name, err)
		}
	}
	ns := root + "40 22 0:4 net:[4026532008] /run/netns/x rw - nsfs nsfs rw\n"
	if _, err := ParseMountTableStrict([]byte(ns)); err != nil {
		t.Errorf("an nsfs bind: %v", err)
	}
	// The snapshot reader reads a file whole and strictly.
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	if mt, b, err := ReadMountSnapshot(path); err != nil || string(b) != root || !mt.Of("/x").Held {
		t.Errorf("ReadMountSnapshot = %v, %q, %v", mt, b, err)
	}
	if _, _, err := ReadMountSnapshot(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Errorf("an absent table read")
	}
}

func TestParseMountTableStrictRejectsIncompleteRecordsAndGraphs(t *testing.T) {
	root := "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
	for name, row := range map[string]string{
		"no source or super options": "30 22 8:1 /secret /alias rw - ext4",
		"no super options":           "30 22 8:1 /secret /alias rw - ext4 /dev/sda1",
		"no mount options":           "30 22 8:1 /secret /alias - ext4 /dev/sda1 rw",
		"extra fields":               "30 22 8:1 /secret /alias rw - ext4 /dev/sda1 rw extra",
		"empty required field":       "30 22 8:1 /secret /alias rw - ext4  rw",
		"unclean point":              "30 22 8:1 /secret /alias/../elsewhere rw - ext4 /dev/sda1 rw",
		"unclean root":               "30 22 8:1 /deep/../secret /alias rw - ext4 /dev/sda1 rw",
		"relative filesystem root":   "30 22 8:1 secret /alias rw - ext4 /dev/sda1 rw",
		"nul in point":               `30 22 8:1 /secret /alias\000 rw - ext4 /dev/sda1 rw`,
		"device words":               "30 22 disk:one /secret /alias rw - ext4 /dev/sda1 rw",
		"device without minor":       "30 22 8 /secret /alias rw - ext4 /dev/sda1 rw",
		"device with extra colon":    "30 22 8:1:2 /secret /alias rw - ext4 /dev/sda1 rw",
		"device overflows":           "30 22 8:4294967296 /secret /alias rw - ext4 /dev/sda1 rw",
		"signed device":              "30 22 +8:1 /secret /alias rw - ext4 /dev/sda1 rw",
		"signed id":                  "+30 22 8:1 /secret /alias rw - ext4 /dev/sda1 rw",
		"duplicate id":               "22 22 8:1 /secret /alias rw - ext4 /dev/sda1 rw",
		"duplicate id can cycle":     "30 22 8:1 /secret /alias rw - ext4 /dev/sda1 rw\n30 30 8:1 /secret /alias rw - ext4 /dev/sda1 rw",
		"parent cycle":               "30 31 8:1 /secret /alias rw - ext4 /dev/sda1 rw\n31 30 8:1 /secret /alias rw - ext4 /dev/sda1 rw",
		"self parent below root":     "30 30 8:1 /secret /alias rw - ext4 /dev/sda1 rw",
		"unlisted nonroot parent":    "30 99 8:1 /secret /alias rw - ext4 /dev/sda1 rw",
		"point outside parent":       "30 22 8:1 /secret /alias rw - ext4 /dev/sda1 rw\n31 30 8:1 /secret/deep /elsewhere rw - ext4 /dev/sda1 rw",
	} {
		t.Run(name, func(t *testing.T) {
			mt, err := ParseMountTableStrict([]byte(root + row + "\n"))
			if mt != nil || !errors.Is(err, ErrMountSnapshot) {
				t.Fatalf("ParseMountTableStrict = %v, %v; want no table and ErrMountSnapshot", mt, err)
			}
		})
	}
}

// TestParseMountTableStrictRefusesNonCanonicalDevicesAndTerminatesGraphs: one device has one spelling, the kernel's
// (%u:%u), so a same-device search cannot miss a row spelled otherwise: a leading zero refuses the table. Parent
// rows need not precede their children.
func TestParseMountTableStrictRefusesNonCanonicalDevicesAndTerminatesGraphs(t *testing.T) {
	root := "22 22 8:1 / / rw - ext4 /dev/sda1 rw\n"
	if mt, err := ParseMountTableStrict([]byte("30 22 08:01 /secret /alias rw - ext4 /dev/sda1 rw\n" + root)); mt != nil || !errors.Is(err, ErrMountSnapshot) {
		t.Fatalf("a device spelled 08:01: %v, %v; want no table and ErrMountSnapshot", mt, err)
	}
	mt, err := ParseMountTableStrict([]byte("30 22 8:1 /secret /alias rw - ext4 /dev/sda1 rw\n" + root))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := mt.TreeAliases("/secret"); !ok || !slices.Equal(got, []string{"/alias"}) {
		t.Fatalf("TreeAliases = %q, %v; want [/alias], true", got, ok)
	}
	if id, ok := mt.MountID("/alias/key"); !ok || id != 30 {
		t.Fatalf("MountID = %d, %v; want 30, true", id, ok)
	}
}

func TestCompileMountFactsRejectPartialTables(t *testing.T) {
	root := "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
	for name, content := range map[string]string{
		"incomplete row": root + "30 22 8:1 /secret /alias rw - ext4\n",
		"byte bound":     root + strings.Repeat("x", maxMountTableBytes),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mountinfo")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			mt, err := loadMountTable(path)
			if !errors.Is(err, ErrMountSnapshot) || len(mt.mounts) != 0 || !mt.bindExposed("/project") {
				t.Fatalf("loadMountTable = %+v, %v; want no partial facts, ErrMountSnapshot, and scopes retained", mt, err)
			}
		})
	}
}
