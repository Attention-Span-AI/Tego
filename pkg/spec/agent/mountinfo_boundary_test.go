// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMountStackUsesParentsBeforeRowOrder(t *testing.T) {
	// Mount 2 was moved onto the newer mount 3. Its older ID prints first.
	table := visibleMountFixture(t, "1 0 8:1 / / rw - ext4 disk rw\n2 3 0:2 / /work/m rw - cgroup2 cgroup rw\n3 1 0:3 / /work/m rw - tmpfs none rw\n")
	m, _, ok := table.lookup("/work/m/control")
	if !ok || m.id != "2" {
		t.Fatalf("moved stack top = %+v, known=%v; want mount 2", m, ok)
	}
}

func TestCompileRefusesMovedControlMount(t *testing.T) {
	f := newFixture(t)
	point := filepath.Join(f.project, "out", "m")
	if err := os.MkdirAll(point, 0o755); err != nil {
		t.Fatal(err)
	}
	mi := fakeMountInfo(f, "2 3 0:2 / "+point+" rw - cgroup2 cgroup rw", "3 1 0:3 / "+point+" rw - tmpfs none rw")
	for _, field := range []string{"write", "ask"} {
		_, ds, err := Compile(f.load(strings.Replace(writeSection(filepath.Dir(point)), "write:", field+":", 1)), f.machine, f.opts(mi)...)
		if err == nil || !strings.Contains(render(ds), "cgroup2 filesystem mounted at "+point) {
			t.Errorf("fs.%s admitted a moved control mount: %v\n%s", field, err, render(ds))
		}
	}
}

// TestCompileRefusesAmbiguousMountVisibility: two siblings at one point leave its visibility unknown, and the
// refusal names the point; a parent cycle refuses the table whole (validateMountGraph) and says so.
func TestCompileRefusesAmbiguousMountVisibility(t *testing.T) {
	for _, topology := range []string{"siblings", "cycle"} {
		t.Run(topology, func(t *testing.T) {
			f := newFixture(t)
			point := filepath.Join(f.project, "out", "m")
			if err := os.MkdirAll(point, 0o755); err != nil {
				t.Fatal(err)
			}
			parentA, parentB := "1", "1"
			if topology == "cycle" {
				parentA, parentB = "3", "2"
			}
			mi := fakeMountInfo(f, "2 "+parentA+" 8:2 / "+point+" rw - ext4 disk rw", "3 "+parentB+" 0:3 / "+point+" rw - tmpfs none rw")
			for _, field := range []string{"write", "ask"} {
				_, ds, err := Compile(f.load(strings.Replace(writeSection(filepath.Dir(point)), "write:", field+":", 1)), f.machine, f.opts(mi)...)
				want := []string{"mount visibility", point}
				if topology == "cycle" {
					want = []string{"cannot be read whole", "parent cycle at mount"}
				}
				for _, w := range want {
					if err == nil || !strings.Contains(render(ds), w) {
						t.Errorf("fs.%s must be refused naming %q (%s): %v\n%s", field, w, topology, err, render(ds))
					}
				}
			}
		})
	}
}

func TestLayerClosureKeepsUnreadableLiveCandidate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("root bypasses directory search permissions; run this unit check as an ordinary user")
		return
	}
	dir := t.TempDir()
	storage := filepath.Join(dir, "storage")
	private := filepath.Join(storage, "private")
	if err := os.MkdirAll(filepath.Join(private, "lower"), 0o755); err != nil {
		t.Fatal(err)
	}
	live, err := loadMountTable("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	m, _, ok := live.lookup(storage)
	if !ok {
		t.Fatal("cannot establish the temp tree's real mount identity")
	}
	// Model a bind of an absent host parent using the temp tree's real mount ID.
	// All identity reads, including statx's EACCES, run against the real tree.
	m.point, m.root, m.parent = storage, "/host/layers", "0"
	table := &mountTable{probed: true, live: true, mounts: []mount{m}}
	table.order()
	if err := os.Chmod(private, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o755) })
	candidate := filepath.Join(private, "lower")
	if _, err := os.Stat(candidate); !errors.Is(err, unix.EACCES) {
		t.Fatalf("candidate stat = %v; want EACCES", err)
	}
	if _, _, ok := table.lookup(candidate); ok {
		t.Fatal("unsearchable candidate acquired an identity")
	}
	_, _, unseen, _ := layerClosure(table, []string{"/host/layers/private/lower"})
	if !strings.Contains(unseen, candidate) || !strings.Contains(unseen, "permission denied") {
		t.Fatalf("unreadable live candidate disappeared: %q", unseen)
	}
}

func TestMountSnapshotRejectsMalformedRows(t *testing.T) {
	for _, row := range []string{
		"broken", "2 1 8:2 / /work rw - ext4", "bad 1 8:2 / /work rw - ext4 disk rw",
		"2 1 bad / /work rw - ext4 disk rw", "2 1 8:2 relative /work rw - ext4 disk rw",
		"2 1 8:2 / relative rw - ext4 disk rw", "2 1 8:2 / /work\\999 rw - ext4 disk rw",
		"1 0 8:2 / /work rw - ext4 disk rw",
	} {
		t.Run(fmt.Sprintf("%q", row), func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "mountinfo")
			if err := os.WriteFile(file, []byte("1 0 8:1 / / rw - ext4 disk rw\n"+row+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			table, err := loadMountTable(file)
			if err == nil || table.err == nil || len(table.mounts) != 0 {
				t.Fatalf("partial or malformed snapshot accepted: table=%+v err=%v", table, err)
			}
		})
	}
}

func TestMountVisibilityVerifiesDiscardedCandidates(t *testing.T) {
	point := t.TempDir()
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, point, unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &st); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprint(st.Mnt_id)
	if st.Mask&unix.STATX_MNT_ID == 0 {
		t.Log("kernel does not expose mount IDs")
		return
	}
	// The graph says the invented row covers the real mount. A live check at
	// this descendant contradicts it, before any security scan may discard rows.
	table := visibleMountFixture(t, fmt.Sprintf("%s 0 8:1 / %s rw - cgroup2 cgroup rw\n999999999 %s 0:3 / %s rw - tmpfs none rw\n", id, point, id, point))
	table.live = true
	table.order()
	for _, m := range table.mounts {
		if table.visible(m) {
			t.Errorf("contradictory live topology supplied visible mount %+v", m)
		}
	}
}

func TestMountAliasesKeepFailedIdentity(t *testing.T) {
	f := newFixture(t)
	protected := filepath.Join(f.root, "protected")
	parent := filepath.Join(f.project, "out", "alias")
	for _, d := range []string{protected, parent} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink loop is a deterministic failed identity read. It is not proof
	// that another filesystem covers the mapped protected path.
	alias := filepath.Join(parent, "target")
	if err := os.Symlink(alias, alias); err != nil {
		t.Fatal(err)
	}
	table := visibleMountFixture(t, "1 0 8:1 / / rw - ext4 disk rw\n2 1 8:1 "+protected+" "+parent+" rw - ext4 disk rw\n")
	table.live = true
	// Reindexing this deliberately synthetic table would fail every live ID;
	// lookup itself must still preserve the failed alias read for the target walk.
	live, err := loadMountTable("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	holding, _, ok := live.lookup(protected)
	if !ok {
		t.Fatal("protected path has no live identity")
	}
	// Only the source's lookup must have a real ID; the alias's ELOOP must be
	// retained regardless of whether that candidate ID could be verified.
	table.mounts[table.mountIDs["1"]].id = holding.id
	fm := table.fileMount(filepath.Join(protected, "target"))
	found := false
	for _, p := range fm.Aliases {
		found = found || p == alias
	}
	if !found {
		t.Fatalf("failed alias identity was discarded: %+v", fm)
	}
}

func TestMountOfRefusesPartialSnapshot(t *testing.T) {
	for _, extra := range []string{"broken\n", "1 0 8:2 / /elsewhere rw - ext4 disk rw\n"} {
		fm := MountOf([]byte("1 0 8:1 / / rw - ext4 disk rw\n"+extra), "/protected")
		if fm.Held {
			t.Fatalf("MountOf inferred identity from a partial snapshot: %+v", fm)
		}
	}
}

func TestMountSnapshotAllowsNamespaceHandles(t *testing.T) {
	file := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(file, []byte("1 0 8:1 / / rw - ext4 disk rw\n2 1 0:4 mnt:[12345] /handles/ns rw - nsfs nsfs rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := loadMountTable(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := table.placeOf("/handles/ns"); ok {
		t.Fatal("namespace handle was treated as a filesystem-relative place")
	}
	if !table.bindExposed("/handles/ns") {
		t.Fatal("non-path namespace identity was used to rule out alternate exposure")
	}
	if got := table.controlFS("/handles"); !strings.Contains(got, "nsfs") {
		t.Fatalf("namespace handle lost its refused filesystem type: %q", got)
	}
}

func TestCompileNamesAmbiguousProtectedMount(t *testing.T) {
	f := newFixture(t)
	point := filepath.Join(f.root, "protected-mount")
	profiles := filepath.Join(point, "profiles")
	if err := os.MkdirAll(profiles, 0o755); err != nil {
		t.Fatal(err)
	}
	machine := *f.machine
	machine.Profiles.Value = profiles
	mi := fakeMountInfo(f, "2 1 8:2 / "+point+" rw - ext4 disk rw", "3 1 8:3 / "+point+" rw - ext4 disk rw")
	for _, field := range []string{"write", "ask"} {
		_, ds, err := Compile(f.load(strings.Replace(writeSection(filepath.Join(f.project, "out")), "write:", field+":", 1)), &machine, f.opts(mi)...)
		if err == nil || !strings.Contains(render(ds), "mount visibility at "+point+" is unknown") {
			t.Errorf("fs.%s did not name protected mount %s: %v\n%s", field, point, err, render(ds))
		}
	}
}

func TestMountVisibilityKeepsUnrelatedOmittedParentsUnknown(t *testing.T) {
	table := visibleMountFixture(t, "10 9 8:10 /new /vol rw - ext4 disk rw\n20 19 0:20 /old /vol/sub rw - cgroup2 cgroup rw\n")
	// A chroot may omit its enclosing mount. Distinct omitted parent IDs do
	// not establish that the child belongs under the visible ancestor.
	if m, _, ok := table.lookup("/vol/sub/control"); ok {
		t.Fatalf("unplaced child silently hidden by %+v", m)
	}
}
