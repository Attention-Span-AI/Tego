// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// kernelStatx fakes statx(2) for a mount table read as this process's own (live): the answer for a path names the
// mount the kernel shows there (the visible row at the deepest mount point at or above the path; a hidden mount's point
// answers for the mount on top), and the type is a regular file for a visible unlinked root (a runtime's single-file
// bind) and a directory otherwise.
func kernelStatx(t *testing.T, plain *MountTable) {
	t.Helper()
	idOf := func(p string) (uint64, bool) {
		for q := filepath.Clean(p); ; q = filepath.Dir(q) {
			if i, ok := plain.t.visiblePoints[q]; ok {
				n, _ := strconv.ParseUint(plain.t.mounts[i].id, 10, 64)
				return n, plain.t.mounts[i].unlinkedRoot() && q == filepath.Clean(p)
			}
			if q == "/" {
				return 0, false
			}
		}
	}
	fake := func(_ int, p string, _ int, _ int, st *unix.Statx_t) error {
		id, file := idOf(p)
		st.Mnt_id = id
		st.Mask = unix.STATX_MNT_ID | unix.STATX_TYPE | unix.STATX_INO
		st.Mode = unix.S_IFDIR
		if file {
			st.Mode = unix.S_IFREG
		}
		return nil
	}
	oldL, oldB := statLiveMount, statBackingFile
	t.Cleanup(func() { statLiveMount, statBackingFile = oldL, oldB })
	statLiveMount, statBackingFile = fake, fake
}

// liveStyle parses a captured table as the calling process's own, with statx answering as the kernel does.
func liveStyle(t *testing.T, raw []byte) (*MountTable, error) {
	t.Helper()
	plain, err := ParseMountTableStrict(raw)
	if err != nil {
		return nil, err
	}
	kernelStatx(t, plain)
	return parseMountSnapshot(raw, liveMountInfo, true)
}

// TestHiddenMountsNeverDoubtAFilesystem: a mount hidden under another shows nothing under any name, so its unknown type
// never puts the filesystem it sits on in doubt (round 6, Z1). systemd-nspawn's captured table, read as live, holds an
// unlinked boot_id bind under the /proc/sys bind; before the fix every path on the container's /run was doubted and every
// compile refused (every contract has built-in deny entries on /run). Every other captured table in the repository
// (Docker, Podman, bubblewrap, toolbox, snap, WSL2, desktop, chroot) gets the same replay: no device may be in doubt.
func TestHiddenMountsNeverDoubtAFilesystem(t *testing.T) {
	tables, hidden, partial := 0, 0, 0
	err := filepath.WalkDir("testdata", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".mountinfo") {
			return err
		}
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.NewReplacer("@HOME@", "/fixture/home", "@HOST@", "/fixture/host", "{{ROOT}}", "/fixture").Replace(string(data)))
			var rows []string
			for _, row := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
				if !strings.HasPrefix(row, "#") {
					rows = append(rows, row)
				}
			}
			live, err := liveStyle(t, []byte(strings.Join(rows, "\n")+"\n"))
			if err != nil {
				// A host-side or chroot capture is not a whole table: the strict reader refuses it as one, which
				// is the answer it must give (a compile on such a table refuses with the reason), so the case is
				// checked, not skipped. Any other error fails.
				if !errors.Is(err, ErrMountSnapshot) {
					t.Fatalf("reading the table: %v; want a table or %v", err, ErrMountSnapshot)
				}
				partial++
				return
			}
			tables++
			devs := map[string]bool{}
			for _, m := range live.t.mounts {
				devs[m.dev] = true
				if m.unlinkedRoot() && !live.t.visible(m) {
					hidden++
					t.Logf("hidden unlinked root: %s", m.point)
				}
			}
			for dev := range devs {
				if why := live.t.unlinkedOn(dev); why != "" {
					t.Errorf("device %s is in doubt: %s", dev, why)
				}
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tables < 40 || hidden == 0 || partial > 10 {
		t.Fatalf("replayed %d tables with %d hidden unlinked roots and %d partial captures: the nspawn capture (a hidden one) must be among them, and partial captures may not crowd out whole ones", tables, hidden, partial)
	}
}

// TestNspawnLiveTableListsTheRunNames: the captured nspawn table as live names every other name of the /run files the
// built-in rules deny with no doubt, as the supplied table does.
func TestNspawnLiveTableListsTheRunNames(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "chroot-mountinfo", "nspawn.mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	live, err := liveStyle(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/run", "/run/dbus/system_bus_socket", "/run/user/0", "/home/runner/proj/.env", "/root/.ssh"} {
		if _, why := live.t.otherNames(p); why != "" {
			t.Errorf("otherNames(%q) uncertain: %s", p, why)
		}
	}
	if why := live.aliasUncertainty(live.Of("/run"), "/run"); why != "" {
		t.Errorf("the public alias query doubts /run: %s", why)
	}
}

// TestVisibleUnlinkedDirectoryStillDoubts: the rule is about hidden mounts only. A visible unlinked directory root (or
// one of unknown type) still doubts its device, and the refusal names the mount.
func TestVisibleUnlinkedDirectoryStillDoubts(t *testing.T) {
	table := "1 0 8:1 / / rw - ext4 disk rw\n2 1 8:2 /gone//deleted /srv/dir rw - ext4 disk rw\n3 1 8:2 / /srv/other rw - ext4 disk rw\n"
	plain, err := ParseMountTableStrict([]byte(table))
	if err != nil {
		t.Fatal(err)
	}
	kernelStatx(t, plain) // answers a directory for a point that is not an unlinked root: set the type by hand below
	old := statBackingFile
	t.Cleanup(func() { statBackingFile = old })
	statBackingFile = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error {
		st.Mnt_id = 2
		st.Mask = unix.STATX_MNT_ID | unix.STATX_TYPE
		st.Mode = unix.S_IFDIR
		return nil
	}
	live, err := parseMountSnapshot([]byte(table), liveMountInfo, true)
	if err != nil {
		t.Fatal(err)
	}
	if why := live.t.unlinkedOn("8:2"); !strings.Contains(why, `"/srv/dir"`) || !strings.Contains(why, "unlinked directory root") {
		t.Errorf("visible unlinked directory: %q", why)
	}
}
