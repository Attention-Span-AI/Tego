// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// PathLocal is PathsLocalIn for one path.
func PathLocal(mounts []Mount, path string) bool { return PathsLocalIn(mounts, path) }

// A mountinfo of a desktop (testdata/mountinfo-desktop.txt, a stock desktop's table, with the names
// neutralised): ext4 root on an NVMe, a vfat boot partition, snaps on squashfs loop devices, tmpfs, and two FUSE mounts.
func TestPathLocalOnADesktopMountTable(t *testing.T) {
	data, err := os.ReadFile("testdata/mountinfo-desktop.txt")
	if err != nil {
		t.Fatal(err)
	}
	mounts := ParseMountInfo(data)
	if len(mounts) < 60 {
		t.Fatalf("parsed %d mounts from the desktop table", len(mounts))
	}
	for path, want := range map[string]bool{
		"/home/user/work/agent.yaml":           true,  // ext4 root
		"/home/user/does/not/exist/yet":        true,  // not there yet: its parent's mount
		"/tmp/x":                               true,  // on the root (or a tmpfs): local either way
		"/dev/shm/x":                           true,  // tmpfs
		"/run/user/1000/tego.sock":             true,  // tmpfs
		"/boot/efi/EFI":                        true,  // vfat on a device node
		"/snap/editor-app/101/bin":             true,  // squashfs on /dev/loop3
		"/proc/sys/fs/binfmt_misc/status":      true,  // binfmt_misc, mounted over the autofs trigger at that point (the later line wins)
		"/run/user/1000/doc/abc/file":          false, // fuse.portal
		"/run/user/1000/gvfs/sftp:host/file":   false, // fuse.gvfsd-fuse
		"relative/agent.yaml":                  false, // cannot be placed
		"":                                     false,
		"/home/user/../../run/user/1000/doc/x": false, // cleaned, never resolved: under the portal mount
	} {
		if got := PathLocal(mounts, path); got != want {
			t.Errorf("PathLocal(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestPathLocalOnThisMachine(t *testing.T) {
	mounts, err := ReadMountInfo()
	if err != nil || len(mounts) == 0 {
		t.Fatalf("this machine's mount table: %d %v", len(mounts), err)
	}
	// Whatever this machine has, the answer is the same for the same table, and the root is a mount.
	if _, ok := indexMounts(mounts).of("/"); !ok {
		t.Fatal("no mount holds /")
	}
	if PathLocal(mounts, "/") != PathLocal(mounts, "/definitely/not/there/yet") {
		t.Fatal("a path that does not exist yet was classed apart from its parent's mount")
	}
	if PathsLocal() || PathsLocal("") {
		t.Fatal("no path at all was called local")
	}
}

const header = "36 35 98:0 / / rw - ext4 /dev/sda1 rw\n"

func TestClassOfFilesystemTypes(t *testing.T) {
	line := func(point, typ, source, super string) string {
		return "50 36 0:40 / " + point + " rw - " + typ + " " + source + " " + super + "\n"
	}
	for _, c := range []struct {
		name  string
		table string
		path  string
		local bool
	}{
		{"nfs", header + line("/mnt/nfs", "nfs", "srv:/export", "rw,vers=3,addr=10.0.0.1"), "/mnt/nfs/a/agent.yaml", false},
		{"nfs4", header + line("/mnt/nfs", "nfs4", "srv:/export", "rw,vers=4.2"), "/mnt/nfs/a", false},
		{"cifs", header + line("/mnt/smb", "cifs", "//srv/share", "rw,vers=3.1.1"), "/mnt/smb/a", false},
		{"smb3", header + line("/mnt/smb", "smb3", "//srv/share", "rw"), "/mnt/smb/a", false},
		{"sshfs", header + line("/mnt/ssh", "fuse.sshfs", "user@srv:/", "rw,user_id=1000,group_id=1000"), "/mnt/ssh/a", false},
		{"plain fuse", header + line("/mnt/f", "fuse", "x", "rw"), "/mnt/f/a", false},
		{"fuseblk (ntfs-3g)", header + line("/mnt/n", "fuseblk", "/dev/sdb1", "rw"), "/mnt/n/a", false},
		{"9p", header + line("/mnt/host", "9p", "share", "rw,trans=virtio"), "/mnt/host/a", false},
		{"virtiofs", header + line("/mnt/vfs", "virtiofs", "share", "rw"), "/mnt/vfs/a", false},
		{"ceph", header + line("/mnt/ceph", "ceph", "10.0.0.1:/", "rw"), "/mnt/ceph/a", false},
		{"afs", header + line("/afs", "afs", "none", "rw"), "/afs/cell/a", false},
		{"autofs", header + line("/net", "autofs", "-hosts", "rw,fd=5,pgrp=1"), "/net/srv/export", false},
		{"unknown type", header + line("/mnt/odd", "somefs2", "x", "rw"), "/mnt/odd/a", false},
		{"xfs", header + line("/data", "xfs", "/dev/sdb1", "rw"), "/data/a", true},
		{"btrfs", header + line("/data", "btrfs", "/dev/sdb1", "rw,subvol=/@"), "/data/a", true},
		{"f2fs", header + line("/data", "f2fs", "/dev/sdb1", "rw"), "/data/a", true},
		{"tmpfs", header + line("/scratch", "tmpfs", "tmpfs", "rw,size=1g"), "/scratch/a", true},
		{"zfs", header + line("/tank", "zfs", "tank/home", "rw"), "/tank/a", true},
		{"bcachefs", header + line("/data", "bcachefs", "/dev/sdb:/dev/sdc", "rw"), "/data/a", true},
		{"vfat on a block device", header + line("/media/usb", "vfat", "/dev/sdc1", "rw"), "/media/usb/a", true},
		{"exfat on a block device", header + line("/media/usb", "exfat", "/dev/sdc1", "rw"), "/media/usb/a", true},
		{"vfat that is not a block device", header + line("/media/usb", "vfat", "server", "rw"), "/media/usb/a", false},
		{"ext4 on a network block device", header + line("/data", "ext4", "/dev/nbd0", "rw"), "/data/a", false},
		{"ext4 on a device-mapper device: its backing store is not in the table, so local", header + line("/data", "ext4", "/dev/mapper/vg-root", "rw"), "/data/a", true},
		{"ext4 on a loop device: the backing file is not in the table, so local", header + line("/data", "ext4", "/dev/loop7", "rw"), "/data/a", true},
		{"a device-mapper device over a network block device is not seen, so local", header + line("/data", "xfs", "/dev/mapper/crypt-nbd0", "rw"), "/data/a", true},
		{"squashfs on a loop device", header + line("/snap/x", "squashfs", "/dev/loop3", "ro"), "/snap/x/a", true},
		{"a bind of an nfs directory", header + "51 36 0:41 /export/sub /srv/bound rw - nfs4 srv:/export rw\n", "/srv/bound/a", false},
		{"a bind of a local directory", header + "51 36 8:17 /sub /srv/bound rw - xfs /dev/sdb1 rw\n", "/srv/bound/a", true},
		{"a local directory below a mount point of nfs in the table but not over it", header + line("/mnt/nfs", "nfs", "s:/e", "rw"), "/mnt/nfsother/a", true},
		{"nfs nested in a local mount", header + line("/data", "xfs", "/dev/sdb1", "rw") + line("/data/share", "nfs4", "s:/e", "rw"), "/data/share/a", false},
		{"a local mount nested in nfs", header + line("/mnt/nfs", "nfs4", "s:/e", "rw") + line("/mnt/nfs/cache", "tmpfs", "tmpfs", "rw"), "/mnt/nfs/cache/a", true},
		{"the nfs parent of that", header + line("/mnt/nfs", "nfs4", "s:/e", "rw") + line("/mnt/nfs/cache", "tmpfs", "tmpfs", "rw"), "/mnt/nfs/a", false},
		{"two mounts at one point: the later one is the visible one", header + line("/data", "nfs4", "s:/e", "rw") + line("/data", "xfs", "/dev/sdb1", "rw"), "/data/a", true},
		{"and the other way", header + line("/data", "xfs", "/dev/sdb1", "rw") + line("/data", "nfs4", "s:/e", "rw"), "/data/a", false},
		{"the mount point itself", header + line("/mnt/nfs", "nfs4", "s:/e", "rw"), "/mnt/nfs", false},
		{"a trailing slash and dots are cleaned, not resolved", header + line("/mnt/nfs", "nfs4", "s:/e", "rw"), "/mnt/nfs/./x/../y/", false},
		{"no mount at all", "", "/data/a", false},
		{"only garbage", "this is not a mount table\n\n", "/data/a", false},
		{"a root that is not there leaves a path unplaced only if no line covers it", "50 36 0:40 / /data rw - xfs /dev/sdb1 rw\n", "/other/a", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := PathLocal(ParseMountInfo([]byte(c.table)), c.path); got != c.local {
				t.Fatalf("PathLocal(%q) = %v, want %v", c.path, got, c.local)
			}
		})
	}
}

// Escapes in mountinfo: a space is \040, a tab \011, a newline \012, a backslash \134. The mount point is the
// decoded path, so a path with a space in it finds its mount.
func TestMountInfoEscapes(t *testing.T) {
	table := header +
		"50 36 0:40 / /mnt/my\\040share rw - nfs4 srv:/my\\040export rw\n" +
		"51 36 0:41 / /mnt/tab\\011and\\134slash rw - xfs /dev/sdb1 rw\n"
	mounts := ParseMountInfo([]byte(table))
	if PathLocal(mounts, "/mnt/my share/agent.yaml") {
		t.Fatal("a mount with an escaped space in its point was not found")
	}
	if !PathLocal(mounts, "/mnt/tab\tand\\slash/agent.yaml") {
		t.Fatal("a mount with an escaped tab and backslash in its point was not found")
	}
	// The undecoded spelling is another path, which is under the root mount.
	if !PathLocal(mounts, `/mnt/my\040share/agent.yaml`) {
		t.Fatal("the literal spelling of an escape is a plain directory name under /")
	}
	for _, bad := range []string{`/mnt/bad\04`, `/mnt/bad\9zz`, `/mnt/bad\`} {
		got := ParseMountInfo([]byte("50 36 0:40 / " + bad + " rw - xfs /dev/sdb1 rw\n"))
		if len(got) != 0 {
			t.Fatalf("a malformed escape %q was accepted: %+v", bad, got)
		}
	}
}

// Optional fields (shared:N, master:N, propagate_from:N, unbindable) sit between the options and the dash.
func TestMountInfoOptionalFields(t *testing.T) {
	for _, line := range []string{
		"50 36 0:40 / /data rw - xfs /dev/sdb1 rw",
		"50 36 0:40 / /data rw shared:5 - xfs /dev/sdb1 rw",
		"50 36 0:40 / /data rw shared:5 master:2 propagate_from:3 - xfs /dev/sdb1 rw",
		"50 36 0:40 / /data rw unbindable - xfs /dev/sdb1 rw",
	} {
		m := ParseMountInfo([]byte(line))
		if len(m) != 1 || m[0].Point != "/data" || m[0].Type != "xfs" || m[0].Source != "/dev/sdb1" {
			t.Fatalf("%q: %+v", line, m)
		}
	}
	for _, line := range []string{"", "50 36 0:40 / /data rw", "50 36 0:40 / /data rw - xfs", "- - - - - - - - -", "50 36 0:40 / data rw - xfs /dev/sdb1 rw"} {
		if m := ParseMountInfo([]byte(line)); len(m) != 0 {
			t.Fatalf("%q was taken for a mount: %+v", line, m)
		}
	}
}

// An overlay is local only when every layer it is made of is on a local mount that is not itself an overlay.
func TestOverlayIsLocalWhenItsLayersAre(t *testing.T) {
	ov := func(super string) string {
		return "60 36 0:50 / /merged rw - overlay overlay " + super + "\n"
	}
	local := header + "51 36 8:17 / /var/lib/layers rw - xfs /dev/sdb1 rw\n"
	nfs := header + "51 36 0:41 / /var/lib/layers rw - nfs4 s:/e rw\n"
	for _, c := range []struct {
		name  string
		table string
		local bool
	}{
		{"all layers on a local mount", local + ov("rw,lowerdir=/var/lib/layers/l1:/var/lib/layers/l2,upperdir=/var/lib/layers/up,workdir=/var/lib/layers/work"), true},
		{"layers on the root", local + ov("rw,lowerdir=/usr:/opt,upperdir=/up,workdir=/work"), true},
		{"a lower layer on nfs", nfs + ov("rw,lowerdir=/var/lib/layers/l1:/usr,upperdir=/up,workdir=/work"), false},
		{"the upper layer on nfs", nfs + ov("rw,lowerdir=/usr,upperdir=/var/lib/layers/up,workdir=/work"), false},
		{"a read-only overlay without an upper layer", local + ov("ro,lowerdir=/usr:/opt"), true},
		{"the new mount API's lowerdir+", local + ov("rw,lowerdir+=/usr,lowerdir+=/opt,upperdir=/up,workdir=/work"), true},
		{"a data-only layer after ::", local + ov("rw,lowerdir=/usr::/opt"), true},
		{"a data-only layer on nfs", nfs + ov("rw,lowerdir=/usr::/var/lib/layers/d"), false},
		{"a layer on a fuse mount", header + "51 36 0:41 / /var/lib/layers rw - fuse.sshfs u@h:/ rw\n" + ov("rw,lowerdir=/usr,upperdir=/var/lib/layers/up,workdir=/var/lib/layers/w"), false},
		{"a lower layer on a fuse mount", header + "51 36 0:41 / /var/lib/layers rw - fuse.mergerfs m rw\n" + ov("rw,lowerdir=/var/lib/layers/l:/usr"), false},
		{"no layer named in the options", local + ov("rw"), false},
		{"a relative layer", local + ov("rw,lowerdir=usr,upperdir=/up,workdir=/work"), false},
		{"a layer name with an escaped colon is split and one piece is no path: not shown local", local + ov(`rw,lowerdir=/us\072r,upperdir=/up,workdir=/work`), false},
		{"a layer on another overlay", header + "52 36 0:51 / /lay rw - overlay overlay rw,lowerdir=/usr\n" + ov("rw,lowerdir=/lay/x,upperdir=/lay/up,workdir=/lay/w"), false},
		// A container's root: its layers are directories of the host, which this table does not have; the longest
		// mount holding them is the overlay itself.
		{"a container's overlay root", "70 1 0:60 / /merged rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A:/var/lib/docker/overlay2/l/B,upperdir=/var/lib/docker/overlay2/x/diff,workdir=/var/lib/docker/overlay2/x/work\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := PathLocal(ParseMountInfo([]byte(c.table)), "/merged/a"); got != c.local {
				t.Fatalf("PathLocal = %v, want %v", got, c.local)
			}
		})
	}
}

// A table that cannot be read is the class that may stop answering.
func TestPathsLocalWithAnUnreadableTable(t *testing.T) {
	if PathLocal(nil, "/data/a") || PathsLocalIn(nil, "/data/a") || PathsLocalIn(ParseMountInfo(nil), "/data/a") {
		t.Fatal("an empty mount table classed a path local")
	}
	if PathsLocalIn(ParseMountInfo([]byte(header)), "/a", "relative") || PathsLocalIn(ParseMountInfo([]byte(header))) {
		t.Fatal("one unplaced path, or none, was called local")
	}
	if !PathsLocalIn(ParseMountInfo([]byte(header)), "/a", "", "/b") {
		t.Fatal("two local paths and an empty one were not local")
	}
}

func FuzzParseMountInfo(f *testing.F) {
	data, _ := os.ReadFile("testdata/mountinfo-desktop.txt")
	f.Add(data, "/home/user/x")
	f.Add([]byte(header+"60 36 0:50 / /m rw - overlay overlay rw,lowerdir=/a:/b::/c,upperdir=/u,workdir=/w\n"), "/m/x")
	f.Add([]byte("50 36 0:40 / /a\\040b rw - nfs4 s:/e rw\n"), "/a b/c")
	f.Fuzz(func(t *testing.T, table []byte, path string) {
		mounts := ParseMountInfo(table)
		for _, m := range mounts {
			if m.Point == "" || m.Point[0] != '/' {
				t.Fatalf("a mount point that is not absolute: %q", m.Point)
			}
		}
		_ = PathLocal(mounts, path) // never panics; any answer is fine
		_ = PathsLocalIn(mounts, path, "/")
	})
}

func TestAMountTableLargerThanTheCapIsNotClassified(t *testing.T) {
	line := "50 36 0:40 / /mnt/a rw - xfs /dev/sdb1 rw\n"
	table := strings.Repeat(line, 100)
	if m, err := readMountInfo(strings.NewReader(table), int64(len(table))); err != nil || len(m) != 100 {
		t.Fatalf("a table of exactly the cap: %d mounts, %v", len(m), err)
	}
	if _, err := readMountInfo(strings.NewReader(table), int64(len(table))-1); !errors.Is(err, ErrMountInfoTooLarge) {
		t.Fatalf("a table one byte over the cap: %v", err)
	}
	if maxMountInfo < 1<<20 {
		t.Fatal("the cap is below what a busy container host has")
	}
}
