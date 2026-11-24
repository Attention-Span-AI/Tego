// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestOwnerFSKind: the file systems whose owner and permission bits a rules file's trust cannot rest on, told by the
// statfs magic and by the mount row (ADR 0059, amended 2026-11-19, rounds 4 and 5). WSL's Windows drive is said to be
// one, by drvfs's options on 9p or virtiofs and by WSL 1's drvfs type; a FUSE file system whose mount row cannot be
// read is refused (FUSE alone does not say whose files it shows); ordinary Linux file systems, NFS, tmpfs, overlay and
// FUSE file systems run by a user's daemon are not refused.
func TestOwnerFSKind(t *testing.T) {
	const ext4, btrfs, tmpfs, nfs, overlay, fuse = 0xef53, 0x9123683e, 0x01021994, 0x6969, 0x794c7630, unix.FUSE_SUPER_MAGIC
	wslSuper := `rw,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=5,access=client,msize=65536,trans=fd,rfd=6,wfd=6`
	for _, c := range []struct {
		name                 string
		magic                int64
		fstype, point, super string
		want                 string
		windows              bool
	}{
		{"WSL 2's Windows drive", unix.V9FS_MAGIC, "9p", "/mnt/c", wslSuper, "the Windows drive (9p mounted at /mnt/c)", true},
		{"a Windows drive the table could not show", unix.V9FS_MAGIC, "", "", "", "a 9p share", false},
		{"WSL 1's drvfs", 0x53464846, "drvfs", "/mnt/c", "rw", "the Windows drive (drvfs mounted at /mnt/c)", true},
		{"WSL's drive through virtiofs", fuse, "virtiofs", "/mnt/d", "rw,aname=drvfs;path=D:\\", "the Windows drive (virtiofs mounted at /mnt/d)", true},
		{"another 9p share", unix.V9FS_MAGIC, "9p", "/srv/share", "rw,trans=virtio", "a 9p share mounted at /srv/share", false},
		{"a virtiofs share", fuse, "virtiofs", "/mnt/host", "rw", "a virtiofs share of the host's files mounted at /mnt/host", false},
		{"a FAT stick", unix.MSDOS_SUPER_MAGIC, "vfat", "/media/u/STICK", "rw,uid=1000", "a FAT disk mounted at /media/u/STICK", false},
		{"an exFAT disk", unix.EXFAT_SUPER_MAGIC, "exfat", "/media/u/X", "rw", "an exFAT disk mounted at /media/u/X", false},
		{"an NTFS disk (ntfs3)", ntfs3Magic, "ntfs3", "/media/u/W", "rw", "an NTFS disk mounted at /media/u/W", false},
		{"an NTFS disk (ntfs-3g)", fuse, "fuseblk", "/media/u/W", "rw", "a disk mounted through FUSE (fuseblk) mounted at /media/u/W", false},
		{"an SMB share", unix.SMB2_SUPER_MAGIC, "smb3", "/mnt/share", "rw", "an SMB share mounted at /mnt/share", false},
		{"a FUSE file system whose row cannot be read", fuse, "", "", "", "a FUSE file system whose mount tego could not look up", false},
		{"ext4", ext4, "ext4", "/", "rw", "", false},
		{"btrfs", btrfs, "btrfs", "/home", "rw", "", false},
		{"tmpfs", tmpfs, "tmpfs", "/tmp", "rw", "", false},
		{"NFS", nfs, "nfs4", "/home", "rw", "", false},
		{"overlay", overlay, "overlay", "/", "rw", "", false},
		{"sshfs (a user's FUSE daemon)", fuse, "fuse.sshfs", "/mnt/remote", "rw", "", false},
	} {
		what, windows := ownerFSKind(c.magic, c.fstype, c.point, c.super)
		if what != c.want || windows != c.windows {
			t.Errorf("%s: %q, windows=%v; want %q, windows=%v", c.name, what, windows, c.want, c.windows)
		}
	}
}

// onFS makes every rules file under dir look as if it lies on the file system the four facts describe, for this test.
func onFS(t *testing.T, dir string, magic int64, fstype, point, super string) {
	t.Helper()
	prev := rulesFileFS
	rulesFileFS = func(f *os.File) (int64, string, string, string, error) {
		if strings.HasPrefix(f.Name(), dir+string(filepath.Separator)) {
			return magic, fstype, point, super, nil
		}
		return prev(f)
	}
	t.Cleanup(func() { rulesFileFS = prev })
}

// TestReadRulesFileRefusesUnreliableFileSystems (ADR 0059, amended 2026-11-19, rounds 4 and 5; guest row W-N3-DRIVE):
// ReadRulesFile refuses a rules file on WSL's Windows drive, a FAT disk or a FUSE file system whose mount row it could
// not read, asked of the descriptor it reads, with words that say why and where to keep it instead; it reads one in the
// Linux home; and it refuses a file it cannot look at (fail closed).
func TestReadRulesFileRefusesUnreliableFileSystems(t *testing.T) {
	root := t.TempDir()
	const body = "version: 0\nname: t\ncommand: [\"true\"]\n"
	read := func(p string) ([]byte, error) {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		return ReadRulesFile(context.Background(), f, p, 1<<20)
	}
	for _, c := range []struct {
		dir, fstype, point, super string
		magic                     int64
		words                     []string
	}{
		{"drive", "9p", "/mnt/c", `rw,aname=drvfs;path=C:\;uid=1000`, unix.V9FS_MAGIC, []string{"the Windows drive (9p mounted at /mnt/c)",
			"any Windows program can change the rules", "keep the rules file, and every file it extends, in your Linux home",
			"the project may stay where it is"}},
		{"stick", "vfat", "/media/u/STICK", "rw,uid=1000", unix.MSDOS_SUPER_MAGIC, []string{"a FAT disk mounted at /media/u/STICK"}},
		{"fuse", "", "", "", unix.FUSE_SUPER_MAGIC, []string{"a FUSE file system whose mount tego could not look up"}},
	} {
		dir := filepath.Join(root, c.dir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		onFS(t, dir, c.magic, c.fstype, c.point, c.super)
		p := filepath.Join(dir, "agent.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := read(p)
		if !errors.Is(err, ErrOwnerUnreliable) || !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: %v; want refused as unreliable and untrusted", c.dir, err)
			continue
		}
		for _, w := range append([]string{p}, c.words...) {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the refusal lacks %q: %v", c.dir, w, err)
			}
		}
	}
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	inHome := filepath.Join(home, "agent.yaml")
	if err := os.WriteFile(inHome, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := read(inHome); err != nil || string(data) != body {
		t.Errorf("a rules file in the Linux home: %q, %v", data, err)
	}
	// A file that cannot be looked at: a descriptor closed under the reader.
	f, err := os.Open(inHome)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close() // the read below must refuse what it cannot look at
	if _, err := ReadRulesFile(context.Background(), f, inHome, 1<<20); !errors.Is(err, ErrOwnerUnreliable) {
		t.Errorf("a file that cannot be looked at: %v; want refused", err)
	}
}

// cancelAfterRead is a reader that cancels its context during its first read.
type cancelAfterRead struct {
	cancel func()
	calls  int
}

func (r *cancelAfterRead) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 1 {
		return 0, io.EOF
	}
	r.cancel()
	p[0] = 'x'
	return 1, nil
}

// TestReadRulesFileStopsBetweenReads: a profile graph's budget cancels a read between two reads of the file.
func TestReadRulesFileStopsBetweenReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := &cancelAfterRead{cancel: cancel}
	_, err := io.ReadAll(ctxReader{ctx: ctx, r: raw})
	if !errors.Is(err, context.Canceled) || raw.calls != 1 {
		t.Fatalf("continued reading after cancellation: calls=%d err=%v", raw.calls, err)
	}
}

// TestMountRowByID: the row of a mount id, its point unescaped; none for an id no well-formed row has.
func TestMountRowByID(t *testing.T) {
	table := []byte("60 1 8:48 / / rw,relatime - ext4 /dev/sdd rw\n" +
		"75 60 0:33 / /mnt/c rw,noatime - 9p C:\\134 rw,aname=drvfs;path=C:\\134;uid=1000\n" +
		"80 60 0:40 / /mnt/my\\040disk rw shared:2 - vfat /dev/sdb1 rw,uid=1000\n" +
		"90 60 0:41 / /broken rw\n")
	for _, c := range []struct{ id, fstype, point, super string }{
		{"75", "9p", "/mnt/c", `rw,aname=drvfs;path=C:\134;uid=1000`},
		{"80", "vfat", "/mnt/my disk", "rw,uid=1000"},
		{"90", "", "", ""},
		{"99", "", "", ""},
	} {
		fstype, point, super := mountRowByID(table, c.id)
		if fstype != c.fstype || point != c.point || super != c.super {
			t.Errorf("row %s: %q %q %q; want %q %q %q", c.id, fstype, point, super, c.fstype, c.point, c.super)
		}
	}
}
