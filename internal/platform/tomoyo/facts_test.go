// SPDX-License-Identifier: Apache-2.0

package tomoyo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeKernel stands in for the kernel facts the facts directory's check reads: the opened file's filesystem magic, its
// mount id, the path /proc/self/fd names for it, and mountinfo. It returns the restore function.
type fakeKernel struct {
	magic     uint32
	mountID   uint64
	mountIDEr error
	link      string // "": the opened path itself
	mountinfo string
	miErr     error
}

func (k fakeKernel) install(t *testing.T) {
	t.Helper()
	oldMagic, oldID, oldMI, oldLink := statfsType, statxMountID, readMountinfo, fdPath
	t.Cleanup(func() {
		statfsType, statxMountID, readMountinfo, fdPath = oldMagic, oldID, oldMI, oldLink
		_ = SetFactsDir("")
	})
	statfsType = func(*os.File) (uint32, error) { return k.magic, nil }
	statxMountID = func(*os.File) (uint64, error) { return k.mountID, k.mountIDEr }
	readMountinfo = func() ([]byte, error) { return []byte(k.mountinfo), k.miErr }
	fdPath = func(f *os.File) (string, error) {
		if k.link != "" {
			return k.link, nil
		}
		return f.Name(), nil
	}
}

const securityfsMagic = uint32(unix.SECURITYFS_MAGIC)

// factsFixture is a directory holding the three fact files, as a container's bind of /sys/kernel/security/tomoyo would,
// and the mountinfo line a mount of it at that directory has when root and options are as given.
func factsFixture(t *testing.T, root, opts, fstype string) (dirPath, mountinfo string) {
	t.Helper()
	dirPath = t.TempDir()
	for name, body := range map[string]string{"self_domain": "<kernel>\n", "stat": stockLine, "profile": "PROFILE_VERSION=20150505\n"} {
		if err := os.WriteFile(filepath.Join(dirPath, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mountinfo = "20 1 0:5 / /sys rw - sysfs sysfs rw\n" +
		"41 20 0:19 " + root + " " + dirPath + " " + opts + " master:2 - " + fstype + " securityfs rw\n"
	return dirPath, mountinfo
}

// TestFactsDirAccepted: a read-only bind of TOMOYO's own directory on securityfs is read in place of the kernel's path,
// each of the three facts, with the same proofs as before.
func TestFactsDirAccepted(t *testing.T) {
	for name, root := range map[string]string{"the whole directory": "/tomoyo"} {
		t.Run(name, func(t *testing.T) {
			d, mi := factsFixture(t, root, "ro,nosuid,nodev,noexec,relatime", "securityfs")
			fakeKernel{magic: securityfsMagic, mountID: 41, mountinfo: mi}.install(t)
			if err := SetFactsDir(d); err != nil {
				t.Fatal(err)
			}
			for _, n := range factNames {
				if b, err := ReadFile(filepath.Join(d, n)); err != nil || len(b) == 0 {
					t.Errorf("%s: %q, %v", n, b, err)
				}
			}
			if err := Check(ReadFile); err != nil {
				t.Errorf("the never-updated machine through the facts directory: %v", err)
			}
		})
	}
}

// TestFactsDirFileBinds: each file bound by itself (`-v .../tomoyo/stat:/run/x/stat:ro`) is accepted when its mount's
// root is that very file, and refused when it is another file of the directory.
func TestFactsDirFileBinds(t *testing.T) {
	d, _ := factsFixture(t, "/tomoyo", "ro", "securityfs")
	stat := filepath.Join(d, "stat")
	bind := func(root string) string {
		return "50 20 0:19 " + root + " " + stat + " ro - securityfs securityfs rw\n"
	}
	fakeKernel{magic: securityfsMagic, mountID: 50, mountinfo: bind("/tomoyo/stat")}.install(t)
	if err := SetFactsDir(d); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(stat); err != nil {
		t.Errorf("a bind of the stat file itself: %v", err)
	}
	fakeKernel{magic: securityfsMagic, mountID: 50, mountinfo: bind("/tomoyo/profile")}.install(t)
	_ = SetFactsDir(d)
	if _, err := ReadFile(stat); err == nil || !strings.Contains(err.Error(), "/tomoyo/profile") {
		t.Errorf("another file of the directory bound in stat's place: %v", err)
	}
}

// TestFactsDirRefuses: anything but TOMOYO's own files, bound read-only on securityfs, refuses with the held-open words
// the kernel's path gives, and names what is wrong.
func TestFactsDirRefuses(t *testing.T) {
	const ok = "ro,nosuid,nodev,noexec,relatime"
	for _, tc := range []struct {
		name   string
		root   string
		opts   string
		fstype string
		k      func(*fakeKernel)
		want   string
	}{
		{name: "a wrong filesystem (tmpfs)", root: "/tomoyo", opts: ok, fstype: "tmpfs", k: func(k *fakeKernel) { k.magic = unix.TMPFS_MAGIC }, want: "is not on securityfs"},
		{name: "mountinfo says another filesystem", root: "/tomoyo", opts: ok, fstype: "tmpfs", want: "mounted as tmpfs"},
		{name: "a wrong root (AppArmor's directory)", root: "/apparmor", opts: ok, fstype: "securityfs", want: "/apparmor/"},
		{name: "the root of securityfs", root: "/", opts: ok, fstype: "securityfs", want: "path /stat in its filesystem"},
		{name: "a writable bind", root: "/tomoyo", opts: "rw,nosuid,nodev,noexec,relatime", fstype: "securityfs", want: "writable"},
		{name: "no mount id", root: "/tomoyo", opts: ok, fstype: "securityfs", k: func(k *fakeKernel) { k.mountIDEr = errors.New("no STATX_MNT_ID") }, want: "mount id"},
		{name: "a mount id mountinfo does not hold", root: "/tomoyo", opts: ok, fstype: "securityfs", k: func(k *fakeKernel) { k.mountID = 99 }, want: "no mountinfo line"},
		{name: "unreadable mountinfo", root: "/tomoyo", opts: ok, fstype: "securityfs", k: func(k *fakeKernel) { k.miErr = errors.New("no /proc") }, want: "mountinfo"},
		{name: "a link in the path", root: "/tomoyo", opts: ok, fstype: "securityfs", k: func(k *fakeKernel) { k.link = "/sys/kernel/security/apparmor/stat" }, want: "link"},
		{name: "a mount point that is not above the file", root: "/tomoyo", opts: ok, fstype: "securityfs", k: func(k *fakeKernel) {
			k.mountinfo = "41 20 0:19 /tomoyo /somewhere/else " + ok + " - securityfs securityfs rw\n"
		}, want: "not under"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, mi := factsFixture(t, tc.root, tc.opts, tc.fstype)
			k := fakeKernel{magic: securityfsMagic, mountID: 41, mountinfo: mi}
			if tc.k != nil {
				tc.k(&k)
			}
			k.install(t)
			if err := SetFactsDir(d); err != nil {
				t.Fatal(err)
			}
			_, err := ReadFile(filepath.Join(d, "stat"))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "held file opens are refused on this machine") {
				t.Fatalf("ReadFile = %v, want a refusal naming %q", err, tc.want)
			}
			if err := Check(ReadFile); err == nil {
				t.Error("Check admitted a facts directory that is not TOMOYO's")
			}
			// The supervisor's own reader opens the file and asks CheckFact.
			f, err := os.Open(filepath.Join(d, "stat"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if err := CheckFact(f.Name(), f); err == nil {
				t.Error("CheckFact admitted a facts directory that is not TOMOYO's")
			}
		})
	}
}

// TestFactsDirTmpfsRefuses is the case no fake stands in for: a real directory on this machine's tmpfs or disk, with the
// real fstatfs, is not securityfs.
func TestFactsDirTmpfsRefuses(t *testing.T) {
	d, _ := factsFixture(t, "/tomoyo", "ro", "securityfs")
	t.Cleanup(func() { _ = SetFactsDir("") })
	if err := SetFactsDir(d); err != nil {
		t.Fatal(err)
	}
	if err := Check(ReadFile); err == nil || !strings.Contains(err.Error(), "is not on securityfs") {
		t.Fatalf("a directory of ordinary files: %v", err)
	}
}

// TestSetFactsDirRefusesWhatIsNotAbsolute: a facts directory that is relative or unclean is an error, and every fact is
// then refused rather than read from the kernel's path.
func TestSetFactsDirRefusesWhatIsNotAbsolute(t *testing.T) {
	t.Cleanup(func() { _ = SetFactsDir("") })
	for _, bad := range []string{"run/x", "/run/../x", "/run//x", "/run/x/", "/"} {
		if err := SetFactsDir(bad); err == nil {
			t.Errorf("SetFactsDir(%q) = nil", bad)
		}
		read := func(p string) ([]byte, error) { t.Errorf("%q: read %s", bad, p); return nil, errors.New("read") }
		if err := Check(read); err == nil || !strings.Contains(err.Error(), "not a clean absolute path") {
			t.Errorf("%q: Check = %v", bad, err)
		}
	}
}

// TestFactsDirDefaultUnchanged: with no facts directory the kernel's paths are read as before, no mountinfo is
// consulted, and FactsDir names the kernel's directory.
func TestFactsDirDefaultUnchanged(t *testing.T) {
	_ = SetFactsDir("")
	oldMI := readMountinfo
	t.Cleanup(func() { readMountinfo = oldMI })
	readMountinfo = func() ([]byte, error) {
		t.Error("mountinfo read for the kernel's own path")
		return nil, errors.New("no")
	}
	var seen []string
	read := func(p string) ([]byte, error) {
		seen = append(seen, p)
		if p == selfDomain {
			return []byte("<kernel>\n"), nil
		}
		return []byte(stockLine), nil
	}
	if err := Check(read); err != nil {
		t.Fatal(err)
	}
	for _, p := range seen {
		if !strings.HasPrefix(p, "/sys/kernel/security/tomoyo/") {
			t.Errorf("read %s", p)
		}
	}
	if Configured() || FactsDir() != "/sys/kernel/security/tomoyo" {
		t.Errorf("Configured %v, FactsDir %q", Configured(), FactsDir())
	}
}

// TestFactsDirIsReadInPlaceOfTheKernelsPath: with a facts directory set, Check reads its three files and nothing under
// the kernel's path, and an error names the path it read.
func TestFactsDirIsReadInPlaceOfTheKernelsPath(t *testing.T) {
	t.Cleanup(func() { _ = SetFactsDir("") })
	if err := SetFactsDir("/run/tego-tomoyo"); err != nil {
		t.Fatal(err)
	}
	var seen []string
	read := func(p string) ([]byte, error) {
		seen = append(seen, p)
		if strings.HasSuffix(p, "/stat") {
			return nil, os.ErrPermission
		}
		return []byte("<kernel>\n"), nil
	}
	err := Check(read)
	if err == nil || !strings.Contains(err.Error(), "/run/tego-tomoyo/stat") {
		t.Errorf("Check = %v", err)
	}
	for _, p := range seen {
		if !strings.HasPrefix(p, "/run/tego-tomoyo/") {
			t.Errorf("read %s", p)
		}
	}
	if FactsDir() != "/run/tego-tomoyo" || !Configured() {
		t.Errorf("FactsDir %q", FactsDir())
	}
}

// TestFindMountUnescapes: mountinfo writes a space, tab, newline and backslash of a path as an octal escape, a mount's
// line is found by its id alone, and a line this check cannot read is an error, never a guess.
func TestFindMountUnescapes(t *testing.T) {
	raw := []byte("12 1 0:3 / /x rw - tmpfs t rw\n" +
		`41 20 0:19 /tomoyo /run/my\040facts\134dir ro,nosuid master:2 shared:3 - securityfs securityfs rw` + "\n" +
		"42 20 0:19 /tomoyo /run/short ro\n" +
		`43 20 0:19 /tomoyo /run/bad\777 ro - securityfs securityfs rw` + "\n")
	m, err := findMount(raw, 41)
	if err != nil || m.root != "/tomoyo" || m.point != `/run/my facts\dir` || m.options != "ro,nosuid" || m.fstype != "securityfs" {
		t.Errorf("findMount(41) = %+v, %v", m, err)
	}
	for _, id := range []uint64{42, 43, 44} {
		if _, err := findMount(raw, id); err == nil {
			t.Errorf("findMount(%d) = nil error", id)
		}
	}
}

// TestFactsSeamsOnTheRealKernel: the three real readers answer for a file of this machine, unprivileged: its descriptor's
// path is the opened one, its mount id has a line in the real mountinfo, and that line is not securityfs.
func TestFactsSeamsOnTheRealKernel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if link, err := fdPath(f); err != nil || link != p {
		t.Fatalf("fdPath = %q, %v; want %q", link, err, p)
	}
	id, err := statxMountID(f)
	if err != nil {
		t.Skipf("no mount ids on this kernel: %v", err)
	}
	raw, err := readMountinfo()
	if err != nil {
		t.Fatal(err)
	}
	m, err := findMount(raw, id)
	if err != nil || m.fstype == "securityfs" || !strings.HasPrefix(p, m.point) {
		t.Errorf("mount %d of %s = %+v, %v", id, p, m, err)
	}
}
