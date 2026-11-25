// SPDX-License-Identifier: Apache-2.0

package lsmlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const goodBoot = "5f1c0f1e-0f0c-4a64-8e4b-1f4f7e0a9c11"

// rig is a directory tree standing for a container's filesystem: the walk starts at its root, the trusted owner is this
// test's own uid, and the boot id is goodBoot. The list file is at <root>/run/tego-lsm/lsm-list, in directories only the
// owner can write.
type rig struct {
	root, dir, file string
}

func newRig(t *testing.T) rig {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "run", "tego")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(root, "run"), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	boot := filepath.Join(root, "boot_id")
	if err := os.WriteFile(boot, []byte(goodBoot+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldUID, oldRoot, oldBoot, oldMagic, oldBind := trustedUID, walkRoot, bootIDPath, fsMagic, checkBind
	trustedUID, walkRoot, bootIDPath = uint32(os.Getuid()), root, boot //nolint:gosec // a uid
	t.Cleanup(func() {
		trustedUID, walkRoot, bootIDPath, fsMagic, checkBind = oldUID, oldRoot, oldBoot, oldMagic, oldBind
		_ = SetFile("")
	})
	fsMagic = func(*os.File) (uint32, error) { return unix.EXT4_SUPER_MAGIC, nil }
	r := rig{root: root, dir: dir, file: filepath.Join(dir, "lsm-list")}
	r.write(t, handedIn(goodBoot, "capability,landlock,yama,apparmor"), 0o644)
	if err := SetFile(r.file); err != nil {
		t.Fatal(err)
	}
	return r
}

func handedIn(boot, list string) string {
	return Format + "\nboot_id " + boot + "\nlsm " + list + "\n"
}

func (r rig) write(t *testing.T, body string, mode os.FileMode) {
	t.Helper()
	_ = os.Remove(r.file)
	if err := os.WriteFile(r.file, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.file, mode); err != nil {
		t.Fatal(err)
	}
}

// wantRefused runs Read and wants an *Unusable whose words contain every fragment, and no list.
func wantRefused(t *testing.T, what string, tid int, status string, frags ...string) {
	t.Helper()
	list, _, err := Read(tid, func(string) ([]byte, error) { return []byte(status), nil })
	var u *Unusable
	if !errors.As(err, &u) {
		t.Errorf("%s: err %v (list %q), want an *Unusable", what, err, list)
		return
	}
	if list != "" {
		t.Errorf("%s: refused but returned the list %q", what, list)
	}
	for _, f := range frags {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("%s: %q lacks %q", what, err.Error(), f)
		}
	}
}

// status is a /proc/<tid>/status of a task whose permitted and effective sets are both caps, as after a plain exec.
func status(uids string, caps string) string {
	return statusSets(uids, caps, caps)
}

// statusSets is a status with its own permitted and effective sets, in the order the kernel prints them.
func statusSets(uids, prm, eff string) string {
	return "Name:\tagent\nUid:\t" + uids + "\nGid:\t10001\t10001\t10001\t10001\nCapInh:\t0000000000000000\nCapPrm:\t" + prm + "\nCapEff:\t" + eff + "\n"
}

const agentStatus = "Name:\tagent\nUid:\t10001\t10001\t10001\t10001\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"

// TestHandedInListIsRead: the file an entrypoint wrote, in root's directories, with this boot's id, is the list.
func TestHandedInListIsRead(t *testing.T) {
	newRig(t)
	list, kind, err := Read(0, nil)
	if err != nil || list != "capability,landlock,yama,apparmor" || kind != KindHandedIn {
		t.Fatalf("Read = %q, %v, %v", list, kind, err)
	}
	// For a trapped task too, when it is not root and holds nothing.
	if list, _, err = Read(77, func(n string) ([]byte, error) {
		if n != "/proc/77/status" {
			t.Errorf("read %s", n)
		}
		return []byte(agentStatus), nil
	}); err != nil || list == "" {
		t.Errorf("for a task: %q, %v", list, err)
	}
}

func TestNoFileIsNotConfigured(t *testing.T) {
	newRig(t)
	if err := SetFile(""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(0, nil); !errors.Is(err, ErrNotConfigured) || Configured() {
		t.Errorf("no setting: %v, configured %v", err, Configured())
	}
}

// TestBadSettingRefusesAndNeverFallsBack: an unusable value is kept as a refusal, not read as "none".
func TestBadSettingRefusesAndNeverFallsBack(t *testing.T) {
	newRig(t)
	for _, bad := range []string{"relative/lsm", "/run/../run/lsm", "/run//lsm", "/run/lsm/", "/"} {
		if err := SetFile(bad); err == nil {
			t.Errorf("SetFile(%q) accepted", bad)
		}
		if !Configured() {
			t.Errorf("%q: not counted as configured", bad)
		}
		wantRefused(t, bad, 0, "", "not a clean absolute path")
	}
}

// TestUnusableFilesAreRefused: every way a file is not what root wrote in this boot.
func TestUnusableFilesAreRefused(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		r := newRig(t)
		_ = os.Remove(r.file)
		wantRefused(t, "missing", 0, "", "is not there", "entrypoint writes it at start")
	})
	t.Run("directory in place of the file", func(t *testing.T) {
		r := newRig(t)
		_ = os.Remove(r.file)
		if err := os.Mkdir(r.file, 0o755); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, "directory", 0, "", "not a regular file")
	})
	t.Run("final link", func(t *testing.T) {
		r := newRig(t)
		real := filepath.Join(r.dir, "real")
		if err := os.WriteFile(real, []byte(handedIn(goodBoot, "capability")), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(r.file)
		if err := os.Symlink(real, r.file); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, "link", 0, "", "is a link")
	})
	t.Run("link in the path", func(t *testing.T) {
		r := newRig(t)
		if err := os.Symlink(r.dir, filepath.Join(r.root, "run", "alias")); err != nil {
			t.Fatal(err)
		}
		if err := SetFile(filepath.Join(r.root, "run", "alias", "lsm-list")); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, "link in path", 0, "", "has a link in its path", "name the real path")
	})
	t.Run("a file where a directory should be", func(t *testing.T) {
		r := newRig(t)
		if err := SetFile(filepath.Join(r.root, "boot_id", "x")); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, "file as dir", 0, "", "not a directory")
	})
	t.Run("a pipe", func(t *testing.T) {
		r := newRig(t)
		_ = os.Remove(r.file)
		if err := unix.Mkfifo(r.file, 0o644); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, "fifo", 0, "", "not a regular file")
	})
	t.Run("another owner", func(t *testing.T) {
		newRig(t)
		old := ownerOf
		t.Cleanup(func() { ownerOf = old })
		ownerOf = func(st *unix.Stat_t) uint32 { return st.Uid + 1 } // the file is not root's
		wantRefused(t, "owner", 0, "", "can be written by someone other than root", "is owned by uid")
	})
	t.Run("a directory of another owner", func(t *testing.T) {
		newRig(t)
		trustedUID++ // the test's directories are now not root's
		wantRefused(t, "dir owner", 0, "", "directory that is not root's alone", "is owned by uid")
	})
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666, 0o622} {
		t.Run(fmt.Sprintf("mode %04o", mode), func(t *testing.T) {
			r := newRig(t)
			r.write(t, handedIn(goodBoot, "capability"), mode)
			wantRefused(t, "mode", 0, "", "writable by its group or by others")
		})
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		t.Run(fmt.Sprintf("directory mode %04o", mode), func(t *testing.T) {
			r := newRig(t)
			if err := os.Chmod(r.dir, mode); err != nil {
				t.Fatal(err)
			}
			wantRefused(t, "dir", 0, "", "directory that is not root's alone", "writable by its group or by others")
		})
	}
	t.Run("the walk's root is checked too", func(t *testing.T) {
		r := newRig(t)
		if err := os.Chmod(r.root, 0o777); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, "root dir", 0, "", "directory that is not root's alone")
	})
	t.Run("outside the walk's root", func(t *testing.T) {
		newRig(t)
		if err := SetFile("/etc/hostname"); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, "outside", 0, "", "is not under")
	})
	t.Run("unreadable by permission", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root reads any file")
		}
		r := newRig(t)
		r.write(t, handedIn(goodBoot, "capability"), 0o000)
		wantRefused(t, "mode 000", 0, "", "permission denied")
	})
}

// TestFilesystemsAnotherProgramControlsAreRefused: a FUSE, network or 9p filesystem chooses its own owner and mode.
func TestFilesystemsAnotherProgramControlsAreRefused(t *testing.T) {
	for magic, name := range refusedFS {
		r := newRig(t)
		_ = r
		fsMagic = func(*os.File) (uint32, error) { return magic, nil }
		wantRefused(t, name, 0, "", "is on a "+name+" filesystem")
	}
	newRig(t)
	fsMagic = func(*os.File) (uint32, error) { return 0, unix.EIO }
	wantRefused(t, "statfs error", 0, "", "filesystem type that cannot be read")
}

// TestMalformedFilesAreRefused: a file that is not the entrypoint's three lines, or whose list cannot be the kernel's.
func TestMalformedFilesAreRefused(t *testing.T) {
	good := handedIn(goodBoot, "capability,landlock")
	names := make([]string, 65)
	for i := range names {
		names[i] = fmt.Sprintf("m%d", i)
	}
	cases := []struct{ name, body, frag string }{
		{"empty", "", "cut short"},
		{"no newline at the end", strings.TrimSuffix(good, "\n"), "cut short"},
		{"another version", strings.Replace(good, Format, "tego-lsm-list 2", 1), "not a list file of this version"},
		{"a comment line first", "# x\n" + good, "not a list file of this version"},
		{"an extra line", good + "lsm capability,apparmor\n", "not a list file of this version"},
		{"two lines", Format + "\nlsm capability\n", "not a list file of this version"},
		{"lines out of order", Format + "\nlsm capability\nboot_id " + goodBoot + "\n", "not a list file of this version"},
		{"carriage return", strings.ReplaceAll(good, "\n", "\r\n"), "not a list file of this version"},
		{"another boot", handedIn("00000000-0000-0000-0000-000000000000", "capability,landlock"), "written in another boot"},
		{"no boot id", handedIn("", "capability,landlock"), "written in another boot"},
		{"no module", handedIn(goodBoot, ""), "lists no module"},
		{"no capability", handedIn(goodBoot, "landlock,yama"), "does not list capability"},
		{"upper case", handedIn(goodBoot, "capability,AppArmor"), "not one the kernel prints"},
		{"a space", handedIn(goodBoot, "capability, apparmor"), "not one the kernel prints"},
		{"an empty name", handedIn(goodBoot, "capability,,yama"), "not one the kernel prints"},
		{"a trailing comma", handedIn(goodBoot, "capability,"), "not one the kernel prints"},
		{"a path", handedIn(goodBoot, "capability,../x"), "not one the kernel prints"},
		{"a name twice", handedIn(goodBoot, "capability,yama,yama"), `names "yama" twice`},
		{"too many", handedIn(goodBoot, "capability,"+strings.Join(names, ",")), "more than 64 modules"},
		{"too long", good + strings.Repeat("x", readLimit), "longer than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.write(t, c.body, 0o644)
			wantRefused(t, c.name, 0, "", c.frag)
		})
	}
	t.Run("boot id unreadable", func(t *testing.T) {
		newRig(t)
		bootIDPath = filepath.Join(t.TempDir(), "none")
		wantRefused(t, "boot id", 0, "", "cannot be matched to this boot")
	})
}

// TestKernelsOwnFileIsReadWhenBoundReadOnly: a file on securityfs passes the bind check and is the list as the kernel
// prints it, with no owner, mode or boot id to match; the bind check's refusals are the file's.
func TestKernelsOwnFileIsReadWhenBoundReadOnly(t *testing.T) {
	r := newRig(t)
	fsMagic = func(*os.File) (uint32, error) { return uint32(unix.SECURITYFS_MAGIC), nil }
	var gotPath, gotWant string
	checkBind = func(p string, _ *os.File, want string) error { gotPath, gotWant = p, want; return nil }
	r.write(t, "lockdown,capability,landlock,yama,apparmor,bpf\n", 0o444)
	list, kind, err := Read(0, nil)
	if err != nil || list != "lockdown,capability,landlock,yama,apparmor,bpf" || kind != KindKernel {
		t.Fatalf("Read = %q, %v, %v", list, kind, err)
	}
	if gotPath != r.file || gotWant != "/lsm" {
		t.Errorf("bind check for %q, want file %q at /lsm", gotPath, gotWant)
	}
	checkBind = func(p string, _ *os.File, _ string) error { return errors.New(p + " is on a writable mount (rw)") }
	wantRefused(t, "writable bind", 0, "", "is not the kernel's /sys/kernel/security/lsm bound read-only", "writable mount")
	if _, _, err := Read(0, nil); strings.Contains(err.Error(), r.file+" is on") {
		t.Errorf("the path is repeated in the refusal: %v", err)
	}
	checkBind = func(string, *os.File, string) error { return nil }
	r.write(t, "capability,Apparmor\n", 0o444)
	wantRefused(t, "bad name in the kernel's file", 0, "", "not one the kernel prints")
	r.write(t, "landlock,yama\n", 0o444)
	wantRefused(t, "no capability in the kernel's file", 0, "", "does not list capability")
}

// TestTaskThatCouldRewriteTheFileIsRefused: a list is read for a task only when it holds nothing that could rewrite or
// replace the file; a root task is refused for a handed-in file, whatever user id of its four is 0.
func TestTaskThatCouldRewriteTheFileIsRefused(t *testing.T) {
	newRig(t)
	root := uint32(os.Getuid())
	r0 := fmt.Sprint(root)
	for i := 0; i < 4; i++ {
		ids := []string{"10001", "10001", "10001", "10001"}
		ids[i] = r0
		wantRefused(t, "uid slot "+fmt.Sprint(i), 5, status(strings.Join(ids, "\t"), "0000000000000000"), "task that is root")
	}
	for bit, name := range map[uint]string{0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 3: "CAP_FOWNER", 21: "CAP_SYS_ADMIN"} {
		wantRefused(t, name, 5, status("10001\t10001\t10001\t10001", fmt.Sprintf("%016x", uint64(1)<<bit)), "holds "+name)
	}
	// The permitted set decides, not the effective one: a task that holds CAP_DAC_OVERRIDE in its permitted set can
	// rewrite the file and then clear its effective set (capset) before the open that is trapped. Each of the four
	// capabilities, permitted but not effective, is refused for the handed-in file and for the kernel's.
	for bit, name := range map[uint]string{0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 3: "CAP_FOWNER", 21: "CAP_SYS_ADMIN"} {
		wantRefused(t, name+" permitted but not effective", 5,
			statusSets("10001\t10001\t10001\t10001", fmt.Sprintf("%016x", uint64(1)<<bit), "0000000000000000"), "holds "+name)
	}
	// A capability that cannot rewrite a root-owned file does not matter here.
	if _, _, err := Read(5, func(string) ([]byte, error) {
		return []byte(status("10001\t10001\t10001\t10001", fmt.Sprintf("%016x", uint64(1)<<12))), nil // CAP_NET_ADMIN
	}); err != nil {
		t.Errorf("a task with CAP_NET_ADMIN: %v", err)
	}
	for what, st := range map[string]string{
		"no uid line":           "CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n",
		"no cap line":           "Uid:\t1\t1\t1\t1\n",
		"short uid line":        "Uid:\t1\t1\t1\nCapPrm:\t0\n",
		"letters in uid":        "Uid:\t1\tx\t1\t1\nCapPrm:\t0\n",
		"bad caps":              "Uid:\t1\t1\t1\t1\nCapPrm:\tzz\n",
		"two words in caps":     "Uid:\t1\t1\t1\t1\nCapPrm:\t0 0\n",
		"only an effective set": "Uid:\t1\t1\t1\t1\nCapEff:\t0\n",
		"nothing":               "",
		"uid out of 32 bits":    "Uid:\t1\t99999999999\t1\t1\nCapPrm:\t0\n",
	} {
		wantRefused(t, what, 5, st, "cannot be used for the task")
	}
	if _, _, err := Read(5, nil); err == nil || !strings.Contains(err.Error(), "no way to read its credentials") {
		t.Errorf("no reader for a task: %v", err)
	}
	_, _, err := Read(5, func(string) ([]byte, error) { return nil, os.ErrNotExist })
	if err == nil || !strings.Contains(err.Error(), "credentials cannot be read") {
		t.Errorf("unreadable status: %v", err)
	}
	// The kernel's own file is not root's to lose: a root task without the capabilities is accepted, one with them is not.
	rr := newRig(t)
	fsMagic = func(*os.File) (uint32, error) { return uint32(unix.SECURITYFS_MAGIC), nil }
	checkBind = func(string, *os.File, string) error { return nil }
	rr.write(t, "capability,yama\n", 0o444)
	if _, _, err := Read(5, func(string) ([]byte, error) { return []byte(status("0\t0\t0\t0", "0000000000000000")), nil }); err != nil {
		t.Errorf("a root task without capabilities for the kernel's file: %v", err)
	}
	wantRefused(t, "kernel file, SYS_ADMIN", 5, status("0\t0\t0\t0", "0000000000200000"), "holds CAP_SYS_ADMIN")
}

// TestReadChecksAfreshEveryTime: nothing is kept between reads, so a file replaced after a good read is judged again.
func TestReadChecksAfreshEveryTime(t *testing.T) {
	r := newRig(t)
	if _, _, err := Read(0, nil); err != nil {
		t.Fatal(err)
	}
	r.write(t, handedIn(goodBoot, "capability"), 0o666)
	wantRefused(t, "after it became writable", 0, "", "writable by its group or by others")
	r.write(t, handedIn(goodBoot, "capability"), 0o644)
	if _, _, err := Read(0, nil); err != nil {
		t.Errorf("after it was made right again: %v", err)
	}
}

// BenchmarkRead is the cost one held open pays for this third way when the kernel's two answers failed first.
func BenchmarkRead(b *testing.B) {
	root := b.TempDir()
	_ = os.Chmod(root, 0o755)
	dir := filepath.Join(root, "run")
	_ = os.Mkdir(dir, 0o755)
	_ = os.Chmod(dir, 0o755)
	boot := filepath.Join(root, "boot_id")
	_ = os.WriteFile(boot, []byte(goodBoot+"\n"), 0o644)
	f := filepath.Join(dir, "lsm-list")
	_ = os.WriteFile(f, []byte(handedIn(goodBoot, "lockdown,capability,landlock,yama,apparmor,bpf")), 0o644)
	oldUID, oldRoot, oldBoot, oldMagic := trustedUID, walkRoot, bootIDPath, fsMagic
	trustedUID, walkRoot, bootIDPath = uint32(os.Getuid()), root, boot //nolint:gosec // a uid
	fsMagic = func(*os.File) (uint32, error) { return unix.EXT4_SUPER_MAGIC, nil }
	defer func() {
		trustedUID, walkRoot, bootIDPath, fsMagic = oldUID, oldRoot, oldBoot, oldMagic
		_ = SetFile("")
	}()
	_ = SetFile(f)
	status := []byte(agentStatus)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Read(7, func(string) ([]byte, error) { return status, nil }); err != nil {
			b.Fatal(err)
		}
	}
}
