// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeDevInfo is the file a host could have at a device's path: what lstat would say of it.
type fakeDevInfo struct {
	name string
	st   syscall.Stat_t
}

func (f fakeDevInfo) Name() string       { return f.name }
func (f fakeDevInfo) Size() int64        { return 0 }
func (f fakeDevInfo) Mode() fs.FileMode  { return fs.ModeDevice | fs.ModeCharDevice | 0o666 }
func (f fakeDevInfo) ModTime() time.Time { return time.Time{} }
func (f fakeDevInfo) IsDir() bool        { return false }
func (f fakeDevInfo) Sys() any           { return &f.st }

func devStat(mode uint32, major, minor uint32) syscall.Stat_t {
	return syscall.Stat_t{Mode: mode | 0o666, Rdev: unix.Mkdev(major, minor), Dev: 5, Ino: 11}
}

// TestStandardDeviceAt is the device check every tier asks of the object it grants: exactly the five character
// devices with their own numbers, and nothing else, whatever the name.
func TestStandardDeviceAt(t *testing.T) {
	want := map[string][2]uint32{"/dev/null": {1, 3}, "/dev/zero": {1, 5}, "/dev/full": {1, 7}, "/dev/random": {1, 8}, "/dev/urandom": {1, 9}}
	if got := len(StandardDevices()); got != len(want) {
		t.Fatalf("StandardDevices lists %d, want %d", got, len(want))
	}
	for path, mm := range want {
		real := unix.Mkdev(mm[0], mm[1])
		if !StandardDeviceAt(path, unix.S_IFCHR|0o666, real) {
			t.Errorf("%s as character device %d:%d: not accepted", path, mm[0], mm[1])
		}
		for other, om := range want {
			if other != path && StandardDeviceAt(path, unix.S_IFCHR, unix.Mkdev(om[0], om[1])) {
				t.Errorf("%s accepted the numbers of %s (%d:%d): a look-alike of another device", path, other, om[0], om[1])
			}
		}
		for name, c := range map[string]struct {
			mode uint32
			rdev uint64
		}{
			"regular file":       {unix.S_IFREG, real},
			"block device":       {unix.S_IFBLK, real},
			"symlink":            {unix.S_IFLNK, real},
			"directory":          {unix.S_IFDIR, real},
			"fifo":               {unix.S_IFIFO, real},
			"socket":             {unix.S_IFSOCK, real},
			"char, major only":   {unix.S_IFCHR, unix.Mkdev(mm[0], mm[1]+20)},
			"char, minor only":   {unix.S_IFCHR, unix.Mkdev(mm[0]+1, mm[1])},
			"char, no numbers":   {unix.S_IFCHR, 0},
			"char, tty 5:0":      {unix.S_IFCHR, unix.Mkdev(5, 0)},
			"char, console 5:1":  {unix.S_IFCHR, unix.Mkdev(5, 1)},
			"char, ptmx 5:2":     {unix.S_IFCHR, unix.Mkdev(5, 2)},
			"char, a disk (8:0)": {unix.S_IFCHR, unix.Mkdev(8, 0)},
		} {
			if StandardDeviceAt(path, c.mode, c.rdev) {
				t.Errorf("%s accepted as %s", path, name)
			}
		}
	}
	for _, p := range []string{"/dev/tty", "/dev/ptmx", "/dev/console", "/dev/pts/0", "/dev/shm", "/dev/nul", "/dev/null/", "/dev//null", "dev/null", "", "/tmp/null"} {
		for _, mm := range want {
			if StandardDeviceAt(p, unix.S_IFCHR, unix.Mkdev(mm[0], mm[1])) {
				t.Errorf("%q accepted with the numbers %d:%d: a name that is not a standard device's", p, mm[0], mm[1])
			}
		}
	}
}

// withDevices makes compile see a host whose files at the device paths are the ones given (a path not listed has no
// file), for the cases a test cannot make with mknod.
func withDevices(t *testing.T, files map[string]syscall.Stat_t) {
	t.Helper()
	old := lstatDevice
	lstatDevice = func(p string) (os.FileInfo, error) {
		st, ok := files[p]
		if !ok {
			return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
		}
		return fakeDevInfo{name: filepath.Base(p), st: st}, nil
	}
	t.Cleanup(func() { lstatDevice = old })
}

func realDevices() map[string]syscall.Stat_t {
	m := map[string]syscall.Stat_t{}
	for _, d := range StandardDevices() {
		m[d.Path] = devStat(unix.S_IFCHR, d.Major, d.Minor)
	}
	return m
}

func stdRows(rt *RuleTable) []string {
	var out []string
	for _, r := range rt.FS {
		if r.StdDevice {
			out = append(out, r.Path)
		}
	}
	return out
}

var allFive = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"}

func compileStd(t *testing.T, f *fixture, yaml string) *RuleTable {
	t.Helper()
	rt, ds := f.compile(f.load(yaml))
	if HasErrors(ds) {
		t.Fatalf("errors:\n%s", render(ds))
	}
	return rt
}

// TestCompileGrantsTheStandardDevices is ADR 0158's table: every contract with an fs: section holds exactly five
// device rows beyond what it wrote, each a write grant of the product's own with the narrow device right set, and
// nothing under /dev besides them.
func TestCompileGrantsTheStandardDevices(t *testing.T) {
	withDevices(t, realDevices())
	f := newFixture(t)
	for name, yaml := range map[string]string{
		"a write folder": writeSection("./out"),
		"fs: {}":         "version: 0\nname: a\ncommand: [python]\nfs: {}\n",
		"watch only":     "version: 0\nname: a\ncommand: [python]\nfs:\n  watch: [./config]\n",
	} {
		t.Run(name, func(t *testing.T) {
			rt := compileStd(t, f, yaml)
			if got := stdRows(rt); !slices.Equal(got, allFive) {
				t.Fatalf("device rows = %v, want %v", got, allFive)
			}
			for _, r := range rt.FS {
				if !r.StdDevice {
					if r.Kind == FSWrite && strings.HasPrefix(r.Path, "/dev") {
						t.Errorf("a write row under /dev that is not a device row: %+v", r)
					}
					continue
				}
				if r.Kind != FSWrite || r.Access != standardDeviceAccess || !r.BuiltIn || r.Raw != "" || r.Resolved != r.Path || r.Missing {
					t.Errorf("device row %s = %+v", r.Path, r)
				}
				if r.Access&(AccessRemoveFile|AccessRemoveDir|AccessMakeReg|AccessMakeChar|AccessMakeSym|AccessRefer) != 0 {
					t.Errorf("device row %s grants a right on a directory: %#x", r.Path, r.Access)
				}
				if r.RuleName() != BuiltinStandardDevices || !r.IsStandardDevice() {
					t.Errorf("device row %s is named %q", r.Path, r.RuleName())
				}
			}
			for _, not := range []string{"/dev/tty", "/dev/ptmx", "/dev/console", "/dev/shm", "/dev/pts", "/dev/stdout", "/dev/fd"} {
				if findFS(rt, FSWrite, not) != nil {
					t.Errorf("%s was granted", not)
				}
			}
		})
	}
	t.Run("no fs section", func(t *testing.T) {
		// R6: a contract with no fs: section gets no write entry at all (ADR 0158 leaves it as it is).
		rt := compileStd(t, f, "version: 0\nname: a\ncommand: [python]\n")
		if got := stdRows(rt); len(got) != 0 {
			t.Fatalf("a contract with no fs: section has device rows %v", got)
		}
	})
}

// TestStandardDevicesNeedTheDevice: a file at the name that is not the device holds no row, and the others keep theirs.
func TestStandardDevicesNeedTheDevice(t *testing.T) {
	f := newFixture(t)
	for name, mod := range map[string]func(m map[string]syscall.Stat_t){
		"another character device at the name": func(m map[string]syscall.Stat_t) { m["/dev/null"] = devStat(unix.S_IFCHR, 1, 5) },
		"the numbers of another standard one":  func(m map[string]syscall.Stat_t) { m["/dev/null"] = devStat(unix.S_IFCHR, 1, 9) },
		"a regular file":                       func(m map[string]syscall.Stat_t) { m["/dev/null"] = devStat(unix.S_IFREG, 0, 0) },
		"a symbolic link":                      func(m map[string]syscall.Stat_t) { m["/dev/null"] = devStat(unix.S_IFLNK, 1, 3) },
		"a block device with its numbers":      func(m map[string]syscall.Stat_t) { m["/dev/null"] = devStat(unix.S_IFBLK, 1, 3) },
		"a directory":                          func(m map[string]syscall.Stat_t) { m["/dev/null"] = devStat(unix.S_IFDIR, 0, 0) },
		"nothing":                              func(m map[string]syscall.Stat_t) { delete(m, "/dev/null") },
	} {
		t.Run(name, func(t *testing.T) {
			m := realDevices()
			mod(m)
			withDevices(t, m)
			rt := compileStd(t, f, writeSection("./out"))
			if got := stdRows(rt); !slices.Equal(got, allFive[1:]) {
				t.Fatalf("device rows = %v, want %v", got, allFive[1:])
			}
			if findFS(rt, FSWrite, "/dev/null") != nil {
				t.Fatal("/dev/null holds a write row")
			}
		})
	}
	t.Run("no device at all", func(t *testing.T) {
		withDevices(t, nil)
		rt := compileStd(t, f, writeSection("./out"))
		if got := stdRows(rt); len(got) != 0 {
			t.Fatalf("device rows = %v on a host with none", got)
		}
	})
}

// TestStandardDevicesNeverOverrideTheContract: an entry of the contract that names a device, or a place over it,
// decides it. A write entry already does, and every kind of refusal or question the author wrote is theirs.
func TestStandardDevicesNeverOverrideTheContract(t *testing.T) {
	withDevices(t, realDevices())
	f := newFixture(t)
	head := "version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n"
	for _, tc := range []struct {
		name, fs string
		want     []string
	}{
		{"deny_write on one", "  write: [./out]\n  deny_write: [/dev/null]\n", allFive[1:]},
		{"deny_write over all", "  write: [./out]\n  deny_write: [/dev]\n", nil},
		{"deny_read on one", "  write: [./out]\n  deny_read: [/dev/zero]\n", []string{"/dev/null", "/dev/full", "/dev/random", "/dev/urandom"}},
		{"deny_read glob", "  write: [./out]\n  deny_read: [\"/dev/ran*\"]\n", []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/urandom"}},
		{"ask on one", "  write: [./out]\n  ask: [/dev/full]\n", []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}},
		{"ask_read on one", "  write: [./out]\n  ask_read: [/dev/urandom]\n", allFive[:4]},
		{"watch on one", "  write: [./out]\n  watch: [/dev/null]\n", allFive[1:]},
		{"an explicit write entry", "  write: [./out, /dev/null]\n", allFive[1:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, ds := f.compile(f.load(head + tc.fs))
			if HasErrors(ds) {
				t.Fatalf("errors:\n%s", render(ds))
			}
			if got := stdRows(rt); !slices.Equal(got, tc.want) {
				t.Fatalf("device rows = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStandardDevicesSkipASymlinkedExplicitEntry: a write entry that is a link to a device is that device's entry,
// found by where the link leads, so the device is not granted twice (the plane keys one row per inode).
func TestStandardDevicesSkipASymlinkedExplicitEntry(t *testing.T) {
	withDevices(t, realDevices())
	f := newFixture(t)
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("no /dev/null on this host")
	}
	link := filepath.Join(f.project, "sink")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Fatal(err)
	}
	rt := compileStd(t, f, writeSection(link))
	if got := stdRows(rt); !slices.Equal(got, allFive[1:]) {
		t.Fatalf("device rows = %v, want %v (the link's target is the entry's)", got, allFive[1:])
	}
}

// TestStandardDevicesAreTheHostsOwn: with no stand-in, on a real host, compile finds the real devices.
func TestStandardDevicesAreTheHostsOwn(t *testing.T) {
	f := newFixture(t)
	want := 0
	for _, d := range StandardDevices() {
		var st unix.Stat_t
		if unix.Lstat(d.Path, &st) == nil && StandardDeviceAt(d.Path, st.Mode, uint64(st.Rdev)) { //nolint:unconvert // Rdev is uint64 on amd64 and arm64, not everywhere
			want++
		}
	}
	if want == 0 {
		t.Skip("this host has none of the standard devices")
	}
	rt := compileStd(t, f, writeSection("./out"))
	if got := len(stdRows(rt)); got != want {
		t.Fatalf("%d device rows, the host has %d standard devices", got, want)
	}
}

// TestStandardDeviceRowsAreNotAliased: a container shows /dev/null again under other names (its masked paths are binds
// of it). An entry the contract wrote for the device gets a row at each such name, as every write entry does; the
// product's own device row does not: the ruleset and the plane key the inode, so every name of it is granted there, and a
// row at a name no device carries could never pass the device check.
func TestStandardDeviceRowsAreNotAliased(t *testing.T) {
	f := newFixture(t)
	var st syscall.Stat_t
	if err := syscall.Stat("/dev/null", &st); err != nil {
		t.Skipf("host has no /dev/null: %v", err)
	}
	masked := filepath.Join(f.root, "masked-kcore")
	f.file(masked, "", 0o600)
	mi := mountTableFile(t, f, [2]string{"/dev/null", masked})
	id := withFileIdentity(func(p string) (uint64, uint64, error) {
		if p == masked {
			p = "/dev/null"
		}
		var s syscall.Stat_t
		if err := syscall.Stat(p, &s); err != nil {
			return 0, 0, &os.PathError{Op: "stat", Path: p, Err: err}
		}
		return uint64(s.Dev), s.Ino, nil //nolint:unconvert // Dev is a uint32 on some architectures
	})
	for name, tc := range map[string]struct {
		fsBody           string
		alias, deviceRow bool
	}{
		"the product's row":        {"  write: [./out]\n", false, true},
		"the contract's own entry": {"  write: [./out, /dev/null]\n", true, false},
		// An entry at another name of the same file decides it: the plane keys one row per inode.
		"an entry at another name of the device": {"  write: [./out, " + masked + "]\n", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\ntier: landlock\nfs:\n"+tc.fsBody), WithMountInfo(mi), id)
			if rt == nil || HasErrors(ds) {
				t.Fatalf("compile failed:\n%s", render(ds))
			}
			var at *FSRule
			for i := range rt.FS {
				if rt.FS[i].Kind == FSWrite && rt.FS[i].Path == masked {
					at = &rt.FS[i]
				}
			}
			if (at != nil) != tc.alias {
				t.Fatalf("a write row at the masked name %s: %+v, want one: %v", masked, at, tc.alias)
			}
			if got := slices.Contains(stdRows(rt), "/dev/null"); got != tc.deviceRow {
				t.Fatalf("the product's row for /dev/null: %v, want %v (rows %v)", got, tc.deviceRow, stdRows(rt))
			}
		})
	}
}
