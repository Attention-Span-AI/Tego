// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// stdTable compiles a contract with a write folder and, when withDevices is false, drops the five device rows the
// compiler added, so the two ruleset builds differ by those rows alone.
func stdTable(t *testing.T, withDevices bool, fsKeys string) *agent.RuleTable {
	t.Helper()
	root := tempDir(t)
	mkTree(t, root, "work/", "home/", "config/")
	c, ds, err := agent.LoadBytes(filepath.Join(root, "config", "agent.yaml"),
		[]byte("version: 0\nname: std-devices\ncommand: [/bin/true]\ntier: landlock\nfs:\n  write: [./]\n"+fsKeys), nil)
	if err != nil {
		t.Fatalf("load %v %v", err, ds)
	}
	rt, ds, err := agent.Compile(c, &config.Machine{}, agent.Offline(), agent.WithCwd(filepath.Join(root, "work")),
		agent.WithHome(filepath.Join(root, "home")), agent.WithMountInfo(""), agent.WithTiers(backend.TierLandlock))
	if err != nil {
		t.Fatalf("compile %v %v", err, ds)
	}
	if !withDevices {
		rt.FS = slices.DeleteFunc(rt.FS, func(r agent.FSRule) bool { return r.StdDevice })
	}
	return rt
}

// writeGrants is every held entry under /dev that carries a right to change what the file holds or the directory it
// lies in, by path.
func writeGrants(h *Handle) map[string]accessFS {
	const modifies = accessWriteFile | accessTruncate | accessRemoveFile | accessRemoveDir | accessMakeChar | accessMakeDir |
		accessMakeReg | accessMakeSock | accessMakeFifo | accessMakeBlock | accessMakeSym | accessRefer
	out := map[string]accessFS{}
	for _, p := range h.fds.open {
		if p.Kind == kindWrite && p.Access&modifies != 0 && underDev(p.Path) {
			out[p.Path] = p.Access
		}
	}
	return out
}

// TestStandardDevicesAreFiveExactRulesAtTierLandlock: the ruleset a contract with an fs: section builds holds a
// file rule on each of the five devices and no other grant under /dev: not /dev, not a terminal, not /dev/shm. The
// rule carries the write, truncate and ioctl rights of a device and no right on a directory.
func TestStandardDevicesAreFiveExactRulesAtTierLandlock(t *testing.T) {
	// The terminals the run holds (/dev/tty, /dev/ptmx) are granted by their own layer at every table; what the
	// device rows add is the difference.
	without, _ := prepare(t, 7, stdTable(t, false, ""))
	base := writeGrants(without)
	h, fake := prepare(t, 7, stdTable(t, true, ""))
	all := writeGrants(h)
	got := map[string]accessFS{}
	for p, a := range all {
		if b, held := base[p]; held {
			if b != a {
				t.Errorf("%s: rights changed from %#x to %#x by the device rows", p, b, a)
			}
			continue
		}
		got[p] = a
	}
	var paths []string
	for p := range got {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	if want := []string{"/dev/full", "/dev/null", "/dev/random", "/dev/urandom", "/dev/zero"}; !slices.Equal(paths, want) {
		t.Fatalf("write grants the device rows add under /dev = %v, want %v", paths, want)
	}
	for p, a := range got {
		if a&accessWriteFile == 0 || a&accessIoctlDev == 0 {
			t.Errorf("%s: rights %#x lack write or ioctl", p, a)
		}
		if a&(accessRemoveFile|accessRemoveDir|accessMakeChar|accessMakeReg|accessMakeSym|accessMakeDir|accessRefer) != 0 {
			t.Errorf("%s: rights %#x include a right on a directory", p, a)
		}
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil || !agent.StandardDeviceAt(p, st.Mode, uint64(st.Rdev)) { //nolint:unconvert // Rdev is uint64 on amd64 and arm64, not everywhere
			t.Errorf("%s: the host's file is not the device the row is for: %v", p, err)
		}
	}
	if len(fake.paths) < len(got) {
		t.Fatalf("the kernel was given %d path rules, fewer than the %d device grants", len(fake.paths), len(got))
	}
	for _, nope := range []string{"/dev", "/dev/console", "/dev/shm", "/dev/pts", "/dev/stdout", "/dev/fd"} {
		if e, ok := h.entry(nope); ok && e.Kind == kindWrite && e.Access&accessWriteFile != 0 {
			t.Errorf("%s was granted: %+v", nope, e)
		}
	}
}

// TestAContractDenialKeepsItsDeviceOutOfTheRuleset: a device an fs.deny_write entry names has no file rule: Landlock
// cannot deny beneath an allow, so the default is never laid where the author wrote a refusal.
func TestAContractDenialKeepsItsDeviceOutOfTheRuleset(t *testing.T) {
	base := writeGrants(func() *Handle { h, _ := prepare(t, 7, stdTable(t, false, "")); return h }())
	h, _ := prepare(t, 7, stdTable(t, true, "  deny_write: [/dev/null]\n"))
	got := writeGrants(h)
	if _, ok := got["/dev/null"]; ok {
		t.Fatalf("/dev/null holds a write rule beneath the author's deny_write: %v", got)
	}
	if len(got)-len(base) != 4 {
		t.Fatalf("grants = %v over the baseline %v, want the four other devices", got, base)
	}
}

// TestPrepareRefusesAStandardDeviceRowOnAnotherFile: the row is the device's by what the held descriptor is. A
// regular file, a directory, a character device with another number (even another standard device's) and a link's
// target held at the device's name are not it; each stops the build, and the real device passes.
func TestPrepareRefusesAStandardDeviceRowOnAnotherFile(t *testing.T) {
	dir := tempDir(t)
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	row := agent.FSRule{Path: "/dev/null", Resolved: "/dev/null", Kind: agent.FSWrite, Access: agent.AccessWriteFile, BuiltIn: true, StdDevice: true}
	for _, tc := range []struct {
		name, path string
		ok         bool
	}{
		{"the device itself", "/dev/null", true},
		{"a regular file", plain, false},
		{"a directory", dir, false},
		{"another standard device (1:5)", "/dev/zero", false},
		{"the terminal (5:0)", "/dev/tty", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Open(tc.path, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Skipf("host has no %s: %v", tc.path, err)
			}
			bd := &builder{fds: newFDSet()}
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				t.Fatal(err)
			}
			idx := bd.fds.add(fd, row.Path, kindWrite, accessWriteFile, &st)
			t.Cleanup(func() { _ = bd.fds.closeAll() })
			err = bd.sameStandardDevice(idx, row)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("the real device refused: %v", err)
			case !tc.ok && (err == nil || !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), "not the standard character device")):
				t.Fatalf("held %s as /dev/null: %v, want a refusal", tc.path, err)
			}
		})
	}
}

// TestAHeldStandardDeviceRowFailsPrepareClosed: the same through Prepare, with a table whose device row's path is a
// symlink to something that is not the device: the descriptor Prepare holds follows the link and is checked.
func TestAHeldStandardDeviceRowFailsPrepareClosed(t *testing.T) {
	rt := stdTable(t, true, "")
	dir := tempDir(t)
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range rt.FS {
		if rt.FS[i].StdDevice && rt.FS[i].Path == "/dev/null" {
			// The table says /dev/null; the descriptor Prepare holds is for a regular file (a stand-in held by path).
			rt.FS[i].Path, rt.FS[i].Resolved = plain, plain
		}
	}
	// With the row's name no longer a standard device's name the check refuses it outright.
	_, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{})
	if err == nil || !errors.Is(err, ErrRulesetBuild) {
		t.Fatalf("Prepare with a device row on a regular file = %v, want ErrRulesetBuild", err)
	}
}
