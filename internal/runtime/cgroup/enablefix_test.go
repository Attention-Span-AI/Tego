// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnableFixLeadsWithTheRootStepsWhenTheParentOffersNothing: on AlmaLinux 9.8 a new user's
// user@<uid>.service is not offered cpu (its cgroup.controllers lists memory pids), so the kernel refuses a
// "+cpu" write to its cgroup.subtree_control. Doctor's cgroupv2 line and a refused run's fix both led with that
// write ("add "+cpu" to cgroup.subtree_control of ..."), which this user cannot do (GAPS B15). Where root's
// cgroup.controllers does not list every missing controller, the fix now starts with the administrator's steps
// and says why the user cannot add it; where it does, the fix is the one it was. A root launcher's fix is
// unchanged either way.
func TestEnableFixLeadsWithTheRootStepsWhenTheParentOffersNothing(t *testing.T) {
	const root = "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service"
	cpu := []string{ControllerCPU}
	for _, offered := range []map[string]bool{{}, {ControllerMemory: true, ControllerPids: true}} {
		fix := EnableFix(cpu, root, false, offered)
		if strings.HasPrefix(fix, "add ") {
			t.Errorf("offered %v: fix leads with a write this user cannot make: %s", offered, fix)
		}
		for _, want := range []string{"as root: Delegate=cpu memory pids in /etc/systemd/system/user@.service.d/",
			"CPUWeight=100 under [Slice] in /etc/systemd/user/app.slice.d/", "then reboot",
			root + "/cgroup.controllers does not offer cpu"} {
			if !strings.Contains(fix, want) {
				t.Errorf("offered %v: fix lacks %q: %s", offered, want, fix)
			}
		}
	}
	// One missing controller not offered is enough: the direct write would fail for it.
	if fix := EnableFix([]string{ControllerCPU, ControllerPids}, root, false, map[string]bool{ControllerPids: true}); strings.HasPrefix(fix, "add ") ||
		!strings.Contains(fix, "does not offer cpu") || strings.Contains(fix, "offer cpu pids") {
		t.Errorf("cpu not offered, pids offered: %s", fix)
	}
	// Offered: this user can write it, so the fix is the one it was.
	want := `add "+cpu" to cgroup.subtree_control of ` + root + ` (as root: Delegate=cpu memory pids in ` +
		`/etc/systemd/system/user@.service.d/, and CPUWeight=100 under [Slice] in /etc/systemd/user/app.slice.d/ so the ` +
		`user manager enables cpu; then reboot)`
	if got := EnableFix(cpu, root, false, map[string]bool{ControllerCPU: true}); got != want {
		t.Errorf("offered cpu:\n got %s\nwant %s", got, want)
	}
	// Root at the mount root: the same text whatever cgroup.controllers says.
	if a, b := EnableFix(cpu, "/sys/fs/cgroup", true, nil), EnableFix(cpu, "/sys/fs/cgroup", true,
		map[string]bool{ControllerCPU: true}); a != b {
		t.Errorf("root's fix depends on offered: %s | %s", a, b)
	}
}

// TestMissingControllerFixReadsTheRootsControllers: the refusal a run with limits.pids meets carries the same
// probe: its fix leads with the root steps until the delegated root's cgroup.controllers offers pids.
func TestMissingControllerFixReadsTheRootsControllers(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	for _, tc := range []struct {
		controllers string
		direct      bool
	}{{"", false}, {"memory\n", false}, {"memory pids\n", true}, {"\n", false}} {
		if tc.controllers != "" {
			if err := os.WriteFile(filepath.Join(fs.Root(), "cgroup.controllers"), []byte(tc.controllers), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		var mc *MissingControllerError
		if err := fs.SetLimits(c, Limits{PidsMax: 5}); !errors.As(err, &mc) {
			t.Fatalf("want *MissingControllerError, got %v", err)
		}
		if got := strings.HasPrefix(mc.Fix(), `add "+pids"`); got != tc.direct || mc.Offered[ControllerPids] != tc.direct {
			t.Errorf("cgroup.controllers %q: direct write first = %v (Offered %v), want %v: %s", tc.controllers, got,
				mc.Offered, tc.direct, mc.Fix())
		}
		// No file is not known; a file that lists nothing offers nothing (TestEnableFixSaysWhenTheControllersFileCouldNotBeRead).
		if unread := strings.Contains(mc.Fix(), "could not be read"); unread != (tc.controllers == "") {
			t.Errorf("cgroup.controllers %q: fix says unread = %v: %s", tc.controllers, unread, mc.Fix())
		}
	}
}

// TestEnableFixSaysWhenTheControllersFileCouldNotBeRead: Offered returned nil on any read error, and EnableFix
// read nil as "offers nothing", so a refused run and doctor's D3 said "<root>/cgroup.controllers does not offer
// cpu" about a file nobody read (review of DOCTOR-RHEL9, S1). nil is now "not known": the fix still leads with the
// administrator's steps and says the file could not be read, while an empty file still offers nothing.
func TestEnableFixSaysWhenTheControllersFileCouldNotBeRead(t *testing.T) {
	root := t.TempDir()
	offered, err := Offered(root)
	if err == nil || offered != nil {
		t.Fatalf("Offered with no cgroup.controllers: %v, %v", offered, err)
	}
	fix := EnableFix([]string{ControllerCPU}, root, false, offered)
	if strings.HasPrefix(fix, "add ") || strings.Contains(fix, "does not offer") ||
		!strings.HasPrefix(fix, "as root: Delegate=cpu memory pids") ||
		!strings.Contains(fix, root+`/cgroup.controllers could not be read, so whether this user can add "+cpu" to `+
			"cgroup.subtree_control of "+root+" alone is not known") {
		t.Errorf("fix with cgroup.controllers unread: %s", fix)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if offered, err := Offered(root); err != nil || offered == nil || len(offered) != 0 {
		t.Fatalf("Offered with an empty cgroup.controllers: %v, %v", offered, err)
	}
}

// TestEnableFixNamesOnlyTheControllersTheUserCannotAdd: with cpu and memory missing and cpu offered, the fix said
// this user "cannot add "+cpu +memory" alone", while the user can add +cpu (review of DOCTOR-RHEL9, note A10). It
// names only the controllers not offered.
func TestEnableFixNamesOnlyTheControllersTheUserCannotAdd(t *testing.T) {
	const root = "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service"
	fix := EnableFix([]string{ControllerCPU, ControllerMemory}, root, false, map[string]bool{ControllerCPU: true})
	if !strings.Contains(fix, `this user cannot add "+memory" to cgroup.subtree_control of `+root+" alone: "+root+
		"/cgroup.controllers does not offer memory)") || strings.Contains(fix, `"+cpu +memory"`) {
		t.Errorf("fix with cpu offered and memory not: %s", fix)
	}
}
