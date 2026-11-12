// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestControllersResultLeadsWithTheRootStepsWhenCPUIsNotOffered: on AlmaLinux 9.8 as a new user, D3's line ended
// with `to allow those limits, add "+cpu" to cgroup.subtree_control of .../user@1001.service (as root: ...)`
// (kit/acc2/alma/02-doctor.out), a write the kernel refuses there because that cgroup's cgroup.controllers lists
// memory pids only. D3 reads cgroup.controllers and leads with the administrator's steps then; where cpu is offered
// the line is the one it was. D3 stays ok either way, so the tier does not move.
func TestControllersResultLeadsWithTheRootStepsWhenCPUIsNotOffered(t *testing.T) {
	root := t.TempDir()
	write := func(name, s string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cgroup.subtree_control", "memory pids\n")
	write("cgroup.controllers", "memory pids\n")
	r := controllersResult(root, delegateFix, false, nil)
	if !r.OK || r.Fix != "" {
		t.Fatalf("D3 with cpu not offered: %+v", r)
	}
	if strings.Contains(r.Detail, `limits, add "+cpu"`) ||
		!strings.Contains(r.Detail, "; to allow those limits, as root: Delegate=cpu memory pids") ||
		!strings.Contains(r.Detail, root+"/cgroup.controllers does not offer cpu") {
		t.Errorf("D3 with cpu not offered: %s", r.Detail)
	}
	write("cgroup.controllers", "cpu memory pids\n")
	if r := controllersResult(root, delegateFix, false, nil); !r.OK ||
		!strings.Contains(r.Detail, `; to allow those limits, add "+cpu" to cgroup.subtree_control of `+root+" (as root:") {
		t.Errorf("D3 with cpu offered: %+v", r)
	}
}

// TestControllersResultSaysWhenTheControllersFileCouldNotBeRead: D3 used to read an unreadable cgroup.controllers
// as "offers nothing" and print "<root>/cgroup.controllers does not offer cpu", a statement about the kernel it had
// not read (review of DOCTOR-RHEL9, S1). It now says the file could not be read, and still leads with the
// administrator's steps.
func TestControllersResultSaysWhenTheControllersFileCouldNotBeRead(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := controllersResult(root, delegateFix, false, nil)
	if !r.OK || r.Fix != "" {
		t.Fatalf("D3 with cgroup.controllers unreadable: %+v", r)
	}
	if strings.Contains(r.Detail, "does not offer") ||
		!strings.Contains(r.Detail, "; to allow those limits, as root: Delegate=cpu memory pids") ||
		!strings.Contains(r.Detail, root+"/cgroup.controllers could not be read") {
		t.Errorf("D3 with cgroup.controllers unreadable: %s", r.Detail)
	}
}
