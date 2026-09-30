// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestControllersResultReportsAnUnreadableSubtreeControl: a failed read of cgroup.subtree_control
// used to yield an empty controller list, which D3 reported as "missing cpu memory pids" with a
// Delegate= fix, losing the real errno.
func TestControllersResultReportsAnUnreadableSubtreeControl(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "cgroup.subtree_control")
	// A directory of that name makes the read fail (EISDIR) without needing privileges.
	if err := os.Mkdir(file, 0o755); err != nil {
		t.Fatal(err)
	}
	r := controllersResult(root, delegateFix)
	if r.OK || !strings.Contains(r.Detail, "read "+file) || strings.Contains(r.Detail, "missing") {
		t.Errorf("unreadable subtree_control misreported: %+v", r)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := controllersResult(root, delegateFix); !r.OK {
		t.Errorf("all three controllers enabled but D3 failed: %+v", r)
	}
}
