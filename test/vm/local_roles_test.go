// SPDX-License-Identifier: Apache-2.0

package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// guestScriptsRoot is changed only by compiler overlays for negative proof.
const guestScriptsRoot = "."

func TestLocalRolesGuestNamespacesUsePreconnectedSender(t *testing.T) {
	driver, err := os.ReadFile(filepath.Join(guestScriptsRoot, "local-roles-guest.sh"))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(driver), "for namespace in user cgroup; do\n")
	if start < 0 {
		t.Fatal("private namespace decision rows missing")
	}
	rows := string(driver[start:])
	end := strings.Index(rows, "\ndone\n")
	if end < 0 {
		t.Fatal("private namespace row loop does not end")
	}
	// Execute the real row wiring without a guest. A fresh CLI invocation through
	// refuse must fail: private mapped root cannot open the UID 21001 socket.
	stub := `set -euo pipefail
BIN=/unrun RUN=r ASK=q
start_held() { :; }
once_effect() { :; }
namespace_answer() { printf '%s %s %s\n' "$1" "$2" "$3"; }
refuse() { echo 'namespace row attempted a fresh CLI after unshare' >&2; return 1; }
`
	cmd := exec.Command("bash", "-c", stub+rows[:end+len("\ndone\n")])
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("private namespace rows did not use the preconnected sender: %v\n%s", err, out)
	}
	const want = "approve user private\ndeny user private\napprove cgroup private\ndeny cgroup private\n"
	if string(out) != want {
		t.Fatalf("private namespace decisions=%q, want %q", out, want)
	}
}

func TestLocalRolesGuestPacketBarrierOverlay(t *testing.T) {
	root, err := filepath.Abs(guestScriptsRoot)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", filepath.Join(root, "local-roles-fault-overlay_test.py"))
	cmd.Env = append(os.Environ(), "TEGO_ROLES_SCRATCH="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("guest packet barrier overlay: %v\n%s", err, out)
	}
}

func TestLocalRolesGuestAssertionsRejectWrongOutcomes(t *testing.T) {
	root, err := filepath.Abs(guestScriptsRoot)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(root, "local-roles-guest.sh"), "--self-check")
	cmd.Env = append(os.Environ(), "TEGO_ROLES_SCRATCH="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("guest assertion self-check: %v\n%s", err, out)
	}
	for _, marker := range []string{"ASSERTION-SELF-CHECK-DONE: 57 wrong outcomes rejected", "DASHBOARD-SELF-CHECK-DONE: 6 wrong outcomes rejected", "NAMESPACE-SELF-CHECK-DONE: 14 wrong outcomes rejected"} {
		if !strings.Contains(string(out), marker) {
			t.Errorf("missing %q in %s", marker, out)
		}
	}
	if got := strings.Count(string(out), "FAIL (expected)"); got != 77 {
		t.Fatalf("wrong-outcome failures=%d, want77: %s", got, out)
	}
}
