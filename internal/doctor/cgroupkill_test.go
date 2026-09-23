// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestProbeCgroupChecksCgroupKill is D3's cgroup.kill half. R27 D1 lists cgroup.kill 5.14 among the
// per-mechanism minimums, but until this check D3 only ever inferred it from uname — and D1's own
// table comment says a distribution that backports into an older release (RHEL 9's "5.14") is
// reported as missing what it has, while a "6.x" with cgroup v1 semantics would be reported as
// having what it lacks. The scratch cgroup D3 already creates is the one place the question can be
// answered exactly, because cgroup.kill only exists below the cgroup root.
//
// Without the check the detail never names cgroup.kill and this fails.
func TestProbeCgroupChecksCgroupKill(t *testing.T) {
	uid, _ := config.InvokingUID()
	r := probeCgroup(uid)
	t.Logf("%+v", r)
	if !r.OK {
		// No cgroup v2 delegation on this box: the probe never reached its scratch cgroup, so there
		// is nothing to assert about cgroup.kill. The delegation failure is D3's own answer.
		t.Skipf("no delegated cgroup v2 subtree here: %s", r.Detail)
	}
	if !strings.Contains(r.Detail, cgroupKillFile) {
		t.Errorf("D3 passed without establishing %s: %q — the kernel version is not evidence, a "+
			"backporting distribution makes it a guess in both directions", cgroupKillFile, r.Detail)
	}
	if r.Fix != "" {
		t.Errorf("a passing probe carries a fix: %q", r.Fix)
	}
}

// TestProbeCgroupReportsTheFixDetectDiagnosed: cgroup.Detect refuses with ErrNotDelegated for more
// than one reason, and the reasons have different remedies — case 39 alone has three. D3 used to key
// its fix on ErrNotCgroup2 alone, so case 39's refusal — a cgroup namespace looking at the host's
// /sys/fs/cgroup, whose remedy is that namespace's own cgroup2 mount — was printed with the Delegate=
// drop-in after it, which changes nothing there, and the one line carried two contradictory fixes.
//
// D3 reads the remedy from the *cgroup.DetectError every refusal is; the cgroup package's
// TestEveryDetectRefusalNamesItsRemedy pins that each of its refusals is one, with the right remedy.
// A real case 39 needs a cgroup namespace this test cannot enter, so those rows are built as the
// cgroup package builds them; the last row is a real refusal from the real Detect.
func TestProbeCgroupReportsTheFixDetectDiagnosed(t *testing.T) {
	ownMount := "give this cgroup namespace its own cgroup2 mount at /sys/fs/cgroup instead of the host's tree"
	cases := []struct {
		name    string
		err     error
		want    string
		notWant string
	}{
		{"case 39", &cgroup.DetectError{Diagnosis: "cgroup: no delegated cgroup v2 subtree: /proc/self/cgroup " +
			"puts this process in cgroup \"/\", but /sys/fs/cgroup holds no such cgroup (case 39)", Remedy: ownMount},
			ownMount, "Delegate="},
		{"case 39, a cgroup outside this namespace's root", &cgroup.DetectError{Diagnosis: "cgroup: no delegated " +
			"cgroup v2 subtree: /proc/self/cgroup names this process's cgroup as \"/../x.scope\" (case 39)",
			Remedy: "run tego from a cgroup inside its own cgroup namespace, with that namespace's cgroup2 mount " +
				"at /sys/fs/cgroup"}, "from a cgroup inside its own cgroup namespace", "Delegate="},
		{"no cgroup2 at the mount", &cgroup.DetectError{Diagnosis: "cgroup: not a cgroup v2 filesystem: " +
			"/sys/fs/cgroup has magic 0x1021994", Remedy: "mount the cgroup v2 hierarchy at /sys/fs/cgroup (on a " +
			"systemd host, boot with systemd.unified_cgroup_hierarchy=1)"}, "systemd.unified_cgroup_hierarchy=1",
			"Delegate="},
		// A caller that adds context after the refusal: D3 still prints the refusal's own remedy, which
		// splitting the message on its last "; fix: " would have run into the caller's text.
		{"a refusal wrapped with trailing context", fmt.Errorf("%w (while probing D3)", &cgroup.DetectError{
			Diagnosis: "cgroup: no delegated cgroup v2 subtree for uid 1000 (tried /x): access: permission denied",
			Remedy:    "enable systemd user delegation"}), "enable systemd user delegation", "while probing"},
		// An error Detect did not build: the sentinel, then the delegation fix.
		{"a bare ErrNotCgroup2", fmt.Errorf("%w: /sys/fs/cgroup has magic 0x1021994", cgroup.ErrNotCgroup2),
			"systemd.unified_cgroup_hierarchy=1", "Delegate="},
		{"nothing to go on", errors.New("statfs(/sys/fs/cgroup): no such file or directory"),
			"Delegate=cpu memory pids", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := probeCgroupWith(1000, func(int) (*cgroup.FS, error) { return nil, tc.err })
			if r.OK || r.ID != CheckCgroupV2 {
				t.Fatalf("a Detect refusal is not a D3 failure: %+v", r)
			}
			if !strings.Contains(r.Fix, tc.want) {
				t.Errorf("fix %q, want one naming %q", r.Fix, tc.want)
			}
			if tc.notWant != "" && strings.Contains(r.Fix, tc.notWant) {
				t.Errorf("fix %q names %q, which cannot help here", r.Fix, tc.notWant)
			}
			if strings.Contains(r.Detail, "; fix: ") {
				t.Errorf("detail %q still carries a fix of its own next to Fix %q", r.Detail, r.Fix)
			}
		})
	}
}

// TestProbeCgroupReportsARealRefusalsRemedy is the same rule across the package boundary: no uid on
// this box has a user@4242.service, so the real Detect refuses whatever this machine is (no
// delegation, case 39, or no cgroup2 at all), and D3's detail and fix have to be exactly the
// diagnosis and remedy that refusal chose.
func TestProbeCgroupReportsARealRefusalsRemedy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the uid-0 branch roots at the mount and asks no delegation question")
	}
	const nobody = 4242
	_, err := cgroup.Detect(nobody)
	var de *cgroup.DetectError
	if !errors.As(err, &de) {
		t.Fatalf("cgroup.Detect(%d) = %v (%T), want a *cgroup.DetectError", nobody, err, err)
	}
	r := probeCgroupWith(nobody, cgroup.Detect)
	if r.OK || r.Fix != de.Remedy || r.Detail != de.Diagnosis {
		t.Errorf("D3 over a real refusal = %+v, want detail %q and fix %q", r, de.Diagnosis, de.Remedy)
	}
}
