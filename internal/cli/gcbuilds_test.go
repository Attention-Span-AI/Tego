// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestGCJSONCarriesTheBuildSweepErrors: a root gc whose build, capture-probe or ring sweep fails lists
// that failure in --json's errors, beside the per-run ones. It went to stderr only, so a JSON consumer read
// builds_removed 0 as "nothing to remove". The exit stays 0 (R29: gc's exit is 0; the next pass meets it
// again).
func TestGCJSONCarriesTheBuildSweepErrors(t *testing.T) {
	gcRoot(t)
	prevRoot, prevSweep := gcPrivileged, gcSweepBPF
	defer func() { gcPrivileged, gcSweepBPF = prevRoot, prevSweep }()
	gcPrivileged = func() bool { return true }
	gcSweepBPF = func(*config.Machine, bool) (int, int, []error) {
		return 0, 0, []error{errors.New("builds: boom"), errors.New("capture probes: bang"), errors.New("rings: crash")}
	}
	code, out, errs := gcOut(t, "--json", "--builds")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got gcJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("output is not one JSON object: %v (%q)", err, out)
	}
	for _, want := range []string{"builds: boom", "capture probes: bang", "rings: crash"} {
		if !slices.Contains(got.Errors, want) {
			t.Errorf("errors %q lack %q", got.Errors, want)
		}
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
}

// TestGCBuildsSaysWhenItTouchedNoBuild: --builds without root, or under --dry-run, removes no build, and
// says so on stderr. It printed the ordinary summary, the same as a root pass that found no idle build.
func TestGCBuildsSaysWhenItTouchedNoBuild(t *testing.T) {
	gcRoot(t)
	prevRoot, prevSweep := gcPrivileged, gcSweepBPF
	defer func() { gcPrivileged, gcSweepBPF = prevRoot, prevSweep }()
	swept := false
	gcSweepBPF = func(*config.Machine, bool) (int, int, []error) { swept = true; return 0, 0, nil }

	gcPrivileged = func() bool { return false }
	code, _, errs := gcOut(t, "--builds")
	if code != identity.ExitOK || !strings.Contains(errs, "--builds needs root") {
		t.Errorf("unprivileged --builds: exit %d stderr %q, want 0 and a note that it needs root", code, errs)
	}
	gcPrivileged = func() bool { return true }
	code, _, errs = gcOut(t, "--builds", "--dry-run")
	if code != identity.ExitOK || !strings.Contains(errs, "--builds removes nothing under --dry-run") {
		t.Errorf("--builds --dry-run: exit %d stderr %q, want 0 and a note that it removed nothing", code, errs)
	}
	if swept {
		t.Error("the build sweep ran without root or under --dry-run")
	}
	// No --builds, no note: a plain unprivileged gc is the common case and says nothing about builds.
	gcPrivileged = func() bool { return false }
	if _, _, errs = gcOut(t); strings.Contains(errs, "--builds") {
		t.Errorf("a plain gc mentioned --builds: %q", errs)
	}
}
