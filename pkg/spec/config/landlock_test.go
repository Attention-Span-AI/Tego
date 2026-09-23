// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"
	"testing"
)

// TestLandlockAuditIsAnOptIn: landlock.audit is off unless a layer asks for new-exec, and a value the launcher
// cannot apply is refused rather than read as off, which would leave the operator believing an audit is on that
// is not.
func TestLandlockAuditIsAnOptIn(t *testing.T) {
	m, _ := mustLoad(t, Sources{}, "/home/test")
	if m.Landlock.Audit.Value != LandlockAuditOff || m.Landlock.Audit.Source.Layer != LayerBuiltin {
		t.Fatalf("built-in landlock.audit %+v, want off", m.Landlock.Audit)
	}

	src := layers(t, trustedDir(t), "", "landlock:\n  audit: new-exec\n", "")
	m, _ = mustLoad(t, src, "/home/test")
	if m.Landlock.Audit.Value != LandlockAuditNewExec || m.Landlock.Audit.Source.Line != 2 {
		t.Errorf("new-exec from the user layer: %+v", m.Landlock.Audit)
	}

	for _, bad := range []string{"landlock:\n  audit: on\n", "landlock:\n  audit: true\n", "landlock:\n  quiet: yes\n"} {
		src := layers(t, trustedDir(t), "", "", bad)
		_, diags, err := LoadSources(src, "/home/test", os.Getuid(), TrustAbort)
		if err == nil {
			t.Errorf("%q loaded (diags %v)", bad, diags)
			continue
		}
		var said bool
		for _, d := range diags {
			said = said || strings.Contains(d.Message, "landlock.")
		}
		if !said {
			t.Errorf("%q: no diagnostic names the key: %v", bad, diags)
		}
	}
}

// TestLandlockAuditIsAFloor: once a layer sets landlock.audit: new-exec, no later layer switches it off (R16). At
// tier landlock the kernel's own refusals reach no ledger, so the audit is the administrator's only view of them;
// an off in the invoking user's ~/.tego/config.yaml or $TEGO_CONFIG that undid /etc/tego/config.yaml's
// new-exec would remove that view and leave no trace. The attempt is reported the way R15 reports a raise, and
// the inherited value and source stand.
func TestLandlockAuditIsAFloor(t *testing.T) {
	const on, off = "landlock:\n  audit: new-exec\n", "landlock:\n  audit: off\n"
	cases := []struct {
		name           string
		etc, user, env string
		wantKept       []string // the layers whose off is reported, by file key
	}{
		{name: "user off under etc new-exec", etc: on, user: off, wantKept: []string{"user"}},
		{name: "env off under etc new-exec", etc: on, env: off, wantKept: []string{"env"}},
		{name: "user and env off under etc new-exec", etc: on, user: off, env: off, wantKept: []string{"user", "env"}},
		{name: "env off under user new-exec", user: on, env: off, wantKept: []string{"env"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := layers(t, trustedDir(t), tc.etc, tc.user, tc.env)
			m, diags := mustLoad(t, src, "/home/test")
			first := src.Etc
			if first == "" {
				first = src.User
			}
			if m.Landlock.Audit.Value != LandlockAuditNewExec || m.Landlock.Audit.Source.File != first {
				t.Fatalf("landlock.audit %+v, want new-exec from %s", m.Landlock.Audit, first)
			}
			files := map[string]string{"user": src.User, "env": src.EnvFile}
			for _, k := range tc.wantKept {
				want := "floor landlock.audit=new-exec kept from " + first + ":2"
				var found bool
				for _, d := range diags {
					found = found || (d.Code == CodeCeilingKept && d.File == files[k] && d.Line == 2 &&
						d.Severity == SeverityWarning && d.Message == want)
				}
				if !found {
					t.Errorf("no %q warning at %s:2: %v", want, files[k], diags)
				}
			}
			if n := countCode(diags, CodeCeilingKept); n != len(tc.wantKept) {
				t.Errorf("%d kept warnings, want %d: %v", n, len(tc.wantKept), diags)
			}
		})
	}

	// new-exec over off is the opt-in itself, and a later new-exec moves the source like an equal ceiling
	// (E11); neither is reported.
	src := layers(t, trustedDir(t), off, on, on)
	m, diags := mustLoad(t, src, "/home/test")
	if m.Landlock.Audit.Value != LandlockAuditNewExec || m.Landlock.Audit.Source.File != src.EnvFile {
		t.Errorf("landlock.audit %+v, want new-exec from %s", m.Landlock.Audit, src.EnvFile)
	}
	if n := countCode(diags, CodeCeilingKept); n != 0 {
		t.Errorf("%d kept warnings: %v", n, diags)
	}
}
