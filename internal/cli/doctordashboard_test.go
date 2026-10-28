// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/peer"
)

// TestDoctorDashboardClassification: doctor's dashboard line reads the TCP sock_diag probe's answer. A lookup that
// answers is ok; peer.ErrNoTCPDiag, wrapped or not, names the missing modules, the effect and the modprobe fix; any
// other error is a warning that says the error and offers no module load, since none fixes it, and a probe that could
// not open its own loopback connection says it did not check. None of them is a
// probe line's FAIL: the check never decides doctor's exit.
func TestDoctorDashboardClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		want    dashboardCheck
		line    string
		hasText []string
	}{
		{
			name: "ok",
			want: dashboardCheck{OK: true, Detail: dashboardOK},
			line: "\nok   dashboard: the dashboard can tell which run a connection comes from\n",
		},
		{
			name: "missing",
			err:  peer.ErrNoTCPDiag,
			want: dashboardCheck{Missing: true, Detail: dashboardMissing, Fix: dashboardFix},
			line: "\nwarn dashboard: the kernel answers no TCP socket lookup (the inet_diag and tcp_diag modules are not " +
				"loaded): tego-control refuses every dashboard action until it is loaded; fix: load the tcp_diag module: " +
				"sudo modprobe tcp_diag (and add it to /etc/modules-load.d)\n",
		},
		{
			name: "missing wrapped",
			err:  fmt.Errorf("probe: %w", peer.ErrNoTCPDiag),
			want: dashboardCheck{Missing: true, Detail: dashboardMissing, Fix: dashboardFix},
		},
		{
			name:    "unchecked",
			err:     fmt.Errorf("loopback listener: %w: %w", errDashboardUnchecked, errors.New("permission denied")),
			want:    dashboardCheck{Detail: "not checked: loopback listener: the probe's own loopback connection failed: permission denied"},
			hasText: []string{"\nwarn dashboard: not checked: "},
		},
		{
			name:    "other error",
			err:     peer.ErrNoCgroupID,
			hasText: []string{"\nwarn dashboard: cannot tell which run", peer.ErrNoCgroupID.Error(), "refuses every dashboard action"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := probeTCPDiag
			t.Cleanup(func() { probeTCPDiag = saved })
			probeTCPDiag = func() error { return tc.err }
			got := checkDashboard()
			if tc.want.Detail != "" && got != tc.want {
				t.Fatalf("check = %+v, want %+v", got, tc.want)
			}
			if tc.err != nil && got.OK {
				t.Fatalf("an error %v classified ok", tc.err)
			}
			if !errors.Is(tc.err, peer.ErrNoTCPDiag) && got.Fix != "" {
				t.Fatalf("fix %q offered for %v, which no module load fixes", got.Fix, tc.err)
			}
			var out bytes.Buffer
			if err := writeDashboardCheck(&out, got); err != nil {
				t.Fatal(err)
			}
			if tc.line != "" && out.String() != tc.line {
				t.Fatalf("line:\n%q\nwant:\n%q", out.String(), tc.line)
			}
			for _, s := range tc.hasText {
				if !strings.Contains(out.String(), s) {
					t.Fatalf("line %q does not say %q", out.String(), s)
				}
			}
			if strings.Contains(out.String(), "FAIL") {
				t.Fatalf("line %q says FAIL, which reads as doctor's exit", out.String())
			}
		})
	}
}

// TestDoctorDashboardJSON: --json carries the check under "dashboard", with the fix when the modules are missing.
func TestDoctorDashboardJSON(t *testing.T) {
	b, err := json.Marshal(doctorReport{Dashboard: classifyTCPDiag(peer.ErrNoTCPDiag)})
	if err != nil {
		t.Fatal(err)
	}
	var part struct {
		Dashboard map[string]any `json:"dashboard"`
	}
	if err := json.Unmarshal(b, &part); err != nil {
		t.Fatal(err)
	}
	if part.Dashboard["ok"] != false || part.Dashboard["missing"] != true || part.Dashboard["fix"] != dashboardFix {
		t.Fatalf("dashboard = %v", part.Dashboard)
	}
}
