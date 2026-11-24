// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

func TestSetupScanGuideGoldens(t *testing.T) {
	for _, state := range []string{"a", "b", "systemd-login", "partial", "partial-b", "partial-zero", "failed"} {
		t.Run(state, func(t *testing.T) {
			path, err := filepath.Abs(filepath.Join("testdata", "setup-scan-"+state+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			f := onFixture(t, guidetest.Fresh)
			hintsAt(t, false, "off")
			want := f.PutScan(t, state)
			code, out, errs := run(t, "setup")
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errs)
			}
			fact := "found by scan at " + guidetest.CheckTime.Format(time.RFC3339) + " (any program running as you can change it)"
			if strings.Contains(out, fact) != want {
				t.Fatal(out)
			}
			if state == "systemd-login" && (!strings.Contains(out, "3130") || !strings.Contains(out, "any program can make itself unreadable")) {
				t.Fatal("missing unreadable-program warning", out)
			}
			got := f.Normal([]byte("--- stdout\n" + out + "--- stderr\n" + errs))
			if *updateGolden {
				if err := os.WriteFile(path, got, 0644); err != nil {
					t.Fatal(err)
				}
				return
			}
			expected, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expected, got) {
				t.Fatalf("setup differs from %s:\n%s", path, got)
			}
		})
	}
}

func TestSetupScanNeverChangesExitCode(t *testing.T) {
	for _, name := range []string{guidetest.Fresh, guidetest.NotReady, guidetest.Tampered} {
		t.Run(name, func(t *testing.T) {
			f := onFixture(t, name)
			base, _, _ := run(t, "setup", "--json")
			for _, state := range guidetest.ScanCases {
				t.Run(state, func(t *testing.T) {
					f.PutScan(t, state)
					code, out, errs := run(t, "setup", "--json")
					if code != base {
						t.Fatalf("%d -> %d: %s", base, code, errs)
					}
					var got guide.State
					if e := json.Unmarshal([]byte(out), &got); e != nil {
						t.Fatal(e)
					}
					if got.Steps[2].State == guide.NotKnown {
						t.Fatal("scan made find not known")
					}
				})
			}
		})
	}
}
