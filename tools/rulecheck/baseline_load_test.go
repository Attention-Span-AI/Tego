// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const baselineDocsRoot = "../.."

// TestBaselineLoadClassesDocumented holds the safety distinction in ADR 0144: a failed layer
// cannot authorize rules, but must not disable stop or be described as an empty baseline.
func TestBaselineLoadClassesDocumented(t *testing.T) {
	tests := []struct {
		path     string
		required []string
	}{
		{"docs/adr/0144-machine-baseline.md", []string{"TrustAbort", "TrustWarn", "UNKNOWN", "NOT YET APPLIED", "100,000", "runStop", "runGC", "path_chmod"}},
		{"spec/config/v0/README.md", []string{"TrustAbort", "TrustWarn", "UNKNOWN", "100,000", "BaselineKnown"}},
		{"docs/user/baseline.md", []string{"Stop", "UNKNOWN", "cannot", "widen"}},
		{"docs/GAPS.md", []string{"UNKNOWN", "root-owned", "65534", "1775"}},
	}
	stale := regexp.MustCompile("(?i)all config loads (?:now )?abort|all config load modes fail closed|compile`/`doctor`\\s+warn and (?:continue|skip)")
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(baselineDocsRoot, filepath.FromSlash(tt.path)))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(strings.Fields(string(data)), " ")
			if strings.HasSuffix(tt.path, "CHANGELOG.md") {
				_, text, _ = strings.Cut(text, "## Unreleased ")
				text, _, _ = strings.Cut(text, " ## ")
			}
			for _, required := range tt.required {
				if !strings.Contains(strings.ToLower(text), strings.ToLower(required)) {
					t.Errorf("load-class safety contract omits %q", required)
				}
			}
			if bad := stale.FindString(text); bad != "" {
				t.Errorf("obsolete universal-abort or compile warn-and-skip claim: %q", bad)
			}
		})
	}
}

func TestBaselineRound2Documentation(t *testing.T) {
	for _, file := range []string{"docs/user/baseline.md", "spec/config/v0/README.md"} {
		data, err := os.ReadFile(filepath.Join(baselineDocsRoot, file))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		for _, want := range []string{"baseline.known", "baseline.reasons", "125", "no user layer"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s omits %q", file, want)
			}
		}
	}
}
