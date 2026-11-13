// SPDX-License-Identifier: Apache-2.0

package execmatchdiff_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func securityNotes(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../tools/oss/testdata/overlay/docs/CHANGELOG.md")
	if os.IsNotExist(err) {
		data, err = os.ReadFile("../../docs/CHANGELOG.md")
	}
	if err != nil {
		t.Fatal(err)
	}
	_, unreleased, ok := strings.Cut(string(data), "## Unreleased\n")
	if !ok {
		t.Fatal("missing Unreleased section")
	}
	_, security, ok := strings.Cut(unreleased, "### Security\n")
	if !ok {
		t.Fatal("missing Unreleased security notes")
	}
	security, _, _ = strings.Cut(security, "\n##")
	return security
}

// TestUnreleasedCommandRuleNotes keeps the affected rules and tools visible in
// the public notice, and prevents the review's opaque wording from returning.
func TestUnreleasedCommandRuleNotes(t *testing.T) {
	notes := securityNotes(t)
	for _, rule := range []string{"exec.deny", "exec.ask"} {
		if !strings.Contains(notes, rule) {
			t.Errorf("security notice omits %s", rule)
		}
	}
	for _, tool := range []string{"systemctl", "go", "npm", "pip", "aws"} {
		if !regexp.MustCompile(`\b` + tool + `\b`).MatchString(notes) {
			t.Errorf("security notice omits %s", tool)
		}
	}
	for _, jargon := range []string{"verified tool parser", "unstable command-position terminator"} {
		if strings.Contains(notes, jargon) {
			t.Errorf("security notice uses opaque wording %q", jargon)
		}
	}
}
