// SPDX-License-Identifier: Apache-2.0

package execmatchdiff_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// securityNotes is the "### Security" notes of the changelog section that starts with heading ("## Unreleased\n",
// "## v0.1.3 "): the section's own notes, never a later release's, so a section that has none fails here instead of
// reading the next release's (the Unreleased section had no security notes while this test read v0.1.3's).
func securityNotes(t *testing.T, heading string) string {
	t.Helper()
	data, err := os.ReadFile("../../tools/oss/testdata/overlay/docs/CHANGELOG.md")
	if os.IsNotExist(err) {
		data, err = os.ReadFile("../../docs/CHANGELOG.md")
	}
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "\n"+heading)
	if !ok {
		t.Fatalf("missing changelog section %q", strings.TrimSpace(heading))
	}
	section, _, _ = strings.Cut(section, "\n## ")
	_, security, ok := strings.Cut(section, "### Security\n")
	if !ok {
		t.Fatalf("missing security notes in %q", strings.TrimSpace(heading))
	}
	security, _, _ = strings.Cut(security, "\n##")
	return security
}

// TestCommandRuleSecurityNotes keeps the affected rules and tools visible in the public notice of the release that
// fixed the command rules (v0.1.3), and keeps opaque wording out of that notice and the Unreleased one.
func TestCommandRuleSecurityNotes(t *testing.T) {
	notes := securityNotes(t, "## v0.1.3 ")
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
	for _, heading := range []string{"## Unreleased\n", "## v0.1.3 "} {
		for _, jargon := range []string{"verified tool parser", "unstable command-position terminator"} {
			if strings.Contains(securityNotes(t, heading), jargon) {
				t.Errorf("security notice of %q uses opaque wording %q", strings.TrimSpace(heading), jargon)
			}
		}
	}
}
