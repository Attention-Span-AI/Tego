// SPDX-License-Identifier: Apache-2.0

package tego_test

import (
	"embed"
	"strings"
	"testing"
)

// Test-only embedding lets overlay proofs replace documentation without rewriting
// the worktree. None of these texts is linked into a product binary.
//
//go:embed docs/site/finding-agents.md docs/adr/0145-tego-scan.md docs/site/presets.md pkg/spec/presets/README.md docs/adr/0068-presets-as-built-in-profiles.md
var ciDocs embed.FS

func checkCIDocs(t *testing.T, limits ...string) {
	t.Helper()
	for _, file := range []string{
		"docs/site/presets.md", "pkg/spec/presets/README.md", "docs/adr/0068-presets-as-built-in-profiles.md",
	} {
		t.Run(file, func(t *testing.T) {
			data, err := ciDocs.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			// Match concepts across line wrapping and inline code markup.
			text := strings.Join(strings.Fields(strings.ReplaceAll(string(data), "`", "")), " ")
			for _, limit := range limits {
				if !strings.Contains(text, limit) {
					t.Errorf("CI safety disclosure lacks %q", limit)
				}
			}
		})
	}
}

func TestCIPresetDocsExposeEnvironmentLimits(t *testing.T) {
	checkCIDocs(t, "INPUT_GITHUB-TOKEN", "cannot be denied", "scrub", "env.pass",
		"INPUT_TOKEN", "INPUT_GITHUB_TOKEN", "recalled, to verify on a runner")
}

func TestCIPresetDocsExposeRunnerCommands(t *testing.T) {
	checkCIDocs(t, "not protected", "stdout workflow commands", "GITHUB_ENV", "GITHUB_PATH",
		"GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY")
}

func TestCIPresetDocsExposeCompileLimits(t *testing.T) {
	checkCIDocs(t, "fs.assurance: kernel", "tier landlock", "beneath a write grant", "redundant-rule")
}

// TestScanDocsExplainLinkedPasswdRefusal keeps collector link support from
// implying that caller identification accepts the same system layout.
func TestScanDocsExplainLinkedPasswdRefusal(t *testing.T) {
	for _, file := range []string{"docs/site/finding-agents.md", "docs/adr/0145-tego-scan.md"} {
		t.Run(file, func(t *testing.T) {
			data, err := ciDocs.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(strings.Fields(strings.ReplaceAll(string(data), "`", "")), " ")
			for _, want := range []string{
				"The account-evidence collector accepts verified links",
				"the scan as a whole refuses before discovery",
				"/etc or /etc/passwd is a symbolic link",
				"store-path and image-based distribution layouts",
				"exit 125", "reason owner", "scan-not-performed",
				"Ask the distribution administrator",
				"Do not replace distribution-managed links",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("missing linked-passwd limitation %q", want)
				}
			}
		})
	}
}
