// SPDX-License-Identifier: Apache-2.0

package contractsrc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These assertions guard the accepted design contract for future slices. They do
// not claim that the launch authority check or compiled comparator exists today.
func requireDesign(t *testing.T, file string, facts ...string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "adr", file))
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range facts {
		if !strings.Contains(string(data), fact) {
			t.Errorf("%s lacks required design fact %q", file, fact)
		}
	}
}
func TestGeneralAuthorityDesign(t *testing.T) {
	requireDesign(t, "0153-general-contract.md", "### One authority check, fixed scope and a closed system source universe",
		"contractsrc.CheckGeneralAuthority(ctx, request, previous)", "Scope comes first", "SUDO_UID", "SUDO_GID", "AT_SECURE",
		"/etc/tego/profiles", "user-level", "ignored", "caller PATH", "policy source", "observation", "before child release")
}
func TestGeneralExceptionProgramDesign(t *testing.T) {
	requireDesign(t, "0153-general-contract.md", "this agent's exception was approved for a different program: <what changed>; publish it again or remove it", "SHA-256", "interpreter", "script", "republication")
}
func TestGeneralCompiledCompositionDesign(t *testing.T) {
	requireDesign(t, "0153-general-contract.md", "### Exhaustive rule-family matrix for the first version", "this part of the general contract cannot be customised yet", "command: [true]", "exec.allow: [\"git status\"]", "[git, status]", "SUPPORTED", "FROZEN", "DENY <= ASK <= ALLOW", "C silence always inherits", "File read:", "File write:", "Exec programs:", "Exec command rules:", "Network hosts and ports:", "MCP servers and tools:", "Secrets:", "Caps and budgets:", "Ask rules:", "Required tier and mechanisms:", "Gates:", "Business rules")
}
func TestGeneralProductionBoundaryDesign(t *testing.T) {
	requireDesign(t, "0153-general-contract.md", "tegotesthooks", "Slice 11 alone removes")
}

func TestGeneralLaunchFormsDesign(t *testing.T) {
	requireDesign(t, "0153-general-contract.md",
		"NODE_OPTIONS", "TERM", "LC_*", "NO_COLOR", "env.set", "env.pass",
		"npx", "uvx", "pipx run", "go run", "docker run", "initial mount or user namespace",
		"Anything that can change the files this program loads can use the", "user-level",
		"descriptor path", "No binding matches", "store nothing")
}

func TestGeneralManifestLifecycleDesign(t *testing.T) {
	requireDesign(t, "0153-general-contract.md",
		"source manifest", "compiled constraints", "preparation facts", "captured bytes",
		"File identity", "content SHA-256", "directory", "floor", "no retry loop",
		"lower tier", "exit 125")
}

func TestGeneralExceptionEnvironmentDecisionDesign(t *testing.T) {
	requireDesign(t, "0153-general-contract.md", "### R5: engine-set variables are the third and last environment source",
		"Discard every caller entry", "No engine-set variable may carry a path or option",
		"Values come\nonly from the engine", "### R6: prices are policy wherever a cost limit is in force")
}
