// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// absentTable is a table with one deny_read target, so the plan is built by enumeration, and the given absent rows.
func absentTable(deny string, rows ...agent.AbsentRow) *agent.RuleTable {
	rt := denyTable([]string{deny})
	rt.AbsentDenyRead = rows
	return rt
}

// TestAbsentRowLeavesOutTheNameCompilePredicted (ADR 0067 D3): the
// ruleset leaves out exactly AbsentRow.At, the name the tier models refuse a read beneath. Missing still, At's
// directory is enumerated and At is no sibling; made since compile, At is a held deny target, so a token written
// between compile and the run is refused too; a row whose directory exists only beneath At leaves out all of At.
func TestAbsentRowLeavesOutTheNameCompilePredicted(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "deny/x", "home/.codex/config.toml", "home/notes")
	home := filepath.Join(root, "home")
	stillMissing := agent.AbsentRow{Path: filepath.Join(home, ".codex", "auth.json"), Resolved: filepath.Join(home, ".codex", "auth.json"), At: filepath.Join(home, ".codex", "auth.json")}
	dirMissing := agent.AbsentRow{Path: filepath.Join(home, ".gemini", "oauth_creds.json"), Resolved: filepath.Join(home, ".gemini", "oauth_creds.json"), At: filepath.Join(home, ".gemini")}
	madeSince := agent.AbsentRow{Path: filepath.Join(home, ".netrc"), Resolved: filepath.Join(home, ".netrc"), At: filepath.Join(home, ".netrc")}
	mkTree(t, root, "home/.netrc")
	h, _ := prepare(t, 7, absentTable(filepath.Join(root, "deny"), stillMissing, dirMissing, madeSince))
	assertLevel(t, h, filepath.Join(home, ".codex"), []string{"auth.json"})
	assertLevel(t, h, home, []string{".codex", ".gemini", ".netrc"})
	if e, ok := h.entry(filepath.Join(home, ".netrc")); !ok || e.Kind != kindDenyTarget || e.Access != 0 {
		t.Errorf("~/.netrc, made since compile, = %+v, %v; want a deny target", e, ok)
	}
	if e, ok := h.entry(filepath.Join(home, ".codex", "config.toml")); !ok || e.Access&accessReadFile == 0 {
		t.Errorf("~/.codex/config.toml, beside the row, = %+v, %v; want readable", e, ok)
	}
}

// TestAbsentRowDriftIsRefused: where At's directory is gone, is no
// longer a directory, or At is now a link compile did not see, the ruleset would leave out another name than the one
// the tier models refuse, so Prepare fails closed rather than build a plan the ledger would misreport.
func TestAbsentRowDriftIsRefused(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "deny/x", "home/afile", "home/elsewhere/")
	home := filepath.Join(root, "home")
	if err := os.Symlink(filepath.Join(home, "elsewhere"), filepath.Join(home, ".codex")); err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string]string{
		"directory gone":         filepath.Join(home, "gone", "auth.json"),
		"directory now a file":   filepath.Join(home, "afile", "auth.json"),
		"name now a link":        filepath.Join(home, ".codex"),
		"directory now via link": filepath.Join(home, ".codex", "auth.json"),
	} {
		row := agent.AbsentRow{Path: at, Resolved: at, At: at}
		err := prepareErr(t, 7, absentTable(filepath.Join(root, "deny"), row), nil)
		if !errors.Is(err, ErrRulesetBuild) {
			t.Errorf("%s: Prepare = %v, want ErrRulesetBuild", name, err)
		}
	}
}
