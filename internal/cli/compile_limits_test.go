// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// compileWithMachineLimits compiles testdata/minimal.yaml under a machine config carrying the given
// limits: block ("" for no machine config at all) and returns the table and the --json rendering.
func compileWithMachineLimits(t *testing.T, limits string) (text string, tbl Table) {
	t.Helper()
	if limits != "" {
		// R14 skips a layer whose file or directory is group- or other-writable, and t.TempDir
		// inherits the process umask (0775 here), so the directory needs narrowing too.
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(limits), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TEGO_CONFIG", path)
	} else {
		t.Setenv("TEGO_CONFIG", "")
	}
	contract := filepath.Join("testdata", "minimal.yaml")
	code, out, errs := run(t, "compile", contract, "--offline")
	if code != identity.ExitOK {
		t.Fatalf("compile: exit %d stderr %q", code, errs)
	}
	text = out
	code, out, errs = run(t, "compile", contract, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("compile --json: exit %d stderr %q", code, errs)
	}
	if err := json.Unmarshal([]byte(out), &tbl); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	return text, tbl
}

// limitsLine returns the compile table's single "limits" row.
func limitsLine(t *testing.T, text string) string {
	t.Helper()
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, "limits ") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no limits line:\n%s", text)
	return ""
}

// TestCompileTellsZeroCeilingFromNoCeiling. A machine ceiling of
// exactly 0 and an omitted one resolve to the same number, and for as long as compile printed only
// that number it told an operator who had asked for the tightest possible budget the same thing it
// told one who had asked for none — while handing the first a run with no budget at all (E16).
func TestCompileTellsZeroCeilingFromNoCeiling(t *testing.T) {
	zeroText, zeroJSON := compileWithMachineLimits(t, "limits:\n  tokens: 0\n  cost_usd: 0\n")
	openText, openJSON := compileWithMachineLimits(t, "")

	zeroLine, openLine := limitsLine(t, zeroText), limitsLine(t, openText)
	if zeroLine == openLine {
		t.Fatalf("a zero ceiling prints the same as none:\n%s", zeroLine)
	}
	if !strings.Contains(zeroLine, "tokens=0") || !strings.Contains(zeroLine, "cost_usd=0") {
		t.Errorf("zero ceilings are not shown as budgets: %s", zeroLine)
	}
	if !strings.Contains(openLine, "tokens=unbounded") || !strings.Contains(openLine, "cost_usd=unbounded") {
		t.Errorf("an omitted ceiling is not shown as unbounded: %s", openLine)
	}

	// --json says it with null against 0 rather than 0 against 0.
	if zeroJSON.Limits.Tokens == nil || *zeroJSON.Limits.Tokens != 0 {
		t.Errorf("--json tokens = %v, want a budget of 0", zeroJSON.Limits.Tokens)
	}
	if zeroJSON.Limits.CostUSD == nil || *zeroJSON.Limits.CostUSD != 0 {
		t.Errorf("--json cost_usd = %v, want a budget of 0", zeroJSON.Limits.CostUSD)
	}
	if openJSON.Limits.Tokens != nil || openJSON.Limits.CostUSD != nil {
		t.Errorf("--json reported a budget nobody asked for: tokens=%v cost_usd=%v", openJSON.Limits.Tokens, openJSON.Limits.CostUSD)
	}
	// A dimension neither config names stays null in both, so the difference above is the ceiling
	// and not the presence of a machine config.
	if zeroJSON.Limits.Pids != nil || openJSON.Limits.Pids != nil {
		t.Errorf("pids came out bounded: %v %v", zeroJSON.Limits.Pids, openJSON.Limits.Pids)
	}
}
