// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// Keep the operator's validation claim scoped to the parser that enforces it.
func TestRound4OperationsUnknownAllowOptionScope(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "docs", "OPERATIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "unknown allow option is invalid for a tool with a known row.") {
		t.Error("OPERATIONS must scope unknown allow option rejection to tools with a known row")
	}
	for _, c := range []struct {
		entry string
		valid bool
	}{
		{"git --round4-unknown-option", false},
		{"find -name file", true},
		{"java -jar app.jar", true},
	} {
		_, err := execmatch.Parse(c.entry, execmatch.ListAllow, rows.Builtin())
		if (err == nil) != c.valid {
			t.Errorf("%s: valid=%v, want %v", c.entry, err == nil, c.valid)
		}
	}
}
