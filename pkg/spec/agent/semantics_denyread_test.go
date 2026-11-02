// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSemanticsDenyReadRowNamesBuiltInList: SEMANTICS §1's "no deny_read:" row is the spec of the
// built-in list, so every credential entry of builtInDenyRead is written there. Browser profile
// directories (the rows of family SecretBrowsers) are named by class, not one by one.
func TestSemanticsDenyReadRowNamesBuiltInList(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "spec", "policy", "SEMANTICS.md"))
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "| no `deny_read:`") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("SEMANTICS §1 has no `no deny_read:` row")
	}
	for _, e := range builtInDenyRead {
		if builtInDenyReadFamily[e] == SecretBrowsers {
			continue
		}
		if !strings.Contains(row, "`~/"+e+"`") {
			t.Errorf("SEMANTICS §1 deny_read row does not name ~/%s, which builtInDenyRead denies", e)
		}
	}
}
