// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"strings"
	"testing"
)

func TestSettingsEnvironmentDiagnosticHidesValue(t *testing.T) {
	for _, value := range []string{"QZ", "private-environment-value-that-is-long"} {
		_, err := parseUser([]byte(`{"env":{"PRIVATE_TOKEN=` + value + `":null}}`))
		if err == nil || !strings.Contains(err.Error(), "PRIVATE_TOKEN") || strings.Contains(err.Error(), value) {
			t.Errorf("settings environment diagnostic: %v", err)
		}
	}
}

// TestEnvEntryMessages: an entry with no name to tell from its value is not shown at all (rule (a) of
// pkg/spec/identity envtext.go): a secret put where a name belongs is never echoed.
func TestEnvEntryMessages(t *testing.T) {
	for _, entry := range []string{"sk-live-qz", "=sk-live-qz", "1BAD=sk-live-qz", "A B=sk-live-qz"} {
		_, err := parseUser([]byte(`{"env":{"` + entry + `":null}}`))
		if err == nil || strings.Contains(err.Error(), "qz") || strings.Contains(err.Error(), "BAD") || !strings.Contains(err.Error(), "its name is not shown") {
			t.Errorf("settings entry %q: %v", entry, err)
		}
	}
}
