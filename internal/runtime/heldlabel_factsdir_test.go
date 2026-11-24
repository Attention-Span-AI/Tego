// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"strings"
	"testing"
)

// TestHeldLabelWarningNamesTheFactsDirRemedy: the launch warning for a TOMOYO fact that cannot be read at the kernel's path
// names the bind of the host's directory and the machine setting (GAPS C74), and never offers to assume TOMOYO enforces
// nothing.
func TestHeldLabelWarningNamesTheFactsDirRemedy(t *testing.T) {
	err := errors.New("TOMOYO /sys/kernel/security/tomoyo/self_domain: permission denied")
	got := heldLabelWarningFor("gate.completion: held", []byte("tomoyo"), nil, err)
	for _, want := range []string{"expose readable /sys/kernel/security/tomoyo", "read-only", "tomoyo.facts_dir"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q lacks %q", got, want)
		}
	}
	if strings.Contains(strings.ToLower(got), "assume tomoyo") {
		t.Errorf("an assume-style remedy: %q", got)
	}
}
