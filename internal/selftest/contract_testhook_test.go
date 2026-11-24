// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package selftest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestTemplatePathMessages: the template a test build reads is named when its path is a place, as any file a message
// is about is; a value that is not an absolute clean path is not echoed (rules (b) and (c) of pkg/spec/identity
// envtext.go).
func TestTemplatePathMessages(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "qz-template.yaml")
	if _, err := readContractTemplate(missing); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("the template that could not be read is not named: %v", err)
	}
	for _, v := range []string{"qz-relative.yaml", "/srv/../qz-unclean.yaml"} {
		if _, err := readContractTemplate(v); err == nil || strings.Contains(err.Error(), "qz-") || !strings.Contains(err.Error(), "echo $"+EnvTestContract) {
			t.Errorf("readContractTemplate(%q): %v", v, err)
		}
	}
}
