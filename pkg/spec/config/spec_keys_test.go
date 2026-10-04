// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSpecREADMENamesEveryParsedKey: the Go mirror of spec/config/v0 is not drift-checked, so this is
// the check: every key parse.go accepts appears in the spec's README as `key:`.
func TestSpecREADMENamesEveryParsedKey(t *testing.T) {
	src, err := os.ReadFile("parse.go")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "config", "v0", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?m)^\s*case "([a-z_0-9]+)":`).FindAllStringSubmatch(string(src), -1) {
		if !strings.Contains(string(readme), m[1]+":") {
			t.Errorf("spec/config/v0/README.md never names %q, which parse.go accepts", m[1])
		}
	}
}
