// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPublicCommentsDescribeOnlyRepositoryContents keeps absent-document explanations about this repository.
func TestPublicCommentsDescribeOnlyRepositoryContents(t *testing.T) {
	for _, rel := range []string{
		"tools/rulecheck/rulecheck.go",
		"pkg/spec/identity/forwardervars_test.go",
		"test/execmatchdiff/ordinary_test.go",
		"test/unit-skips.txt",
		"test/integration-skips.txt",
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "private tree") {
			t.Errorf("%s: absent-document explanation names an unpublished location", rel)
		}
	}
}
