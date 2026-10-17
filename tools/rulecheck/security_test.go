// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSecurityTCBPathsHaveCode: SECURITY.md is what an external reviewer reads first to scope the review. Every
// path it names in backticks must exist and hold at least one non-doc, non-test Go (or BPF C) file, so a
// placeholder or a renamed package cannot stand in for the trusted computing base.
func TestSecurityTCBPathsHaveCode(t *testing.T) {
	root := filepath.Join("..", "..")
	b, err := os.ReadFile(filepath.Join(root, "SECURITY.md"))
	if err != nil {
		t.Skip("no SECURITY.md here")
	}
	n := 0
	for _, m := range regexp.MustCompile("`((?:internal|bpf)[A-Za-z0-9_./-]*)`").FindAllStringSubmatch(string(b), -1) {
		n++
		dir := filepath.Join(root, strings.TrimSuffix(m[1], "/"))
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("SECURITY.md names %s, which does not exist", m[1])
			continue
		}
		code := false
		for _, e := range ents {
			name := e.Name()
			ext := filepath.Ext(name)
			if e.IsDir() || name == "doc.go" || strings.HasSuffix(name, "_test.go") {
				continue
			}
			if ext == ".go" || ext == ".c" || ext == ".h" {
				code = true
			}
		}
		if !code {
			t.Errorf("SECURITY.md names %s, which holds no code beyond doc.go", m[1])
		}
	}
	if n == 0 {
		t.Error("SECURITY.md names no trusted computing base package")
	}
}
