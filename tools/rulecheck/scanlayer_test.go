// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestScanLayers holds the parent/child boundary and its result-reader exception.
func TestScanLayers(t *testing.T) {
	rules, err := loadDepguardRules(filepath.Join("..", "..", ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rule, file, imported string
		denied               bool
	}{
		{"engine-never-imports-scan", "internal/runtime/x.go", "github.com/attention-span-ai/tego/internal/scan", true},
		{"engine-never-imports-scan", "internal/watch/watcher/x.go", "github.com/attention-span-ai/tego/internal/scan/catalog", true},
		{"engine-never-imports-scan", "internal/runscope/x.go", "github.com/attention-span-ai/tego/internal/scan/result", true},
		{"views-never-collect-scan", "internal/guide/x.go", "github.com/attention-span-ai/tego/internal/scan", true},
		{"views-never-collect-scan", "internal/control/web/x.go", "github.com/attention-span-ai/tego/internal/scan/catalog", true},
		{"views-never-collect-scan", "internal/control/web/x.go", "github.com/attention-span-ai/tego/internal/watch/sig", true},
		{"views-never-collect-scan", "internal/guide/x.go", "github.com/attention-span-ai/tego/internal/scan/result", false},
		{"scan-catalog-imports", "internal/scan/catalog/x.go", "github.com/attention-span-ai/tego/internal/watch/sig", false},
		{"scan-catalog-imports", "internal/scan/catalog/x.go", "github.com/attention-span-ai/tego/internal/scan", true},
		{"scan-result-imports", "internal/scan/result/x.go", "github.com/attention-span-ai/tego/internal/scan/catalog", true},
		{"scan-result-imports", "internal/scan/result/x.go", "github.com/attention-span-ai/tego/internal/scan", true},
		{"scan-imports", "internal/scan/x.go", "github.com/attention-span-ai/tego/internal/ledger", true},
		{"scan-imports", "internal/scan/x.go", "github.com/attention-span-ai/tego/internal/runtime", true},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.imported, func(t *testing.T) {
			r, ok := rules[tc.rule]
			if !ok || !r.governs(tc.file) {
				t.Fatalf("rule missing or does not govern %s", tc.file)
			}
			denied := false
			for _, d := range r.Deny {
				exact := strings.HasSuffix(d.Pkg, "$")
				pkg := strings.TrimSuffix(d.Pkg, "$")
				if exact && tc.imported == pkg || !exact && strings.HasPrefix(tc.imported, pkg) {
					denied = true
				}
			}
			if r.ListMode == "strict" {
				allowed := false
				for _, a := range r.Allow {
					if strings.HasPrefix(tc.imported, a) {
						allowed = true
					}
				}
				denied = denied || !allowed
			}
			if denied != tc.denied {
				t.Fatalf("denied=%v want %v", denied, tc.denied)
			}
		})
	}
}
