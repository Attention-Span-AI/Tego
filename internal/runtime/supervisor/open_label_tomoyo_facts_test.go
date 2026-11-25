// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/tomoyo"
)

// TestOpenLabelTOMOYOFactsDirIsChecked: with tomoyo.facts_dir set, a held open's TOMOYO check reads the facts through the
// supervisor's own reader (readOpenLabelFile) from that directory, and a directory of ordinary files, which
// is not securityfs, refuses the open; the files are never read from the kernel's path instead.
func TestOpenLabelTOMOYOFactsDirIsChecked(t *testing.T) {
	t.Cleanup(func() { _ = tomoyo.SetFactsDir("") })
	d := t.TempDir()
	for name, body := range map[string]string{"self_domain": "<kernel>\n", "stat": "Policy update:                                 0\n", "profile": "PROFILE_VERSION=20150505\n"} {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := tomoyo.SetFactsDir(d); err != nil {
		t.Fatal(err)
	}
	tomoyoOnly := func() ([]uint64, error) { return []uint64{103}, nil }
	err := checkOpenLabelAuthority(1, 1, 0, readOpenLabelFile, tomoyoOnly, nil, false)
	if err == nil || !strings.Contains(err.Error(), "is not on securityfs") || !strings.Contains(err.Error(), d) {
		t.Fatalf("a facts directory of ordinary files admitted a held open: %v", err)
	}
}
