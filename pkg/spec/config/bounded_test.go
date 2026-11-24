// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSourcesBounded(t *testing.T) {
	home := trustedDir(t)
	path := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(path, []byte("ledger_root: /chosen/runs\n"), 0600); err != nil {
		t.Fatal(err)
	}
	src := Sources{User: path}
	m, _, err := LoadSourcesBounded(src, home, os.Getuid(), TrustAbort, 128)
	if err != nil || m.LedgerRoot.Value != "/chosen/runs" {
		t.Fatalf("bounded load: %v", err)
	}
	for _, bound := range []int64{0, -1, 4, MaxLayerSize + 1} {
		if _, _, err := LoadSourcesBounded(src, home, os.Getuid(), TrustAbort, bound); err == nil {
			t.Fatalf("bound %d accepted", bound)
		}
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSourcesBounded(src, home, os.Getuid(), TrustAbort, 128); err == nil {
		t.Fatal("smaller byte bound bypassed trust")
	}
}
