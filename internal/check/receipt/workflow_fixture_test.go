// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestWorkflowBindingFixtures keeps the workflow's canned CLI responses tied to
// receipts and comparisons produced by the product, for both supported bindings.
// Set TEGO_UPDATE_ACTION_BINDINGS=1 to refresh the checked-in deterministic files.
func TestWorkflowBindingFixtures(t *testing.T) {
	dataDir := filepath.Join("..", "..", "..", "action", "testdata")
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("binding%d", version), func(t *testing.T) {
			r, err := ledger.OpenReader(dataDir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			r.SkipNewerVersions()
			rc, err := Compute(context.Background(), r, Options{Bind: &testBy, BindVersion: version, BinarySHA256: strings.Repeat("a", 64), Home: "/home/tego"})
			if err != nil {
				t.Fatal(err)
			}
			var receiptJSON bytes.Buffer
			if err := rc.JSON(&receiptJSON); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "receipt.json")
			if err := os.WriteFile(path, receiptJSON.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			check := Check(context.Background(), CheckInput{Receipt: path, Record: dataDir, By: testBy})
			if check.Result != CheckMatch || check.BindingVersion != version || check.ExitCode() != 0 {
				t.Fatalf("fixture does not match: %+v", check)
			}
			var checkJSON bytes.Buffer
			if err := check.JSON(&checkJSON); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(dataDir, "bindings", fmt.Sprintf("v%d", version))
			for name, data := range map[string][]byte{"receipt.json": receiptJSON.Bytes(), "check.json": checkJSON.Bytes()} {
				path := filepath.Join(dest, name)
				if os.Getenv("TEGO_UPDATE_ACTION_BINDINGS") == "1" {
					if err := os.MkdirAll(dest, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, data) {
					t.Errorf("%s differs from product output; refresh fixtures: %v", path, err)
				}
			}
		})
	}
}
