// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Newer records retain the chain's kind and sequence fields. An intact digest
// chain cannot make an invalid run structure valid, including without an anchor.
func TestVerifyNewerRunStructure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kinds []string
		valid bool
	}{
		{"gap-first", []string{"gap"}, false},
		{"end-first", []string{"run_end"}, false},
		{"start-repeated", []string{"run_start", "run_start"}, false},
		{"start-after-gap", []string{"gap", "run_start"}, false},
		{"unknown-middle", []string{"run_start", "hologram", "run_end"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, dir, _ := openTestWriter(t)
			if err := w.Abandon(); err != nil {
				t.Fatal(err)
			}
			var lines strings.Builder
			prev := ""
			for seq, kind := range tc.kinds {
				line := fmt.Sprintf(`{"v":2,"seq":%d,"id":"%s","prev":"%s","run":"%s","kind":"%s"}`,
					seq, record.ZeroID, prev, testRef.ID, kind)
				sum := sha256.Sum256([]byte(line))
				prev = hex.EncodeToString(sum[:])
				lines.WriteString(strings.Replace(line, record.ZeroID, prev, 1))
				lines.WriteByte('\n')
			}
			if err := os.WriteFile(filepath.Join(dir, EventsFile), []byte(lines.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			rep, err := r.Verify(context.Background(), nil)
			if tc.valid {
				if err != nil || !rep.Started || !rep.Ended || rep.Newer != len(tc.kinds) {
					t.Fatalf("valid newer run: report %+v, error %v", rep, err)
				}
			} else if !errors.Is(err, ErrUnverified) {
				t.Fatalf("invalid newer run structure verified: report %+v, error %v", rep, err)
			}
		})
	}
}
