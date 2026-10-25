// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyRunBounds: a run over the dashboard's line bound, a bad run id and an unknown or missing anchor are
// "not checked", each saying why, before any ledger is read; none is ever "verified".
func TestVerifyRunBounds(t *testing.T) {
	root := t.TempDir()
	const id = "r-3f9c2a1b-0dllq06ts7400-b0undx"
	if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(root, "chain.log")
	if err := os.WriteFile(anchor, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, id, anchor string
		run              *Run
		want             string
	}{
		{"too long", id, anchor, &Run{ID: id, Ended: true, Cut: true}, "too long for the dashboard"},
		{"live", id, anchor, &Run{ID: id, Live: true}, "still being written"},
		{"bad id", "../etc", anchor, nil, "not a run id"},
		{"no anchor", id, "", &Run{ID: id, Ended: true}, "not known"},
		{"missing anchor", id, filepath.Join(root, "nope", "chain.log"), &Run{ID: id, Ended: true}, "not readable here"},
	} {
		got := VerifyRun(context.Background(), root, c.id, c.anchor, c.run)
		if got.State != ChainUnchecked || !strings.Contains(got.Reason, c.want) {
			t.Errorf("%s: %+v, want unchecked with %q", c.name, got, c.want)
		}
	}
}
