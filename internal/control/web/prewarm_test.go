// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"testing"
	"time"
)

// TestPrewarm: the start-up pass reads the ledger and checks the overview's chains, so the overview then shows the
// verdict (here, the tampered run) without checking anything itself; with its context ended it returns at once.
func TestPrewarm(t *testing.T) {
	s := fixtureServer(t, true)
	done := make(chan struct{})
	go func() {
		s.Prewarm(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Prewarm did not return")
	}
	wantIn(t, "overview after Prewarm", getPage(t, s, "/"), []string{"Broken ·", "Broken at #2"},
		[]string{"Verifying…", "Verified ·"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s2 := fixtureServer(t, false)
	start := time.Now()
	s2.Prewarm(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Prewarm with an ended context took %v", d)
	}
	wantIn(t, "overview after a cut Prewarm", getPage(t, s2, "/"), []string{"Verified · 1 run"}, []string{"Verifying…"})
}
