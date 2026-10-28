// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// hintRecorder is the rule service with every ActOn request recorded.
type hintRecorder struct {
	*rules.Service
	reqs []rules.ActReq
}

func (h *hintRecorder) ActOn(ctx context.Context, r rules.ActReq) (*rules.ActPlan, error) {
	h.reqs = append(h.reqs, r)
	return h.Service.ActOn(ctx, r)
}

// TestEventPageHandsTheLineOffsetOn: the event page asks the rule service about the line with the read model's
// offset of it, so the service reads that one line instead of every line before it, and the panel is the same.
func TestEventPageHandsTheLineOffsetOn(t *testing.T) {
	s, c, _, _ := askServer(t)
	rec := &hintRecorder{Service: s.cfg.Rules.(*rules.Service)}
	s.cfg.Rules = rec
	b, err := os.ReadFile(filepath.Join(s.cfg.Ledger, actRun, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	off := 0
	for range 3 {
		off += bytes.IndexByte(b[off:], '\n') + 1
	}
	line := "/runs/" + actRun + "/lines/3"
	page := do(s, "GET", line+"?a=block", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the preview with a hint", page, `name="base" value="`)
	if len(rec.reqs) == 0 {
		t.Fatal("the page did not ask the rule service")
	}
	for _, r := range rec.reqs {
		if r.Hint == nil || r.Hint.Off != int64(off) || r.Hint.Size != int64(len(b)) {
			t.Fatalf("ActOn got hint %+v, want offset %d of a %d-byte file", r.Hint, off, len(b))
		}
	}
	if h := lineHint(s.cfg.Ledger, actRun, 99); h != nil {
		t.Errorf("a line the run does not hold has a hint: %+v", h)
	}
	if h := lineHint(s.cfg.Ledger, "../x", 1); h != nil {
		t.Errorf("a path that is not a run has a hint: %+v", h)
	}
}
