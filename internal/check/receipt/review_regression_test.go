// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLinkCreatedNames(t *testing.T) {
	rc := compute(t, []line{start("off", true),
		{kind: record.KindFS, verdict: record.VerdictAllow, rule: "fs.write[/work]", payload: record.FSPayload{Op: record.FSLink, Path: "/work/source", Path2: "/work/new-name"}},
		{kind: record.KindFS, verdict: record.VerdictAllow, rule: "fs.write[/work]", payload: record.FSPayload{Op: record.FSSymlink, Path: "/work/symlink", Path2: "/work/source"}},
	}, Options{})
	if !slices.Equal(rc.Files.Created, []string{"/work/new-name", "/work/symlink"}) {
		t.Fatalf("created = %v", rc.Files.Created)
	}
}

func TestUnansweredBeyondAskDisplayCap(t *testing.T) {
	ls := []line{start("off", true)}
	for i := 0; i < MaxAsks; i++ {
		id := fmt.Sprintf("q-%d", i)
		ls = append(ls, line{kind: record.KindAsk, payload: record.AskPayload{AskID: id, Hold: "exec"}}, line{kind: record.KindAnswer, payload: map[string]any{"ask_id": id, "approved": true}})
	}
	ls = append(ls, line{kind: record.KindAsk, payload: record.AskPayload{AskID: "pending", Hold: "exec"}})
	rc := compute(t, ls, Options{})
	if rc.Asks.Unanswered != 1 || rc.Asks.Asked != MaxAsks+1 || !rc.Asks.Truncated {
		t.Fatalf("asked=%d unanswered=%d truncated=%v", rc.Asks.Asked, rc.Asks.Unanswered, rc.Asks.Truncated)
	}
}

func TestReceiptLimitsUnmatchedAskPrefix(t *testing.T) {
	ls := []line{start("off", true)}
	for i := range 32_769 {
		ls = append(ls, line{kind: record.KindAsk, payload: record.AskPayload{AskID: fmt.Sprintf("q-%d", i), Hold: "exec"}})
	}
	// A later answer cannot make the oversized prefix safe to retain while it is read.
	ls = append(ls, line{kind: record.KindAnswer, payload: map[string]any{"ask_id": "q-0", "approved": true}})
	rc, err := Compute(context.Background(), ledgerOf(t, ls), Options{})
	if !errors.Is(err, ErrAskLimit) || rc != nil {
		t.Fatalf("oversized unmatched prefix returned a receipt: error=%v receipt=%v", err, rc != nil)
	}
}

func TestReceiptLimitsPendingAskIDBytes(t *testing.T) {
	ls := []line{start("off", true)}
	for i := range 130 {
		id := fmt.Sprintf("q-%d-", i) + strings.Repeat("a", 64<<10)
		ls = append(ls, line{kind: record.KindAsk, payload: record.AskPayload{AskID: id, Hold: "exec"}})
	}
	rc, err := Compute(context.Background(), ledgerOf(t, ls), Options{})
	if !errors.Is(err, ErrAskLimit) || rc != nil {
		t.Fatalf("oversized pending IDs returned a receipt: error=%v receipt=%v", err, rc != nil)
	}
}

func TestReceiptPendingAskLimitsCountConcurrentState(t *testing.T) {
	for _, c := range []struct {
		name, suffix string
		n            int
	}{
		{"many answered identities", "", MaxPendingAsks + 1},
		{"long answered identities", strings.Repeat("a", 64<<10), 130},
	} {
		t.Run(c.name, func(t *testing.T) {
			ls := []line{start("off", true)}
			for i := range c.n {
				id := fmt.Sprintf("q-%d-", i) + c.suffix
				ls = append(ls,
					line{kind: record.KindAsk, payload: record.AskPayload{AskID: id, Hold: "exec"}},
					line{kind: record.KindAnswer, payload: map[string]any{"ask_id": id, "approved": true}})
			}
			rc := compute(t, ls, Options{})
			if a := rc.Asks; a.Asked != c.n || a.Approved != c.n || a.Unanswered != 0 || a.Truncated != (c.n > MaxAsks) {
				t.Fatalf("released identities lost exact totals: asked=%d approved=%d unanswered=%d truncated=%v", a.Asked, a.Approved, a.Unanswered, a.Truncated)
			}
		})
	}
}
