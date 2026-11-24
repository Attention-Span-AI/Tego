// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

func TestBuilderExpiredTabCannotUseEqualReview(t *testing.T) {
	f := newChangeFix(t)
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	f.svc.Now = func() time.Time { return now }
	c := f.ref(t, f.other)
	target := "/rules/change"
	_, body := f.get(t, target+"?c="+c.Ref+"&view=full")
	input := builderRenderedEditForm(t, body)
	input.Set("text", strings.TrimPrefix(input.Get("text"), "\n")+"\n# identical review\n")
	input.Set("step", "check")
	input.Set("view", "full")
	check := func() (string, string) {
		t.Helper()
		w := post(f.s, target, input, own, "", f.c)
		match := ackField.FindStringSubmatch(w.Body.String())
		if w.Code != http.StatusOK || match == nil || !strings.Contains(w.Body.String(), "It compiles.") {
			t.Fatalf("Check: %d", w.Code)
		}
		return w.Body.String(), match[1]
	}
	firstBody, firstAck := check()
	first := builderRenderedEditForm(t, firstBody)
	first.Set("text", strings.TrimPrefix(first.Get("text"), "\n"))
	first.Set("step", "save")
	first.Set("view", "full")
	first.Set("ack", firstAck)
	now = now.Add(30 * time.Minute)
	secondBody, secondAck := check()
	before := readText(t, c.Path)
	w := post(f.s, target, first, own, "", f.c)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), rules.ErrReviewGone.Error()) || readText(t, c.Path) != before {
		t.Fatalf("expired tab used later equal review: %d %s", w.Code, w.Header().Get("Location"))
	}
	if firstAck == secondAck || len(firstAck) != 113 {
		t.Fatal("rendered reviews do not carry independent identity/MAC tokens")
	}
	second := builderRenderedEditForm(t, secondBody)
	second.Set("text", strings.TrimPrefix(second.Get("text"), "\n"))
	second.Set("step", "save")
	second.Set("view", "full")
	second.Set("ack", secondAck)
	w = post(f.s, target, second, own, "", f.c)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/rules/change/saved") || readText(t, c.Path) != second.Get("text") {
		t.Fatalf("live equal review did not save its exact bytes: %d %s", w.Code, w.Header().Get("Location"))
	}
}
