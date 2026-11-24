// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// scopeSeen records the context of each call a page makes to the rule service.
type scopeSeen struct {
	*rules.Service
	mu   sync.Mutex
	ctxs []context.Context
}

func (s *scopeSeen) PlanChange(ctx context.Context, req rules.ChangeReq) (*rules.ChangePlan, error) {
	s.mu.Lock()
	s.ctxs = append(s.ctxs, ctx)
	s.mu.Unlock()
	return s.Service.PlanChange(ctx, req)
}

// One request is one scope: every check of a page shares one start-up budget and one location budget, so no page
// waits the start-up budget more than once (contracts.TestScopeSpendsTheStartupBudgetOnce holds the budget itself),
// and two requests never share one.
func TestEveryRequestIsOneScope(t *testing.T) {
	f := newChangeFix(t)
	c := f.ref(t, f.source)
	seen := &scopeSeen{Service: f.svc}
	f.s.cfg.Rules = seen
	target := "/rules/change/preview?" + url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"add"}, "key": {"exec.allow"}, "v": {"/bin/echo"}}.Encode()
	for range 2 {
		if code, body := f.get(t, target); code != http.StatusOK {
			t.Fatalf("Preview: %d %s", code, body)
		}
	}
	if len(seen.ctxs) != 2 {
		t.Fatalf("the service saw %d requests, want 2", len(seen.ctxs))
	}
	for i, ctx := range seen.ctxs {
		if !contracts.SameScope(ctx, ctx) {
			t.Fatalf("request %d's checks are not in a scope", i)
		}
	}
	if contracts.SameScope(seen.ctxs[0], seen.ctxs[1]) {
		t.Fatal("two requests share one scope")
	}
}

// A page's checks end before the server stops writing: the request scope is bounded by the write deadline less a
// margin of at least five seconds (times raceScale in a race build), derived from the same constant, so a page that
// waits for a helper slot is answered and its connection is not closed with no response.
func TestRequestScopeIsBoundedByTheWriteDeadline(t *testing.T) {
	if writeTimeout-requestBound < 5*time.Second*raceScale || requestBound <= 0 {
		t.Fatalf("a page keeps %v of its write deadline %v for its answer, want at least %v", writeTimeout-requestBound, writeTimeout, 5*time.Second*raceScale)
	}
	f := newChangeFix(t)
	c := f.ref(t, f.source)
	seen := &scopeSeen{Service: f.svc}
	f.s.cfg.Rules = seen
	target := "/rules/change/preview?" + url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"add"}, "key": {"exec.allow"}, "v": {"/bin/echo"}}.Encode()
	if code, body := f.get(t, target); code != http.StatusOK {
		t.Fatalf("Preview: %d %s", code, body)
	}
	if len(seen.ctxs) != 1 {
		t.Fatalf("the service saw %d requests, want 1", len(seen.ctxs))
	}
	left, bounded := contracts.ScopeLeft(seen.ctxs[0])
	if !bounded || left > requestBound || left < requestBound-writeMargin {
		t.Fatalf("a page's scope has %v left (bounded %v), want about the request bound %v", left, bounded, requestBound)
	}
}
