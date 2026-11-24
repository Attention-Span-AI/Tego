// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuilderEqualReviewCannotReviveExpiredTab(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.s.Now = func() time.Time { return now }
	c := f.ref(t, f.contract)
	req := RawReq{Session: "same", Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# identical\n")}
	first, err := f.s.PlanRaw(t.Context(), req)
	if err != nil || first.Err != "" {
		t.Fatalf("first: %+v %v", first, err)
	}
	now = now.Add(draftTTL)
	second, err := f.s.PlanRaw(t.Context(), req)
	if err != nil || second.Err != "" {
		t.Fatalf("second: %+v %v", second, err)
	}
	req.Ack = first.Ack
	if _, err := f.s.ApplyRaw(t.Context(), req); !errors.Is(err, ErrReviewGone) {
		t.Fatalf("expired tab selected later review: %v", err)
	}
	if first.Ack == second.Ack {
		t.Fatal("two reviews share acknowledgement")
	}
	req.Ack = second.Ack
	if _, err := f.s.ApplyRaw(t.Context(), req); err != nil {
		t.Fatalf("live tab: %v", err)
	}
}

func TestBuilderEqualLiveReviewsKeepOwnMetadata(t *testing.T) {
	for _, raw := range []bool{true, false} {
		t.Run(map[bool]string{true: "raw", false: "structured"}[raw], func(t *testing.T) {
			f := newFixture(t)
			c := f.ref(t, f.contract)
			var first, second *ChangePlan
			var err error
			if raw {
				req := RawReq{Session: "same", Ref: c.Ref, Base: "older", Text: []byte(f.text(t) + "\n# identical\n")}
				first, err = f.s.PlanRaw(t.Context(), req)
				if err != nil {
					t.Fatal(err)
				}
				req.Base = c.Base
				second, err = f.s.PlanRaw(t.Context(), req)
			} else {
				req := ChangeReq{Session: "same", Ref: c.Ref, Base: "older", Edits: []Edit{{"remove", "exec.allow", "cat"}}}
				first, err = f.s.PlanChange(t.Context(), req)
				if err != nil {
					t.Fatal(err)
				}
				req.Base = c.Base
				second, err = f.s.PlanChange(t.Context(), req)
			}
			if err != nil || first.Err != "" || second.Err != "" {
				t.Fatalf("previews: %+v %+v %v", first, second, err)
			}
			held, err := f.s.reviewedDraft("same", first.Ack)
			if err != nil || !held.Change.Stale {
				t.Fatalf("later review replaced first metadata: %v", err)
			}
			held, err = f.s.reviewedDraft("same", second.Ack)
			if err != nil || held.Change.Stale {
				t.Fatalf("second metadata: %v", err)
			}
			if first.Ack == second.Ack {
				t.Fatal("equal live reviews share acknowledgement")
			}
		})
	}
}

func TestBuilderSavedReviewCannotReplay(t *testing.T) {
	for _, kind := range []string{"raw", "structured", "new"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			before := f.text(t)
			c := f.ref(t, f.contract)
			var save func() error
			switch kind {
			case "new":
				req := NewReq{Dir: f.newProject(t, "one-use"), Name: "one-use", Blank: true, Session: "same"}
				p, err := f.s.PlanNew(t.Context(), req)
				if err != nil || !p.OK {
					t.Fatalf("preview: %+v %v", p, err)
				}
				save = func() error { _, err := f.s.CreateNew(t.Context(), req, p.Base); return err }
			case "raw":
				req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(before + "\n# once\n"), Session: "same"}
				p, err := f.s.PlanRaw(t.Context(), req)
				if err != nil || p.Err != "" {
					t.Fatalf("preview: %+v %v", p, err)
				}
				req.Ack = p.Ack
				save = func() error { _, err := f.s.ApplyRaw(t.Context(), req); return err }
			default:
				req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}, Session: "same"}
				p, err := f.s.PlanChange(t.Context(), req)
				if err != nil || p.Err != "" {
					t.Fatalf("preview: %+v %v", p, err)
				}
				req.Ack = p.Ack
				save = func() error { _, err := f.s.ApplyChange(t.Context(), req); return err }
			}
			if err := save(); err != nil {
				t.Fatal(err)
			}
			if kind != "new" {
				// Even restoring the old source must never make the acknowledgement usable again.
				if err := os.WriteFile(c.Path, []byte(before), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := save(); !errors.Is(err, ErrReviewGone) {
				t.Fatalf("consumed review reused: %v", err)
			}
		})
	}
}

func TestBuilderManyReviewsEvictOwnOldestFirst(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.s.Now = func() time.Time { return now }
	c := f.ref(t, f.contract)
	req := RawReq{Session: "quiet", Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# same\n")}
	quiet, _ := f.s.PlanRaw(t.Context(), req)
	if quiet.Err != "" {
		t.Fatal(quiet.Err)
	}
	req.Session = "busy"
	var first, last *ChangePlan
	for i := 0; i < maxDrafts+2; i++ {
		// Equal creation times still evict in insertion order.
		p, err := f.s.PlanRaw(t.Context(), req)
		if err != nil || p.Err != "" {
			t.Fatalf("preview %d: %+v %v", i, p, err)
		}
		if i == 0 {
			first = p
		}
		last = p
	}
	if len(f.s.drafts.entries) > maxDrafts {
		t.Fatal("review count exceeds bound")
	}
	if _, err := f.s.reviewedDraft("quiet", quiet.Ack); err != nil {
		t.Fatalf("busy session evicted quiet review before its own: %v", err)
	}
	if _, err := f.s.reviewedDraft("busy", first.Ack); !errors.Is(err, ErrReviewGone) {
		t.Fatalf("old busy review selects another review: %v", err)
	}
	if _, err := f.s.reviewedDraft("busy", last.Ack); err != nil {
		t.Fatalf("newest review missing: %v", err)
	}
}

func TestBuilderReviewIdentityBoundAndClaimedOnce(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := RawReq{Session: "one", Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# one\n")}
	p, _ := f.s.PlanRaw(t.Context(), req)
	q, _ := f.s.PlanRaw(t.Context(), req)
	if p.Err != "" || q.Err != "" {
		t.Fatal("invalid fixture")
	}
	_, mac, _ := strings.Cut(p.Ack, ".")
	forged := reviewIdentity(q.Ack) + "." + mac
	for _, invalid := range []struct{ session, ack string }{{"two", p.Ack}, {"one", forged}} {
		if _, err := f.s.takeReview(invalid.session, invalid.ack); !errors.Is(err, ErrReviewGone) {
			t.Fatalf("invalid identity accepted: %v", err)
		}
	}
	// Wrong tokens cannot consume either valid review. Concurrent valid claims
	// must have exactly one winner before either caller can publish.
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := f.s.takeReview("one", p.Ack); results <- err }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrReviewGone) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("review claimed %d times", successes)
	}
	if _, err := f.s.reviewedDraft("one", q.Ack); err != nil {
		t.Fatalf("other review consumed: %v", err)
	}
}

func TestBuilderReviewAccessNeverExtendsLifetime(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.s.Now = func() time.Time { return now }
	c := f.ref(t, f.contract)
	req := RawReq{Session: "one", Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# one\n")}
	p, _ := f.s.PlanRaw(t.Context(), req)
	if p.Err != "" {
		t.Fatal(p.Err)
	}
	now = now.Add(draftTTL - time.Second)
	if _, err := f.s.reviewedDraft("one", p.Ack); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	req.Ack = p.Ack
	if _, err := f.s.ApplyRaw(t.Context(), req); !errors.Is(err, ErrReviewGone) {
		t.Fatalf("access extended review: %v", err)
	}
}

func TestBuilderReviewCollisionRefusesWithoutReplacing(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := RawReq{Session: "one", Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# one\n")}
	p, _ := f.s.PlanRaw(t.Context(), req)
	if p.Err != "" {
		t.Fatal(p.Err)
	}
	r, err := f.s.reviewedDraft("one", p.Ack)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.drafts.entries[p.ReviewID]; !ok {
		t.Fatal("review keyed by something other than its identity")
	}
	r.Change.Stale = !r.Change.Stale
	if err := f.s.keepReview("one", p.Ack, *r); !errors.Is(err, ErrReviewGone) {
		t.Fatalf("identity collision replaced a review: %v", err)
	}
	held, err := f.s.reviewedDraft("one", p.Ack)
	if err != nil || held.Change.Stale != p.Stale {
		t.Fatalf("collision changed held review: %v", err)
	}
}
