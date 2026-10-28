// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestNowOptionsFenceLift: on a running Adjustable run (ADR 0125), a widening whose entry the run's fence lists says
// "Live now" with the fence entry to lift, and places no block; a widening outside the fence, and every widening on a
// Locked run, keep their "Next run" line word for word.
func TestNowOptionsFenceLift(t *testing.T) {
	fence := []record.LiveFenceEntry{
		{Kind: "read", Value: "/h/billing-exports", Source: record.LiveFenceSourceNew},
		{Kind: "read", Value: "/p/secrets", Source: record.LiveFenceSourceDeny},
		{Kind: "net", Value: "api.stripe.com:443", Source: record.LiveFenceSourceNew},
		{Kind: "exec", Value: "/usr/bin/psql", Source: record.LiveFenceSourceNew},
		{Kind: "exec", Value: "/usr/bin/curl", Source: record.LiveFenceSourceDeny},
		{Kind: "exec", Value: "/usr/bin/pg_dump", Source: record.LiveFenceSourceDeny}, // compiled from exec.deny: [pg_dump]
	}
	facts := map[string]livestatus.Facts{
		"r-adj":    {RecordMinor: record.MinorLiveModes, Timed: true, Adjustable: true, Fence: fence},
		"r-locked": {RecordMinor: record.MinorLiveModes, Timed: true},
	}
	s := &Service{Home: "/h",
		readsHeld: func(string) (bool, string) { return true, "" },
		facts:     func(run string) livestatus.Facts { return facts[run] },
	}
	rest := map[string][]string{"fs.read": {"~/billing-exports/"}, "net.allow": {"api.stripe.com:443", "x.example.com:443"},
		"exec.allow": {"/usr/bin/psql", "/usr/bin/curl"}}
	tests := []struct {
		name       string
		c          rule.Change
		kind, val  string
		inFence    bool
		lockedWhy  string // the Locked run's line, unchanged from before Adjustable existed
		outsideWhy string // on the Adjustable run, when the change lies outside its fence ("" = inFence)
	}{
		{"fs.read added", rule.Change{Key: "fs.read", Entry: "~/billing-exports/"}, "read", "/h/billing-exports", true, whyUnknownKey, ""},
		{"deny_read removed", rule.Change{Remove: true, Key: "fs.deny_read", Entry: "./secrets"}, "read", "/p/secrets", true, whyWidens, ""},
		{"net.allow added", rule.Change{Key: "net.allow", Entry: "api.stripe.com:443"}, "net", "api.stripe.com:443", true, whyWidens, ""},
		{"exec.allow added", rule.Change{Key: "exec.allow", Entry: "/usr/bin/psql"}, "exec", "/usr/bin/psql", true, whyWidens, ""},
		{"exec.deny removed", rule.Change{Remove: true, Key: "exec.deny", Entry: "/usr/bin/curl"}, "exec", "/usr/bin/curl", true, whyWidens, ""},
		{"outside the fence", rule.Change{Key: "net.allow", Entry: "x.example.com:443"}, "", "", false, whyWidens, whyWidens},
		{"a command entry", rule.Change{Remove: true, Key: "exec.deny", Entry: "/usr/bin/curl -X"}, "", "", false, whyWidens, whyWidens},
		// A bare-name exec.deny removal lifts the deny-source entry compile resolved the name to.
		{"bare exec.deny removed", rule.Change{Remove: true, Key: "exec.deny", Entry: "pg_dump"}, "exec", "/usr/bin/pg_dump", true, whyWidens, ""},
		// An addition is new access: it never lifts a deny-source entry, whose contract refusal the change keeps, so the
		// next run would still refuse it.
		{"fs.read added over a deny entry", rule.Change{Key: "fs.read", Entry: "./secrets"}, "", "", false, whyUnknownKey, whyUnknownKey},
		{"exec.allow added over a deny entry", rule.Change{Key: "exec.allow", Entry: "/usr/bin/curl"}, "", "", false, whyWidens, whyWidens},
		// A removal takes out a refusal: it never grants a new-source entry.
		{"deny_read removed over a new entry", rule.Change{Remove: true, Key: "fs.deny_read", Entry: "~/billing-exports"}, "", "", false, whyWidens, whyWidens},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.nowOptions(context.Background(), []string{"r-adj", "r-locked"}, []rule.Change{tt.c}, "/p", rest)
			if len(got) != 2 {
				t.Fatalf("options = %+v, want one per run", got)
			}
			adj, locked := got[0], got[1]
			if locked.FenceLift || locked.OK || locked.Why != tt.lockedWhy || locked.Kind != "" {
				t.Errorf("Locked run's line changed: %+v, want Why %q", locked, tt.lockedWhy)
			}
			if !tt.inFence {
				if adj.FenceLift || adj.Why != tt.outsideWhy {
					t.Errorf("outside the fence: %+v, want Why %q", adj, tt.outsideWhy)
				}
				return
			}
			want := NowOption{Run: "r-adj", Kind: tt.kind, Value: tt.val, Why: WhyFenceLift, Change: tt.c.String(), Cwd: "/p", FenceLift: true}
			if adj != want {
				t.Errorf("Adjustable run:\n got %+v\nwant %+v", adj, want)
			}
			if adj.OK || adj.Block != "" {
				t.Errorf("a fence lift placed a block through Also apply now: %+v", adj)
			}
		})
	}
	if WhyFenceLift != "it lies inside the run's fence, so a lift on the Rules page gives it now (Tego's live layer, not the kernel)" {
		t.Errorf("WhyFenceLift = %q", WhyFenceLift)
	}
}

// TestNowOptionsFenceTakenBack: an addition a later change took back offers no lift, on an Adjustable run too.
func TestNowOptionsFenceTakenBack(t *testing.T) {
	s := &Service{Home: "/h",
		facts: func(string) livestatus.Facts {
			return livestatus.Facts{RecordMinor: record.MinorLiveModes, Timed: true, Adjustable: true,
				Fence: []record.LiveFenceEntry{{Kind: "net", Value: "api.stripe.com:443", Source: record.LiveFenceSourceNew}}}
		},
	}
	got := s.nowOptions(context.Background(), []string{"r-adj"}, []rule.Change{{Key: "net.allow", Entry: "api.stripe.com:443"}},
		"/p", map[string][]string{"net.allow": {}})
	if len(got) != 1 || got[0].FenceLift || got[0].Why != whyTakenBack {
		t.Errorf("taken back: %+v", got)
	}
}
