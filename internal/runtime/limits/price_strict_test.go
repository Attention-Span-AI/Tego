// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestLoadRefusesAnUnknownKey: a misspelled price key was dropped by the decoder, leaving the model's price at 0,
// so Cost read $0 as priced and a cost_usd budget never tripped. The table is refused, naming the key and line.
func TestLoadRefusesAnUnknownKey(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "prices-typo.yaml"))
	if err == nil {
		t.Fatal("Load accepted a table with a misspelled key")
	}
	if !errors.Is(err, ErrPriceTable) {
		t.Errorf("error %v does not wrap ErrPriceTable", err)
	}
	for _, want := range []string{"input_per_mtoken", "line 5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestLoadPartialModelIsUnpriced: a model whose entry leaves out the input or the output price is unpriced, as a
// model the table does not name is, never charged $0 for the missing counter.
func TestLoadPartialModelIsUnpriced(t *testing.T) {
	table, err := Load(filepath.Join("testdata", "prices-partial.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, m := range []string{"no-output", "no-input"} {
		if c, priced := table.Cost(ledger.TokenUsage{Model: m, In: 1_000_000, Out: 1_000_000}); priced {
			t.Errorf("model %s: Cost = %v priced, want unpriced", m, c)
		}
	}
	if c, priced := table.Cost(ledger.TokenUsage{Model: "complete", In: 1_000_000, Out: 1_000_000}); !priced || !nearly(c, 6) {
		t.Errorf("complete model: Cost = %v, %v; want 6, true", c, priced)
	}
	// MaxCost charges an unpriced response at the highest complete price; a partial entry's missing counter
	// never lowers that bound.
	if c, ok := table.MaxCost(ledger.TokenUsage{Model: "no-output", In: 1_000_000, Out: 1_000_000}); !ok || c < 6 {
		t.Errorf("MaxCost = %v, %v; want at least 6, true", c, ok)
	}
	// A table whose every entry is partial prices nothing: no bound can be enforced.
	only := &PriceTable{Version: PriceVersion, Models: map[string]ModelPrice{"no-output": table.Models["no-output"]}}
	if _, ok := only.MaxCost(ledger.TokenUsage{Model: "x", In: 1}); ok {
		t.Error("MaxCost over a table of partial entries reported a bound")
	}
}

// TestMissingCachePriceIsUnpricedWhenUsed: an entry that leaves out cache_read_per_mtok or cache_write_per_mtok
// makes a response that reports that counter unpriced, as a missing 1-hour rate does, never charged $0 for it;
// a response that reports none of it is still priced (R2).
func TestMissingCachePriceIsUnpricedWhenUsed(t *testing.T) {
	table, err := parse("inline", []byte("version: 1\nmodels:\n  m:\n    input_per_mtok: 1\n    output_per_mtok: 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]ledger.TokenUsage{
		"cache reads":  {Model: "m", In: 1_000_000, CacheRead: 1_000_000},
		"cache writes": {Model: "m", In: 1_000_000, CacheWrite: 1_000_000},
	} {
		if c, priced := table.Cost(u); priced {
			t.Errorf("%s with no price: Cost = %v priced, want unpriced", name, c)
		}
	}
	if c, priced := table.Cost(ledger.TokenUsage{Model: "m", In: 1_000_000}); !priced || !nearly(c, 1) {
		t.Errorf("no cache counters: Cost = %v, %v; want 1, true", c, priced)
	}
}

// Concatenated tables and invalid trailing YAML must never leave the first table silently active.
func TestLoadRejectsTrailingPriceDocuments(t *testing.T) {
	for _, tail := range []string{"---\nversion: 999\nunknown: invalid\n", "---\n", "---\n[broken"} {
		_, err := parse("inline", []byte("version: 1\nmodels: {}\n"+tail))
		if !errors.Is(err, ErrPriceTable) {
			t.Errorf("tail %q: got %v, want ErrPriceTable", tail, err)
		}
	}
	if _, err := parse("inline", []byte("version: 1\nmodels: {}\n# trailing comment\n")); err != nil {
		t.Fatalf("one document with a trailing comment: %v", err)
	}
}
