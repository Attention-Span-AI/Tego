// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/runtime/limits"
)

// samplePrices is the price table the examples' headers tell a reader to install before a contract that declares
// limits.cost_usd can run: without a table that loads, its run is refused [budget-unmetered] (limits-check-doctor-cli.md
// R32).
var samplePrices = filepath.Join(filepath.Dir(pkgDir), "prices.example.yaml")

// samplePriceKeys are the five prices of a model entry. An entry that leaves one out loads, and leaves unpriced every
// response that reports that counter (limits.PriceTable.Cost), which a cost budget then charges at the table's dearest
// rates: a table to start from gives each model all five.
var samplePriceKeys = []string{"input_per_mtok", "output_per_mtok", "cache_read_per_mtok", "cache_write_per_mtok", "cache_write_1h_per_mtok"}

// TestSamplePriceTable: examples/prices.example.yaml loads as tego loads a price table (limits.Load: one strict document
// of version 1, no key the format does not name, no negative price), says when its prices were read, prices at least
// one model, gives every model all five prices, and names a fee for the web searches a response can report, so that a
// cost budget under it prices each response of a model it names at that model's own rates. A Claude entry keeps the
// Claude API's caching multipliers (5-minute writes at 1.25 times the input price, 1-hour writes at twice it, reads at a
// tenth of it or less) and an output price above its input price, which a mistyped price breaks.
func TestSamplePriceTable(t *testing.T) {
	table, err := limits.Load(samplePrices)
	if err != nil {
		t.Fatalf("the sample price table does not load as tego reads one: %v", err)
	}
	if table.Updated.IsZero() {
		t.Error("the sample price table has no updated: date, so a reader cannot tell how old its prices are")
	}
	if len(table.Models) == 0 || !table.PricesAnyModel() {
		t.Fatalf("the sample price table prices no model: a cost_usd budget under it is refused, as with no table")
	}
	if fee, ok := table.ServerToolPerRequest["web_search_requests"]; !ok || fee <= 0 {
		t.Errorf("server_tool_per_request.web_search_requests is %v (named: %v): a response that reports web searches is unpriced", fee, ok)
	}
	b, err := os.ReadFile(samplePrices)
	if err != nil {
		t.Fatal(err)
	}
	// Read as the file spells it: limits.Load reads a price left out as 0 and only marks the entry.
	var raw struct {
		Models map[string]map[string]float64 `yaml:"models"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for name, prices := range raw.Models {
		for _, k := range samplePriceKeys {
			if _, ok := prices[k]; !ok {
				t.Errorf("%s has no %s: a response of it that reports that counter is unpriced", name, k)
			}
		}
		if !strings.HasPrefix(name, "claude-") {
			continue
		}
		in := prices["input_per_mtok"]
		for _, c := range []struct {
			key  string
			want float64
		}{{"cache_write_per_mtok", 1.25 * in}, {"cache_write_1h_per_mtok", 2 * in}} {
			if got := prices[c.key]; math.Abs(got-c.want) > 1e-9 {
				t.Errorf("%s: %s is %v, want %v for an input price of %v (the Claude API's cache-write multiplier)", name, c.key, got, c.want, in)
			}
		}
		if got := prices["cache_read_per_mtok"]; got <= 0 || got > in/10+1e-9 {
			t.Errorf("%s: cache_read_per_mtok is %v for an input price of %v; the Claude API charges a cache read a tenth of the input price or less", name, got, in)
		}
		if prices["output_per_mtok"] <= in {
			t.Errorf("%s: output_per_mtok %v is not above input_per_mtok %v", name, prices["output_per_mtok"], in)
		}
	}
}
