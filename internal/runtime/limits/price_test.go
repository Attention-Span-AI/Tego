// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestLoad reads the shipped table shape and every way a table can be refused (R32, E15).
func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{name: "a good table", file: "prices.yaml"},
		{name: "a version this binary does not know", file: "prices-v99.yaml", wantErr: true},
		{name: "a negative price", file: "prices-negative.yaml", wantErr: true},
		{name: "a negative 1-hour cache-write price", file: "prices-negative-1h.yaml", wantErr: true},
		{name: "a negative server-tool fee", file: "prices-negative-fee.yaml", wantErr: true},
		{name: "yaml that does not parse as a table", file: "prices-malformed.yaml", wantErr: true},
		{name: "a file that is not there", file: "prices-missing.yaml", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Load(filepath.Join("testdata", tc.file))
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("Load(%s) succeeded, want an error", tc.file)
			case tc.wantErr:
				if !errors.Is(err, ErrPriceTable) {
					t.Fatalf("error %v does not wrap ErrPriceTable", err)
				}
				return
			case err != nil:
				t.Fatalf("Load(%s): %v", tc.file, err)
			}
			if got.Version != PriceVersion {
				t.Errorf("version = %d, want %d", got.Version, PriceVersion)
			}
			if len(got.Models) != 2 {
				t.Fatalf("%d models, want 2", len(got.Models))
			}
			if got.Path == "" {
				t.Error("Path is empty; a loaded table remembers where it came from")
			}
			if got.Updated.IsZero() {
				t.Error("updated did not parse")
			}
			p := got.Models["claude-sonnet-4-5-20250929"]
			if p.CacheWrite1hPerMTok == nil || *p.CacheWrite1hPerMTok != 6 {
				t.Errorf("cache_write_1h_per_mtok = %v, want 6", p.CacheWrite1hPerMTok)
			}
			p.CacheWrite1hPerMTok = nil
			want := ModelPrice{InputPerMTok: 3, OutputPerMTok: 15, CacheReadPerMTok: 0.30, CacheWritePerMTok: 3.75}
			if p != want {
				t.Errorf("model price %+v, want %+v", p, want)
			}
			if h := got.Models["claude-haiku-4-5-20251001"]; h.CacheWrite1hPerMTok != nil {
				t.Errorf("a model with no cache_write_1h_per_mtok read %v, want it unset", *h.CacheWrite1hPerMTok)
			}
			if fee := got.ServerToolPerRequest["web_search_requests"]; fee != 0.01 {
				t.Errorf("web_search_requests fee = %v, want 0.01", fee)
			}
		})
	}
}

// TestCost covers R2's formula, the nil table and the unpriced model.
func TestCost(t *testing.T) {
	table, err := Load(filepath.Join("testdata", "prices.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	const sonnet, haiku = "claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"
	tests := []struct {
		name       string
		table      *PriceTable
		u          ledger.TokenUsage
		want       float64
		wantPriced bool
	}{
		{
			name: "every counter is priced", table: table,
			u:    ledger.TokenUsage{Model: sonnet, In: 1_000_000, Out: 100_000, CacheRead: 500_000, CacheWrite: 200_000},
			want: 3 + 1.5 + 0.15 + 0.75, wantPriced: true,
		},
		{
			name: "a second model has its own prices", table: table,
			u: ledger.TokenUsage{Model: haiku, In: 2_000_000, Out: 1_000_000}, want: 2 + 5, wantPriced: true,
		},
		{name: "no tokens cost nothing", table: table, u: ledger.TokenUsage{Model: haiku}, wantPriced: true},
		{name: "a model the table does not list", table: table, u: ledger.TokenUsage{Model: "gpt-9", In: 1_000_000}},
		{name: "a nil table prices nothing", table: nil, u: ledger.TokenUsage{Model: haiku, In: 1_000_000}},
		{name: "an empty table prices nothing", table: &PriceTable{Version: PriceVersion}, u: ledger.TokenUsage{Model: "x", In: 1}},
		// 1-hour cache writes are billed above the 5-minute kind, and were charged as if they were the cheaper one.
		{
			name: "1-hour cache writes are charged at their own rate", table: table,
			u:    ledger.TokenUsage{Model: sonnet, CacheWrite: 300_000, CacheWrite1h: 100_000},
			want: 0.2*3.75 + 0.1*6, wantPriced: true,
		},
		{
			name: "a model with no 1-hour rate is unpriced for 1-hour writes", table: table,
			u: ledger.TokenUsage{Model: haiku, In: 1_000_000, CacheWrite: 100_000, CacheWrite1h: 100_000},
		},
		{
			name: "a model with no 1-hour rate is priced when none were made", table: table,
			u: ledger.TokenUsage{Model: haiku, CacheWrite: 1_000_000}, want: 1.25, wantPriced: true,
		},
		// Server-side tool requests carry a fee of their own and were charged nothing.
		{
			name: "web search requests are charged their fee", table: table,
			u:    ledger.TokenUsage{Model: sonnet, In: 1_000_000, ServerTool: map[string]int{"web_search_requests": 5}},
			want: 3 + 5*0.01, wantPriced: true,
		},
		{
			name: "a server tool with no fee is unpriced", table: table,
			u: ledger.TokenUsage{Model: sonnet, In: 1_000_000, ServerTool: map[string]int{"code_execution_requests": 1}},
		},
		{
			name: "a server tool with no fee and no requests costs nothing", table: table,
			u:    ledger.TokenUsage{Model: sonnet, ServerTool: map[string]int{"code_execution_requests": 0}},
			want: 0, wantPriced: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, priced := tc.table.Cost(tc.u)
			if priced != tc.wantPriced {
				t.Fatalf("priced = %v, want %v", priced, tc.wantPriced)
			}
			if !nearly(got, tc.want) {
				t.Errorf("cost = %.6f, want %.6f", got, tc.want)
			}
		})
	}
}

// TestMaxCostNewCounters: what an unpriced response is charged toward a cost ceiling covers the
// 1-hour cache writes, at the dearest output rate when some entry names no 1-hour price (haiku here), and the server-tool requests, at their fee
// or the dearest fee when the tool has none.
func TestMaxCostNewCounters(t *testing.T) {
	table, err := Load(filepath.Join("testdata", "prices.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := table.MaxCost(ledger.TokenUsage{Model: "gpt-9", CacheWrite: 1_000_000, CacheWrite1h: 1_000_000,
		ServerTool: map[string]int{"web_search_requests": 2, "code_execution_requests": 3}})
	if want := 15 + 5*0.01; !ok || !nearly(got, want) {
		t.Fatalf("MaxCost = %.6f %v, want %.6f", got, ok, want)
	}
}

// TestFromMachine covers E15 and R32: the machine config's `prices` path is the override, and every
// failure is a warning with the gap reason to record, never an error that could fail a run.
func TestFromMachine(t *testing.T) {
	machine := func(path string) *config.Machine {
		m := config.Builtin()
		m.Prices = config.Setting[string]{Value: path}
		return m
	}
	tests := []struct {
		name      string
		m         *config.Machine
		wantTable bool
		wantWhy   string
	}{
		{name: "the configured table", m: machine(trustedCopy(t, "prices.yaml")), wantTable: true},
		{name: "no machine config at all", m: nil, wantWhy: GapNoPriceTable},
		{name: "an empty path", m: machine(""), wantWhy: GapNoPriceTable},
		{name: "a missing file", m: machine(filepath.Join("testdata", "nope.yaml")), wantWhy: GapNoPriceTable},
		{name: "a version mismatch", m: machine(trustedCopy(t, "prices-v99.yaml")), wantWhy: GapVersionMismatch},
		// yaml.v3 panicked on a key that is a list beside a merge key, which failed the run instead (config.GuardYAML).
		{name: "a list key beside a merge key", m: machine(trustedCopy(t, "prices-mergekey.yaml")), wantWhy: GapNoPriceTable},
		// A table that loads and lists no model prices nothing, as a missing one does: a cost_usd budget under it
		// passed every response at $0, never tripped and drew no word from compile or run.
		{name: "a table listing no models", m: machine(trustedCopy(t, "prices-empty.yaml")), wantWhy: GapNoPriceTable},
		{name: "a table of server-tool fees alone", m: machine(trustedCopy(t, "prices-nomodels.yaml")), wantWhy: GapNoPriceTable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, warn := FromMachine(tc.m)
			if tc.wantTable {
				if warn != nil {
					t.Fatalf("warning %+v, want none", *warn)
				}
				if got == nil {
					t.Fatal("no table")
				}
				return
			}
			if got != nil {
				t.Fatalf("table %+v, want none", got)
			}
			if warn == nil {
				t.Fatal("no warning; a run must be told cost is not estimated")
			}
			if warn.Why != tc.wantWhy {
				t.Errorf("why = %q, want %q", warn.Why, tc.wantWhy)
			}
			if warn.Message == "" {
				t.Error("the warning has no line to print")
			}
			// A nil table never breaches a cost ceiling, which is E15's whole point.
			if cost, priced := got.Cost(ledger.TokenUsage{Model: "claude-sonnet-4-5-20250929", In: 1 << 40, Out: 1 << 40}); priced || cost != 0 {
				t.Errorf("Cost on a refused table = %v, %v", cost, priced)
			}
		})
	}
}

// TestMaxCostBoundsCacheTokensATableDoesNotPrice: a table whose entries name no cache price at all still
// bounds an unpriced response's cache reads and writes, at the table's dearest output rate, not at $0.
func TestMaxCostBoundsCacheTokensATableDoesNotPrice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prices.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nmodels:\n  m:\n    input_per_mtok: 3\n    output_per_mtok: 15\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := table.MaxCost(ledger.TokenUsage{Model: "x", CacheRead: 1_000_000, CacheWrite: 1_000_000})
	if want := 15.0 + 15.0; !ok || !nearly(got, want) {
		t.Fatalf("MaxCost = %.6f %v, want %.6f", got, ok, want)
	}
}

// TestMaxCostMixedCachePricesBoundsTheEntryThatOmitsThem: one entry naming cheap cache prices must not
// bound an unpriced response of another entry that names none; the dearest output rate does.
func TestMaxCostMixedCachePricesBoundsTheEntryThatOmitsThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prices.yaml")
	y := "version: 1\nmodels:\n  cheap:\n    input_per_mtok: 1\n    output_per_mtok: 5\n    cache_read_per_mtok: 0.1\n    cache_write_per_mtok: 1.25\n" +
		"  dear:\n    input_per_mtok: 15\n    output_per_mtok: 75\n"
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := table.Cost(ledger.TokenUsage{Model: "dear", CacheRead: 1}); ok {
		t.Fatal("dear's cache read should be unpriced")
	}
	got, ok := table.MaxCost(ledger.TokenUsage{Model: "dear", CacheRead: 1_000_000, CacheWrite: 1_000_000, CacheWrite1h: 500_000})
	if want := 75.0 + 75.0*0.5 + 75.0*0.5; !ok || !nearly(got, want) {
		t.Fatalf("MaxCost = %.6f %v, want %.6f", got, ok, want)
	}
}
