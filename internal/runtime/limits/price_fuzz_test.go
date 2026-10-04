// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"errors"
	"testing"
)

// FuzzParsePriceTable feeds parse arbitrary bytes standing for the operator's price table. It must never panic,
// and a table it accepts holds the invariants every reader of it relies on: the supported version and only
// non-negative finite prices.
func FuzzParsePriceTable(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("version: 1\nmodels:\n  m:\n    input_per_mtok: 3\n    output_per_mtok: 15\n"))
	f.Add([]byte("version: 1\nmodels:\n  m:\n    input_per_mtok: -1\n    output_per_mtok: .nan\n"))
	f.Add([]byte("version: 1\nserver_tool_per_request:\n  web_search: .inf\n"))
	f.Add([]byte("version: 2\n"))
	f.Add([]byte("models: [1, 2\n"))
	f.Add([]byte("&a [*a]\n"))
	f.Add([]byte("unknown: 1\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		tab, err := parse("fuzz.yaml", b)
		if err != nil {
			if tab != nil {
				t.Fatalf("a table came back with the error %v", err)
			}
			if !errors.Is(err, ErrPriceTable) {
				t.Fatalf("error %v is not an ErrPriceTable", err)
			}
			return
		}
		if tab.Version != PriceVersion {
			t.Fatalf("accepted version %v", tab.Version)
		}
		for name, p := range tab.Models {
			vals := []float64{p.InputPerMTok, p.OutputPerMTok, p.CacheReadPerMTok, p.CacheWritePerMTok}
			if p.CacheWrite1hPerMTok != nil {
				vals = append(vals, *p.CacheWrite1hPerMTok)
			}
			for _, v := range vals {
				if !validPrice(v) {
					t.Fatalf("model %q accepted with price %v", name, v)
				}
			}
		}
		for name, v := range tab.ServerToolPerRequest {
			if !validPrice(v) {
				t.Fatalf("server tool %q accepted with price %v", name, v)
			}
		}
	})
}
