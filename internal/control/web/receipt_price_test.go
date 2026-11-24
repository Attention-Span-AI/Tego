// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/pricetable"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// pricedMachine is a machine config whose price table is a file this user owns (the trust rule's reading of one).
func pricedMachine(t *testing.T, table string) *config.Machine {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "prices.yaml")
	if err := os.WriteFile(p, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Prices = config.Setting[string]{Value: p}
	return m
}

const sonnetTable = "version: 1\nupdated: 2026-09-22\nmodels:\n  claude-sonnet-4-5-20250929:\n    input_per_mtok: 3.00\n    output_per_mtok: 15.00\n"

// TestReceiptTabPricesAsTheTerminalDoes: the Receipt tab prices a run's model responses with the machine's price table,
// the table `tego receipt` and `tego measure` read, so one run says one cost in both. The tab built its receipt with no
// prices at all, so it counted every response unpriced and left the cost out of the tile beside a terminal receipt that
// said "$4.50 est." (the table is read through pricetable.FromMachine in both). A table that is replaced prices the
// next view, and a machine with no table says what the terminal says: nothing priced.
func TestReceiptTabPricesAsTheTerminalDoes(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000071-priced"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		line(run, "py", 0, t0, "run_start", `"tier":"landlock","capture":"uprobe","command":["agent"]`),
		line(run, "py", 1, t0.Add(time.Second), "ssl_response", `"request_seq":1,"status":200,"parser_version":"1","model":"claude-sonnet-4-5-20250929","latency_ms":1,"usage":{"input":1000000,"output":100000}`),
		line(run, "py", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`),
	}, "")
	if err := os.WriteFile(filepath.Join(root, run, ledger.EventsFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// terminal is `tego receipt`'s numbers: receipt.Compute with the machine's table, as internal/cli/receipt.go does.
	terminal := func(m *config.Machine) *receipt.Receipt {
		r, err := ledger.OpenReader(filepath.Join(root, run))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		r.SkipNewerVersions()
		rc, err := receipt.Compute(t.Context(), r, receipt.Options{Prices: pricetable.NewLazy(func() pricetable.Coster {
			if tab, _ := pricetable.FromMachine(m); tab != nil {
				return tab
			}
			return nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		return rc
	}
	tab := func(m *config.Machine) (string, *Server) {
		s, err := New(Config{Ledger: root, Port: port, Token: "tok123", Machine: m,
			Now: func() time.Time { return time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) }})
		if err != nil {
			t.Fatal(err)
		}
		trustPeer(s)
		return get(t, s, login(t, s), "/runs/"+run+"/receipt"), s
	}

	m := pricedMachine(t, sonnetTable)
	want := terminal(m)
	if want.Tokens.CostText == "" || want.Tokens.Unpriced != 0 || !strings.Contains(want.Tokens.CostText, "4.50") {
		t.Fatalf("the terminal receipt does not price the run: %+v", want.Tokens)
	}
	page, s := tab(m)
	if !strings.Contains(page, want.Tokens.CostText) {
		t.Errorf("the Receipt tab does not say the terminal's cost %q:\n%s", want.Tokens.CostText, page)
	}

	// The table changes under a running dashboard: the next view prices by the new one.
	if err := os.WriteFile(m.Prices.Value, []byte(strings.ReplaceAll(sonnetTable, "3.00", "6.00")), 0o600); err != nil {
		t.Fatal(err)
	}
	again := terminal(m)
	if again.Tokens.CostText == want.Tokens.CostText {
		t.Fatalf("the table change did not move the terminal's cost: %q", again.Tokens.CostText)
	}
	if page := get(t, s, login(t, s), "/runs/"+run+"/receipt"); !strings.Contains(page, again.Tokens.CostText) {
		t.Errorf("a replaced table did not price the next view: want %q in\n%s", again.Tokens.CostText, page)
	}

	// No usable table: both count the response unpriced, and neither shows a cost.
	none := config.Builtin()
	none.Prices = config.Setting[string]{Value: filepath.Join(t.TempDir(), "absent.yaml")}
	if rc := terminal(none); rc.Tokens.Unpriced != 1 || rc.Tokens.EstCostUSD != 0 {
		t.Fatalf("terminal with no table: %+v", rc.Tokens)
	}
	page, _ = tab(none)
	if strings.Contains(page, "4.50 est.") {
		t.Errorf("a machine with no table priced the run:\n%s", page)
	}
}

// TestReceiptTabSeesEveryReplacementOfThePriceTable: the table is replaced twice within a second, each time by a rename
// of a file of the same size, and the file system's clock gives every version the same modification time (the stamp a
// coarse timestamp tick gives two quick writes; Chtimes makes it so on any host). Each view after a replacement is
// priced by the table that replaced the last, never by an older one: the dashboard keyed its receipts by the table's size
// and modification time, so the second table was never seen (a Debian 13 guest showed "$4.50 est." for a table that said
// $7.50).
func TestReceiptTabSeesEveryReplacementOfThePriceTable(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000075-reprice"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	root := t.TempDir()
	finishRun(t, root, run,
		line(run, "py", 0, t0, "run_start", `"tier":"landlock","capture":"uprobe","command":["agent"]`),
		line(run, "py", 1, t0.Add(time.Second), "ssl_response", `"request_seq":1,"status":200,"parser_version":"1","model":"claude-sonnet-4-5-20250929","latency_ms":1,"usage":{"input":1000000,"output":100000}`),
		line(run, "py", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	m := pricedMachine(t, sonnetTable)
	dir := filepath.Dir(m.Prices.Value)
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	replace := func(input string) {
		t.Helper()
		tmp := filepath.Join(dir, ".prices.new")
		if err := os.WriteFile(tmp, []byte(strings.ReplaceAll(sonnetTable, "3.00", input)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(tmp, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, m.Prices.Value); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Config{Ledger: root, Port: port, Token: "tok123", Machine: m,
		Now: func() time.Time { return time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	view := func() string { return get(t, s, c, "/runs/"+run+"/receipt") }
	replace("3.00")
	if page := view(); !strings.Contains(page, "$4.50 est.") {
		t.Fatalf("the first table is not priced:\n%s", page)
	}
	// $6.00 per million input tokens and $15.00 output: 6.00 + 1.50 = $7.50; $9.00: $10.50. The same size and the same stamp.
	for _, c2 := range []struct{ input, want string }{{"6.00", "$7.50 est."}, {"9.00", "$10.50 est."}, {"3.00", "$4.50 est."}} {
		replace(c2.input)
		if page := view(); !strings.Contains(page, c2.want) {
			t.Errorf("a table replaced to %s did not price the next view (want %q):\n%s", c2.input, c2.want, page)
		}
	}
}
