// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"gopkg.in/yaml.v3"
)

// PriceVersion is the only price-table schema version this binary understands. A table that
// declares any other version is handled like an unreadable one (R32): a warning and no prices,
// never a hard error, because a run must not fail over a cost estimate.
const PriceVersion = 1

// Gap reasons this package records when it cannot price a response (R2, E15, R32). They are the
// `why` of a gap event whose `what` is record.GapRecord, each emitted at most once per run.
const (
	// GapNoPriceTable is recorded once when the run has no price table at all.
	GapNoPriceTable = "no-price-table"
	// GapVersionMismatch is recorded once when the table's version is not PriceVersion.
	GapVersionMismatch = "price-table-version-mismatch"
	// GapUnpricedModel is recorded once per model the table does not price.
	GapUnpricedModel = "unpriced-model"
)

// ErrPriceTable is the sentinel every price-table failure wraps, so a caller can tell a bad table
// from any other error with errors.Is.
var ErrPriceTable = errors.New("limits: price table")

// ModelPrice is one model's price in USD per million tokens, one field per usage counter of
// spec/record/v1's ssl_response `usage` object (R2).
type ModelPrice struct {
	InputPerMTok      float64 `yaml:"input_per_mtok"`
	OutputPerMTok     float64 `yaml:"output_per_mtok"`
	CacheReadPerMTok  float64 `yaml:"cache_read_per_mtok"`
	CacheWritePerMTok float64 `yaml:"cache_write_per_mtok"`
	// CacheWrite1hPerMTok prices the cache writes made with the 1-hour lifetime (usage.cache_write_1h), which
	// the upstream bills above the 5-minute kind CacheWritePerMTok prices. It has no default: a model whose
	// entry leaves it out is unpriced for a response that reports 1-hour writes, as a model the table does not
	// name is, rather than charged the cheaper 5-minute rate (R2).
	CacheWrite1hPerMTok *float64 `yaml:"cache_write_1h_per_mtok"`
	// partial marks an entry Load read with no input_per_mtok or no output_per_mtok. It is unpriced, as a model
	// the table does not name is, rather than charged $0 for the counter it leaves out (R2).
	partial bool
	// noCacheRead and noCacheWrite mark an entry Load read with no cache_read_per_mtok or no
	// cache_write_per_mtok. The entry is unpriced for a response that reports that counter above 0, as it is for
	// 1-hour writes with no cache_write_1h_per_mtok, and priced for one that reports none of it (R2).
	noCacheRead, noCacheWrite bool
}

// rawModelPrice is ModelPrice as the file spells it, every price a pointer so Load can tell a price left out
// from a price of 0.
type rawModelPrice struct {
	InputPerMTok        *float64 `yaml:"input_per_mtok"`
	OutputPerMTok       *float64 `yaml:"output_per_mtok"`
	CacheReadPerMTok    *float64 `yaml:"cache_read_per_mtok"`
	CacheWritePerMTok   *float64 `yaml:"cache_write_per_mtok"`
	CacheWrite1hPerMTok *float64 `yaml:"cache_write_1h_per_mtok"`
}

// rawPriceTable is PriceTable as the file spells it.
type rawPriceTable struct {
	Version              int                      `yaml:"version"`
	Updated              time.Time                `yaml:"updated"`
	Models               map[string]rawModelPrice `yaml:"models"`
	ServerToolPerRequest map[string]float64       `yaml:"server_tool_per_request"`
}

// deref is *p, or 0 for nil.
func deref(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// PriceTable is the versioned price list of spec/config/v0's `prices` setting: a flat map from the
// exact `ssl_response.model` string to that model's per-million-token prices. P0 implements
// load-and-apply only; the richer override semantics of FEATURES E62 stay P2 (§11).
//
// The zero value and a nil *PriceTable price nothing, which is a supported state: cost estimates
// read 0 and no cost breach can fire (E15).
type PriceTable struct {
	Version int                   `yaml:"version"`
	Updated time.Time             `yaml:"updated"`
	Models  map[string]ModelPrice `yaml:"models"`
	// ServerToolPerRequest is the fee in USD for one server-side tool request, keyed by the name the response
	// reports its count under (usage.server_tool, e.g. web_search_requests), whatever the model. A response
	// that reports a positive count for a name this map leaves out is unpriced, as a model the table does not
	// name is (R2).
	ServerToolPerRequest map[string]float64 `yaml:"server_tool_per_request"`
	// Path is the file this table was read from, "" for one built in memory. It is diagnostic only.
	Path string `yaml:"-"`
}

// Warning is a price table this build declined to use, and why. It is not an error: the caller
// prints Message once and continues with no prices, and the run records Why as a gap (R32, E15).
type Warning struct {
	// Why is one of GapNoPriceTable or GapVersionMismatch: the gap event's `why`.
	Why string
	// Message is the one human line a CLI prints at startup.
	Message string
	// Missing is true when no table is installed (none configured, or no file at the path): the normal state of a
	// fresh machine, which a CLI reports only where a cost matters. A table that is there and unusable is not Missing.
	Missing bool
}

// Load reads and validates the price table at path.
//
// Errors wrap ErrPriceTable: an unreadable file, YAML that does not parse, a key the schema does not
// name (a misspelled price would otherwise read as $0; the error names the key and its line), a second YAML
// document or malformed trailing input, a negative
// price, or a version this binary does not know (R32). A model entry with no input_per_mtok or no
// output_per_mtok loads, and is unpriced (Cost); one with no cache_read_per_mtok or cache_write_per_mtok loads,
// and is unpriced for a response that reports that counter.Callers that must not fail over a price table use
// FromMachine, which turns every one of these into a Warning.
//
// Load reads path as it is; FromMachine, the one a run and compile use, applies the trust rule first.
func Load(path string) (*PriceTable, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrPriceTable, path, err)
	}
	return parse(path, b)
}

// loadTrusted is Load over config.ReadTrusted.
func loadTrusted(path string, uid int) (*PriceTable, error) {
	b, err := config.ReadTrusted(path, uid)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPriceTable, err)
	}
	return parse(path, b)
}

// parse decodes and validates the table read from path.
func parse(path string, b []byte) (*PriceTable, error) {
	var raw rawPriceTable
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %s: %w", ErrPriceTable, path, err)
	}
	// A second decode must reach EOF: even an empty later document is not part of this table.
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("expected exactly one YAML document")
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrPriceTable, path, err)
	}
	t := PriceTable{Version: raw.Version, Updated: raw.Updated, ServerToolPerRequest: raw.ServerToolPerRequest, Path: path}
	if raw.Models != nil {
		t.Models = make(map[string]ModelPrice, len(raw.Models))
	}
	for model, r := range raw.Models {
		t.Models[model] = ModelPrice{
			InputPerMTok: deref(r.InputPerMTok), OutputPerMTok: deref(r.OutputPerMTok),
			CacheReadPerMTok: deref(r.CacheReadPerMTok), CacheWritePerMTok: deref(r.CacheWritePerMTok),
			CacheWrite1hPerMTok: r.CacheWrite1hPerMTok,
			partial:             r.InputPerMTok == nil || r.OutputPerMTok == nil,
			noCacheRead:         r.CacheReadPerMTok == nil,
			noCacheWrite:        r.CacheWritePerMTok == nil,
		}
	}
	if t.Version != PriceVersion {
		return nil, fmt.Errorf("%w: %w", ErrPriceTable, &versionError{path: path, got: t.Version})
	}
	for model, p := range t.Models {
		prices := []float64{p.InputPerMTok, p.OutputPerMTok, p.CacheReadPerMTok, p.CacheWritePerMTok}
		if p.CacheWrite1hPerMTok != nil {
			prices = append(prices, *p.CacheWrite1hPerMTok)
		}
		for _, v := range prices {
			if !validPrice(v) {
				return nil, fmt.Errorf("%w: %s: model %q has a price that is not a non-negative number", ErrPriceTable, path, model)
			}
		}
	}
	for name, v := range t.ServerToolPerRequest {
		if !validPrice(v) {
			return nil, fmt.Errorf("%w: %s: server tool %q has a price that is not a non-negative number", ErrPriceTable, path, name)
		}
	}
	return &t, nil
}

// FromMachine loads the table named by the machine config's `prices` setting — the machine-config
// override of the built-in ~/.tego/prices.yaml, already home-expanded by config.Load. Unlike Load, it
// reads the file under the machine config's trust rule (config.ReadTrusted), wherever the setting puts it:
// whoever can rewrite the table can price every model at $0 and so turn every cost budget off
// (limits-check-doctor-cli.md §3).
//
// It never fails: a missing, unreadable, unparsable or wrong-version table, or one that lists no model,
// yields a nil table and a
// non-nil Warning the caller prints once and records as a gap (E15, R32). A nil table prices
// nothing, so tokens, wall, stall and repeats still hold; only cost does not.
func FromMachine(m *config.Machine) (*PriceTable, *Warning) {
	if m == nil || m.Prices.Value == "" {
		return nil, &Warning{Why: GapNoPriceTable, Message: "no price table configured; cost is not estimated", Missing: true}
	}
	uid, _ := config.InvokingUID()
	t, err := loadTrusted(m.Prices.Value, uid)
	switch {
	case err == nil && len(t.Models) == 0:
		// A table that lists no model prices nothing, as a missing one does: every response is unpriced and
		// MaxCost bounds none, so a cost_usd budget would pass them all at $0 and never trip. It reads as no
		// table, the same warning and gap, so a budget the contract declares is refused at launch (R32), never
		// run with a limit that silently does nothing.
		return nil, &Warning{Why: GapNoPriceTable,
			Message: fmt.Sprintf("the price table %s lists no models; cost is not estimated", t.Path)}
	case err == nil:
		return t, nil
	case errors.Is(err, fs.ErrNotExist):
		// The common case by far: no table has been installed yet. It reads as a missing file, not
		// as a failure, because nothing is wrong with the run.
		return nil, &Warning{Why: GapNoPriceTable,
			Message: fmt.Sprintf("no price table at %s; cost is not estimated", m.Prices.Value), Missing: true}
	}
	why := GapNoPriceTable
	var bad *versionError
	if errors.As(err, &bad) {
		why = GapVersionMismatch
	}
	return nil, &Warning{Why: why,
		Message: strings.TrimPrefix(err.Error(), "limits: ") + "; cost is not estimated"}
}

// versionError marks the one Load failure FromMachine reports as a version mismatch rather than an
// unreadable table (R32). It is returned inside the wrapped chain Load builds.
type versionError struct {
	path string
	got  int
}

// Error names the table and the version it declared.
func (e *versionError) Error() string {
	return fmt.Sprintf("%s: price table version %d, want %d", e.path, e.got, PriceVersion)
}

// validPrice reports whether v is a price: a finite number, not below 0.
func validPrice(v float64) bool { return v >= 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }

// Cost returns the estimated USD cost of one response's usage and whether it was priced (R2): Σ tokens/1e6 ×
// the matching per-million price of u.Model, cache reads and both kinds of cache write included, plus each
// server-tool request at its fee. A nil table, a model the table does not list or lists with no input or no
// output price, or a usage the model's entry
// has no price for (cache reads with no cache_read_per_mtok, 5-minute cache writes with no cache_write_per_mtok,
// 1-hour cache writes with no cache_write_1h_per_mtok, a server-tool count with no fee)
// costs 0 and reports false, as does a response billed under a modifier the table has no rate for (fast speed, a
// priority service tier, geo pinning, extra iterations: ledger.TokenUsage.Modified) — the caller records the unpriced-model gap and carries on, charging the
// response at MaxCost under a cost budget.
//
// Every surface that shows this number labels it "est." (GAPS.md C17).
func (t *PriceTable) Cost(u ledger.TokenUsage) (float64, bool) {
	if t == nil || len(t.Models) == 0 || u.Modified {
		return 0, false
	}
	p, ok := t.Models[u.Model]
	if !ok || p.partial {
		return 0, false
	}
	oneHour := min(u.CacheWrite1h, u.CacheWrite)
	if (u.CacheRead > 0 && p.noCacheRead) || (u.CacheWrite-oneHour > 0 && p.noCacheWrite) {
		return 0, false
	}
	var rate1h float64
	if oneHour > 0 {
		if p.CacheWrite1hPerMTok == nil {
			return 0, false
		}
		rate1h = *p.CacheWrite1hPerMTok
	}
	tools, ok := t.serverToolCost(u.ServerTool)
	if !ok {
		return 0, false
	}
	const perM = 1e6
	cost := float64(u.In)/perM*p.InputPerMTok +
		float64(u.Out)/perM*p.OutputPerMTok +
		float64(u.CacheRead)/perM*p.CacheReadPerMTok +
		float64(u.CacheWrite-oneHour)/perM*p.CacheWritePerMTok +
		float64(oneHour)/perM*rate1h +
		tools
	return cost, true
}

// serverToolCost is the fees of the server-tool requests counted, and false when one with a positive count has
// no fee in the table.
func (t *PriceTable) serverToolCost(counts map[string]int) (float64, bool) {
	var cost float64
	for name, n := range counts {
		if n <= 0 {
			continue
		}
		fee, ok := t.ServerToolPerRequest[name]
		if !ok {
			return 0, false
		}
		cost += float64(n) * fee
	}
	return cost, true
}

// PricesAnyModel reports that the table has an entry with both an input and an output price: without one every
// response is unpriced and MaxCost bounds nothing (R2).
func (t *PriceTable) PricesAnyModel() bool {
	if t == nil {
		return false
	}
	for _, p := range t.Models {
		if !p.partial {
			return true
		}
	}
	return false
}

// MaxCost is Cost at the table's highest price per counter, over every model it names: what a response the
// table does not price is charged toward a cost ceiling (R2). 1-hour cache writes are charged at
// the highest of every model's 1-hour and 5-minute cache-write prices (a cache price some complete entry
// lacks counts as the highest output rate, for reads and both writes), and a server-tool request at its own fee,
// or at the highest fee the table names when it names none for that tool (R2). It reports false for
// a table that prices nothing, where no cost ceiling can be enforced at all (E15), and for a usage reporting
// server-tool requests to a table that names no fee at all (UnfeedServerTool): nothing bounds what those cost,
// and $0 is no bound (ADR 0037 amendment 2026-09-24). Entries with no input or no output price take no part:
// a table of nothing else prices nothing.
func (t *PriceTable) MaxCost(u ledger.TokenUsage) (float64, bool) {
	if t == nil || len(t.Models) == 0 || t.UnfeedServerTool(u) {
		return 0, false
	}
	var top ModelPrice
	var top1h float64
	complete := false
	var missRead, missWrite, miss1h bool
	for _, p := range t.Models {
		if p.partial {
			continue
		}
		complete = true
		top.InputPerMTok = max(top.InputPerMTok, p.InputPerMTok)
		top.OutputPerMTok = max(top.OutputPerMTok, p.OutputPerMTok)
		top.CacheReadPerMTok = max(top.CacheReadPerMTok, p.CacheReadPerMTok)
		top.CacheWritePerMTok = max(top.CacheWritePerMTok, p.CacheWritePerMTok)
		missRead = missRead || p.noCacheRead
		missWrite = missWrite || p.noCacheWrite
		if p.CacheWrite1hPerMTok != nil {
			top1h = max(top1h, *p.CacheWrite1hPerMTok)
		} else {
			miss1h = true
		}
	}
	if !complete {
		return 0, false
	}
	// The bound is an upper bound, so a cache kind some complete entry does not price (that entry's
	// responses are unpriced and charged here) is charged at no less than the table's highest output rate,
	// the dearest rate per token it names (Anthropic prices cache reads at 0.1x input and writes at up to
	// 2x): another entry's cheaper cache price must not bound it. A kind no entry prices gets the same.
	if missRead || top.CacheReadPerMTok == 0 {
		top.CacheReadPerMTok = max(top.CacheReadPerMTok, top.OutputPerMTok)
	}
	if missWrite || top.CacheWritePerMTok == 0 {
		top.CacheWritePerMTok = max(top.CacheWritePerMTok, top.OutputPerMTok)
	}
	if miss1h {
		top1h = max(top1h, top.OutputPerMTok)
	}
	top1h = max(top1h, top.CacheWritePerMTok)
	var topFee, tools float64
	for _, fee := range t.ServerToolPerRequest {
		topFee = max(topFee, fee)
	}
	for name, n := range u.ServerTool {
		if n <= 0 {
			continue
		}
		fee, ok := t.ServerToolPerRequest[name]
		if !ok {
			fee = topFee
		}
		tools += float64(n) * fee
	}
	oneHour := min(u.CacheWrite1h, u.CacheWrite)
	const perM = 1e6
	total := float64(u.In)/perM*top.InputPerMTok +
		float64(u.Out)/perM*top.OutputPerMTok +
		float64(u.CacheRead)/perM*top.CacheReadPerMTok +
		float64(u.CacheWrite-oneHour)/perM*top.CacheWritePerMTok +
		float64(oneHour)/perM*top1h +
		tools
	if u.Modified {
		total *= modifiedFactor
	}
	return total, true
}

// modifiedFactor is what MaxCost multiplies a response billed under a modifier by (ledger.TokenUsage.Modified):
// the dearest premium the Messages API documents on a modifier, fast mode at twice the standard rate. Extra
// iterations (compaction, a refusal fallback) are not bounded by it; derive reports those exchanges unmetered
// because their attempts are not in the counts, and a token or cost budget fails closed.
const modifiedFactor = 2

// UnfeedServerTool reports that u counts server-tool requests (web searches, code executions) while the table,
// which prices models, names no server_tool_per_request fee at all: their cost has no bound in the table, so a
// cost budget cannot see it. The budget watcher treats such a response as unmetered (ADR 0037 amendment
// 2026-09-24), and `tego compile` warns about the table beforehand.
func (t *PriceTable) UnfeedServerTool(u ledger.TokenUsage) bool {
	if t == nil || len(t.Models) == 0 || len(t.ServerToolPerRequest) > 0 {
		return false
	}
	for _, n := range u.ServerTool {
		if n > 0 {
			return true
		}
	}
	return false
}
