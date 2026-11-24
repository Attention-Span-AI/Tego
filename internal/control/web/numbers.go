// SPDX-License-Identifier: Apache-2.0

package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// Inventory definitions name a quantity's source and incomplete forms. The helpers
// refuse unknown IDs; delivered-markup tests also catch direct unmarked text,
// shown/spoken attributes, zero forms and stale per-element exclusions. Ordinary
// reader-error counts hide their prefix; known actionable waiting requests use
// the same lower-bound state as the badge, document title and page sentence.

//go:embed inventory/number_inventory.json
var numberInventory embed.FS

// numberDefinition is one inventory row. Scope "row" marks a number qualified by the run of the row it sits in
// rather than by the page.
type numberDefinition struct {
	Page, ID, Label, Source, Incomplete, Scope string
}

// The sources a number can come from, and so the countScopes field that qualifies it.
var numberSources = map[string]bool{
	"exact":      true, // configuration, a list the page shows whole, or a complete streamed aggregate
	"candidates": true, // eligible runs, including remembered missing records: omission does not bound this total
	"status":     true, // status-derived groups require decoded metadata and running status
	"live":       true, // running status, independently of readable records
	"selection":  true, // a run filter’s matching set
	"remaining":  true, // the run page’s non-running remainder
	"runs":       true, // the list of runs: complete unless runs were omitted or one could not be listed
	"aggregate":  true, // full-run counters over decoded records
	"metadata":   true, // category absence requires decoded run facts, not just known directory presence
	"window":     true, // the retained event windows
	"unanswered": true, // historical unanswered identities; no action remains on a lost run
	"pending":    true, // one run's waiting requests
	"queue":      true, // every run's waiting requests
	"history":    true, // answers from the retained windows, newest first, capped
	"vault":      true, // credential uses in the newest runs
	"mcp":        true, // one run's MCP tool counts
	"daily":      true, // the complete per-day refusal aggregate
	"receipt":    true, // the Receipt's complete streamed record, bounded by its own identity lists and capture
}

// layerNumbers are inventory rows a layer kept out of some builds registers from its own init, as the vault seam
// requires (vault.go): the layer's numbers exist exactly when its pages do.
var layerNumbers []numberDefinition

var numberDefinitions = sync.OnceValues(func() (map[string]numberDefinition, error) {
	b, err := numberInventory.ReadFile("inventory/number_inventory.json")
	if err != nil {
		return nil, err
	}
	var inventory struct{ Rows []numberDefinition }
	if err := json.Unmarshal(b, &inventory); err != nil {
		return nil, fmt.Errorf("number inventory: %w", err)
	}
	rows := append(inventory.Rows, layerNumbers...)
	out := make(map[string]numberDefinition, len(rows))
	for _, row := range rows {
		if _, ok := out[row.ID]; ok {
			return nil, fmt.Errorf("number inventory: duplicate number %s", row.ID)
		}
		if !numberSources[row.Source] {
			return nil, fmt.Errorf("number inventory: unknown source %q for %s", row.Source, row.ID)
		}
		if row.Page == "" || row.Label == "" || row.Incomplete == "" {
			return nil, fmt.Errorf("number inventory: %s lacks its page, label or incomplete form", row.ID)
		}
		if row.Scope != "" && row.Scope != "row" {
			return nil, fmt.Errorf("number inventory: unknown scope %q for %s", row.Scope, row.ID)
		}
		out[row.ID] = row
	}
	return out, nil
})

// countScope is one source's completeness for this page.
type countScope struct {
	// Lower marks numbers from this source as lower bounds; Reason says why, in one plain sentence.
	Lower  bool
	Reason string
	// Error is why the source could not be read. Ordinary counts hide their prefix.
	// Known actionable waiting requests remain a lower bound, through waitingOf.
	Error string
}

// incomplete reports whether a number from this scope is anything but exact.
func (s countScope) incomplete() bool { return s.Lower || s.Error != "" }

// worse returns the scope that qualifies more: an error over a lower bound over an exact one.
func worse(a, b countScope) countScope {
	switch {
	case a.Error != "":
		return a
	case b.Error != "":
		return b
	case a.Lower:
		return a
	default:
		return b
	}
}

// bannerReasons are the count reasons a page's banner already states (chromeOf, the run page): the coverage note
// leaves them out and keeps its links.
var bannerReasons = map[string]string{"window": reasonWindow, "omitted": reasonOmitted, "queue": reasonQueueCut}

// countLink is one way to the complete record.
type countLink struct{ Label, URL string }

// maxCountLinks bounds the recovery links a page lists; past it, the last link is All runs.
const maxCountLinks = 3

// countScopes is every source's completeness on one page, and the links to the complete records.
type countScopes struct {
	Runs, Live, Selection, Rest, Aggregate, Window, Pending, Queue, History, Vault, MCP, Daily, Receipt countScope
	Links                                                                                               []countLink
}

// addLink adds a recovery link once, keeping at most maxCountLinks and ending in All runs past that.
func (n *countScopes) addLink(l countLink) {
	for _, have := range n.Links {
		if have.URL == l.URL {
			return
		}
	}
	switch {
	case len(n.Links) < maxCountLinks-1:
		n.Links = append(n.Links, l)
	case len(n.Links) == maxCountLinks-1:
		n.Links = append(n.Links, countLink{Label: "All runs", URL: "/runs"})
	}
}

const (
	reasonWindow   = "Retained event windows leave out older events."
	reasonOmitted  = "Some runs are omitted from this snapshot."
	reasonBadLines = "Some record lines could not be read: malformed or unsupported records."
	reasonQueueCut = "The waiting list is too long to show."
)

// runNumbers is one run's completeness: its windows, its waiting list, its unreadable lines.
func runNumbers(r *ledgerview.Run) countScopes {
	var n countScopes
	if r == nil {
		return n
	}
	if r.Cut {
		n.Window = countScope{Lower: true, Reason: reasonWindow}
	}
	if r.PendingCut {
		n.Pending = countScope{Lower: true, Reason: reasonQueueCut}
	}
	// A malformed line is skipped and every other line still counts, so it can only hide events: the counts are
	// lower bounds. Ordinary reader-error counts hide their prefix; known actionable
	// waiting requests keep the lower-bound representation required by waitingOf.
	var damaged countScope
	switch {
	case r.ReadError != "":
		damaged = countScope{Error: r.ReadError}
	case r.Bad > 0:
		damaged = countScope{Lower: true, Reason: reasonBadLines}
	}
	if damaged.incomplete() {
		n.Aggregate, n.Window = damaged, worse(damaged, n.Window)

		n.Pending = worse(damaged, n.Pending)
	}
	if r.Live {
		n.Queue = n.Pending
	}
	if r.LiveError != "" && !r.Ended {
		n.Live = countScope{Error: r.LiveError}
		n.Queue = worse(n.Queue, n.Live)
	}
	n.Selection, n.Rest = n.Aggregate, worse(n.Aggregate, n.Live)
	n.History = n.Window
	n.Daily = n.Aggregate
	if n.Window.incomplete() || n.Aggregate.incomplete() || n.Pending.incomplete() || n.Live.incomplete() {
		name := r.Agent
		if name == "" {
			name = shortRun(r.ID)
		}
		n.addLink(countLink{Label: "Complete record of " + name, URL: "/logs.jsonl?run=" + r.ID})
	}
	return n
}

// snapshotNumbers is a whole snapshot's completeness: omitted runs, partial reads and every run's own.
func snapshotNumbers(snap *ledgerview.Snapshot) countScopes {
	var n countScopes
	if snap == nil {
		return n
	}
	if snap.RunsCut || snap.Partial {
		omitted := countScope{Lower: true, Reason: reasonOmitted}
		n.Runs, n.Aggregate, n.Window, n.Pending = omitted, omitted, omitted, omitted
	}
	if snap.LinesCut {
		n.Window = worse(n.Window, countScope{Lower: true, Reason: reasonWindow})
	}
	for _, r := range snap.Runs {
		rn := runNumbers(r)
		n.Aggregate = worse(n.Aggregate, rn.Aggregate)
		n.Window = worse(n.Window, rn.Window)
		n.Pending = worse(n.Pending, rn.Queue)
		for _, l := range rn.Links {
			n.addLink(l)
		}
	}
	if snap.ReadError != "" && !snap.ReadErrorListed {
		// A run that could not be listed hides its counts and its very presence.
		bad := countScope{Error: snap.ReadError}
		n.Runs, n.Aggregate, n.Window, n.Pending = bad, bad, bad, bad
	}
	n.Live = n.Runs
	if snap.LiveError != "" {
		n.Live = worse(n.Live, countScope{Error: snap.LiveError})
	}
	n.Queue = n.Pending
	if snap.LiveError != "" {
		n.Queue = worse(n.Queue, countScope{Error: snap.LiveError})
	}
	n.Selection, n.Rest = n.Aggregate, worse(n.Aggregate, n.Live)
	n.History = n.Window
	n.Daily = n.Aggregate
	if n.Runs.incomplete() || n.Live.incomplete() || n.Aggregate.incomplete() || n.Window.incomplete() || n.Pending.incomplete() {
		n.addLink(countLink{Label: "All runs", URL: "/runs"})
	}
	return n
}

// equal reports whether two pages' completeness is the same.
func (n countScopes) equal(o countScopes) bool {
	return n.Runs == o.Runs && n.Live == o.Live && n.Selection == o.Selection && n.Rest == o.Rest && n.Aggregate == o.Aggregate && n.Window == o.Window && n.Pending == o.Pending &&
		n.Queue == o.Queue && n.History == o.History && n.Vault == o.Vault && n.MCP == o.MCP && n.Daily == o.Daily &&
		n.Receipt == o.Receipt && slices.Equal(n.Links, o.Links)
}

// scope is the completeness of one inventory source.
func (n countScopes) scope(source string) countScope {
	switch source {
	case "candidates":
		return countScope{Error: n.Runs.Error}
	case "runs":
		return n.Runs
	case "live":
		return n.Live
	case "status":
		return worse(n.Aggregate, n.Live)
	case "selection":
		return worse(n.Aggregate, n.Selection)
	case "remaining":
		return worse(n.Aggregate, n.Rest)
	case "aggregate", "metadata":
		return n.Aggregate
	case "window":
		return n.Window
	case "pending", "unanswered":
		return n.Pending
	case "queue":
		return n.Queue
	case "history":
		return n.History
	case "vault":
		return n.Vault
	case "mcp":
		return n.MCP
	case "daily":
		return n.Daily
	case "receipt":
		return n.Receipt
	}
	return countScope{}
}

// Notes is each reason once, for the page's coverage note beside its links to the complete records.
func (n countScopes) Notes() []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range []countScope{n.Runs, n.Live, n.Selection, n.Rest, n.Aggregate, n.Window, n.Pending, n.Queue, n.History, n.Vault, n.MCP, n.Daily, n.Receipt} {
		words := s.Reason
		if s.Error != "" {
			words = "Could not read: " + s.Error
		}
		if words != "" && !seen[words] {
			out = append(out, words)
			seen[words] = true
		}
	}
	return out
}

// quantity is one rendered number: its inventory id, its words, and the reason when they are not exact.
type quantity struct {
	ID, Text, Reason string
	// Short is a compact lower bound or an unknown mark. Waiting requests use waitingOf.
	Short string
}

// groupDigits writes an unsigned decimal with thousands separators, as countWord does.
func groupDigits(s string) string {
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// numberWord formats any integer a template passes.
func numberWord(n any) (string, error) {
	switch v := n.(type) {
	case int:
		return countWord(v), nil
	case int64:
		return countWord(int(v)), nil
	case int32:
		return countWord(int(v)), nil
	case uint64:
		return groupDigits(strconv.FormatUint(v, 10)), nil
	case uint32:
		return groupDigits(strconv.FormatUint(uint64(v), 10)), nil
	case uint:
		return groupDigits(strconv.FormatUint(uint64(v), 10)), nil
	}
	return "", fmt.Errorf("number of type %T", n)
}

// quantityOf qualifies n by the completeness of its inventory source on this page.
func quantityOf(id string, n any, scopes countScopes) (quantity, error) {
	defs, err := numberDefinitions()
	if err != nil {
		return quantity{}, err
	}
	def, ok := defs[id]
	if !ok {
		return quantity{}, fmt.Errorf("number %q is missing from the number inventory", id)
	}
	words, err := numberWord(n)
	if err != nil {
		return quantity{}, fmt.Errorf("number %q: %w", id, err)
	}
	s := scopes.scope(def.Source)
	q := quantity{ID: id, Text: words, Short: words, Reason: s.Reason}
	if def.Source == "queue" || def.Source == "pending" {
		count, err := strconv.Atoi(strings.ReplaceAll(words, ",", ""))
		if err != nil {
			return quantity{}, err
		}
		w := waitingOf(count, s)
		return quantity{ID: id, Text: w.Count, Short: w.Short, Reason: w.Reason}, nil
	}
	switch {
	case s.Error != "":
		q.Text, q.Short, q.Reason = "could not read", "?", "Could not read: "+s.Error
	case s.Lower:
		q.Text, q.Short = "at least "+words, words+"+"
	}
	return q, nil
}

// quantityText is quantityOf's words alone, for attributes and titles.
func quantityText(id string, n any, scopes countScopes) (string, error) {
	q, err := quantityOf(id, n, scopes)
	return q.Text, err
}

// emptyRulesWords distinguishes a known empty result from unavailable declarations.
func emptyRulesWords(unknown, noContract bool) string {
	if noContract {
		return "The run named no rule; its contract entries are not known without a contract copy."
	}
	if unknown {
		return "No rule is listed here; declared entries are not known."
	}
	return "The run named no rule and its contract declares no entry."
}

// quantityWords registers a formatted quantity (a duration, a token total, a sentence that carries counts) under
// its inventory id, keeping its source's qualification.
func quantityWords(id, words string, scopes countScopes) (quantity, error) {
	q, err := quantityOf(id, 0, scopes)
	if err != nil {
		return quantity{}, err
	}
	switch q.Text {
	case "could not read":
	case "at least 0":
		q.Text = "at least " + words
	default:
		q.Text = words
	}
	q.Short = q.Text
	return q, nil
}

// quantityRecordWords scopes a mixed record sentence, including zero clauses,
// without treating digits in an address or an identity as aggregate counts.
func quantityRecordWords(id, words string, n countScopes) (quantity, error) {
	q, err := quantityWords(id, words, n)
	if err == nil && q.Reason != "" && q.Text != "could not read" {
		q.Text = "Only what was seen in what is retained: " + words
		q.Short = q.Text
	}
	return q, err
}

// numberedValue carries a page's countScopes into a sub-template whose dot is something else.
type numberedValue struct {
	Value   any
	Numbers countScopes
}

func withNumbers(v any, n countScopes) numberedValue { return numberedValue{v, n} }

func numberValue(v any) any {
	if x, ok := v.(numberedValue); ok {
		return x.Value
	}
	return v
}

func numbersOf(v any) (countScopes, error) {
	if x, ok := v.(numberedValue); ok {
		return x.Numbers, nil
	}
	return countScopes{}, fmt.Errorf("numbers scope is required for %T", v)
}

// scopedChip keeps a run row's secrets chip honest: a count from incomplete windows is a lower bound, and a run
// whose record could not be read says so, even when an earlier verdict for it is cached.
func scopedChip(c chipText, n countScopes) chipText {
	s := n.Window
	if s.Error != "" {
		return chipText{Class: "b-neutral", Icon: "i-eye", Text: "could not read", Title: s.Error}
	}
	if s.Lower {
		if c.Text == "" {
			c.Text = "not fully known"
		} else if c.Text[0] >= '0' && c.Text[0] <= '9' {
			c.Text = "at least " + c.Text
		}
		c.Title = joinSentence(c.Title, s.Reason)
	}
	return c
}

// joinSentence appends a sentence to a title that may be empty.
func joinSentence(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}

func init() {
	funcs["emptyRulesWords"] = emptyRulesWords
	funcs["quantity"] = quantityOf
	funcs["quantityText"] = quantityText
	funcs["quantityWords"] = quantityWords
	funcs["quantityRecordWords"] = quantityRecordWords
	funcs["runNumbers"] = runNumbers
	funcs["withNumbers"] = withNumbers
	funcs["numberValue"] = numberValue
	funcs["numbersOf"] = numbersOf
	funcs["exactNumbers"] = func() countScopes { return countScopes{} }
	funcs["scopedChip"] = scopedChip
}
