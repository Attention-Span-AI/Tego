// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/mcptools"
	"golang.org/x/net/html"
)

// The number inventory (inventory/number_inventory.json, numbers.go) is the rule's record: every number a page
// shows, its page, label and source, and what it shows when that source is incomplete. These tests walk it three
// ways: the source text names only inventory ids, and pins only exact ones as exact; every row renders its
// qualified form in every incomplete mode; and real pages carry no number outside a marker, each marker in the
// inventory and in the form its source's completeness calls for.

// numberCallSites are the template and Go call sites that name a number: quantity, quantityText and quantityWords
// calls, and literal data-number markers.
var (
	numberCall    = regexp.MustCompile(`(?:quantity|quantityText|quantityWords|quantityRecordWords|quantityZero)\s*\(?\s*"([a-z0-9.-]+)"`)
	numberLiteral = regexp.MustCompile(`data-number(?:-(?:title|aria-label|aria-description|aria-valuenow|aria-valuetext|alt|placeholder|value|min|max|low|high|optimum|data-late))?="([a-z0-9.-]+)"`)
	numberNamedGo = regexp.MustCompile(`"((?:overview|runs|run|logs|detections|hours|approvals|vault|mcp|contracts|shared|event|investigate|editor|compare|machine|glossary|severity|routes)\.[a-z0-9-]+)"`)
)

// TestNumberInventoryMatchesTheSource: every id a template or Go file names is in the inventory, every inventory row
// is named somewhere, and a call site that pins a number as exact (exactNumbers) names a row whose source is exact.
// Templates are read from the embedded assets the server renders, Go files from the package directory.
func TestNumberInventoryMatchesTheSource(t *testing.T) {
	defs, err := numberDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	tmpls, err := fs.Glob(assets, "templates/*.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range tmpls {
		b, err := fs.ReadFile(assets, f)
		if err != nil {
			t.Fatal(err)
		}
		sources[f] = string(b)
	}
	goFiles, _ := filepath.Glob("*.go")
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sources[f] = string(b)
	}
	for _, problem := range numberSourceProblems(defs, sources) {
		t.Error(problem)
	}
}

// numberSourceProblems checks the call sites in sources (file name to text) against the inventory.
func numberSourceProblems(defs map[string]numberDefinition, sources map[string]string) []string {
	var out []string
	named := map[string]bool{}
	for _, f := range slices.Sorted(maps.Keys(sources)) {
		src := sources[f]
		for _, at := range numberCall.FindAllStringSubmatchIndex(src, -1) {
			id := src[at[2]:at[3]]
			named[id] = true
			def, ok := defs[id]
			if !ok {
				out = append(out, fmt.Sprintf("%s names number %q, which the inventory lacks", f, id))
				continue
			}
			if strings.Contains(callArgs(src, at[1]), "exactNumbers") && def.Source != "exact" {
				out = append(out, fmt.Sprintf("%s pins %s as exact, but its source is %s", f, id, def.Source))
			}
		}
		for _, m := range numberLiteral.FindAllStringSubmatch(src, -1) {
			named[m[1]] = true
			if _, ok := defs[m[1]]; !ok {
				out = append(out, fmt.Sprintf("%s marks number %q, which the inventory lacks", f, m[1]))
			}
		}
		if strings.HasSuffix(f, ".go") {
			for _, m := range numberNamedGo.FindAllStringSubmatch(src, -1) {
				if _, ok := defs[m[1]]; ok {
					named[m[1]] = true
				}
			}
		}
	}
	var stale []string
	for id := range defs {
		if !named[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		out = append(out, fmt.Sprintf("inventory rows no page names: %v", stale))
	}
	return out
}

// callArgs is the rest of a call's arguments from i: up to the parenthesis that closes the call, or the end of the
// template action.
func callArgs(src string, i int) string {
	depth := 0
	for j := i; j < len(src); j++ {
		switch {
		case src[j] == '(':
			depth++
		case src[j] == ')':
			if depth == 0 {
				return src[i:j]
			}
			depth--
		case strings.HasPrefix(src[j:], "}}"):
			return src[i:j]
		}
	}
	return src[i:]
}

// TestNumberSourceProblemsAreFound: the source check reports a number missing from the inventory, a number of an
// incomplete-able source pinned as exact, and an inventory row no page names.
func TestNumberSourceProblemsAreFound(t *testing.T) {
	defs := map[string]numberDefinition{
		"runs.all":   {ID: "runs.all", Source: "runs"},
		"runs.stale": {ID: "runs.stale", Source: "exact"},
	}
	got := numberSourceProblems(defs, map[string]string{
		"templates/x.tmpl": `{{template "quantity" (quantity "runs.all" (index .Count "all") exactNumbers)}}{{quantityText "runs.new" .N $.Numbers}}`,
	})
	want := []string{"pins runs.all as exact", `names number "runs.new"`, "rows no page names: [runs.stale]"}
	if len(got) != len(want) {
		t.Fatalf("problems %q, want %d", got, len(want))
	}
	for i := range want {
		if !strings.Contains(got[i], want[i]) {
			t.Errorf("problem %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// numberMode is one completeness state of a ledger, as the read model reports it.
type numberMode struct {
	name string
	snap func() *ledgerview.Snapshot
	// vault and mcp are what the Vault and MCP services report in this mode (vaultact, mcpact).
	vault, mcp countScope
	// history is set when the answer history reached its limit.
	historyCut bool
}

func numberModes() []numberMode {
	run := func(r ledgerview.Run) func() *ledgerview.Snapshot {
		return func() *ledgerview.Snapshot {
			r.ID = cleanRun
			return &ledgerview.Snapshot{Runs: []*ledgerview.Run{&r}}
		}
	}
	lower := countScope{Lower: true, Reason: "lower"}
	failed := countScope{Error: "permission denied"}
	return []numberMode{
		{name: "complete", snap: run(ledgerview.Run{})},
		{name: "live index missing", snap: func() *ledgerview.Snapshot {
			return &ledgerview.Snapshot{LiveError: "live index missing", Runs: []*ledgerview.Run{{ID: cleanRun}}}
		}},
		{name: "truncated", snap: run(ledgerview.Run{Cut: true}), vault: lower},
		{name: "evicted", snap: func() *ledgerview.Snapshot {
			return &ledgerview.Snapshot{LinesCut: true, Runs: []*ledgerview.Run{{ID: cleanRun, Cut: true}}}
		}, vault: lower},
		{name: "runs omitted", snap: func() *ledgerview.Snapshot {
			return &ledgerview.Snapshot{RunsCut: true, Runs: []*ledgerview.Run{{ID: cleanRun}}}
		}, vault: lower},
		{name: "history limit", snap: run(ledgerview.Run{}), historyCut: true},
		{name: "malformed line", snap: run(ledgerview.Run{Bad: 1}), vault: lower},
		{name: "malformed line, running", snap: run(ledgerview.Run{Bad: 1, Live: true}), vault: lower},
		{name: "reader failed", snap: run(ledgerview.Run{ReadError: "permission denied"}), vault: failed, mcp: failed},
		{name: "run not listed", snap: func() *ledgerview.Snapshot {
			return &ledgerview.Snapshot{ReadError: "read run r-x: events.jsonl is not a regular file", Runs: []*ledgerview.Run{{ID: cleanRun}}}
		}, vault: failed},
		{name: "waiting list cut", snap: run(ledgerview.Run{Live: true, PendingCut: true})},
	}
}

// wantForm is the form a number from source takes in mode, decided here from the rule, not from numbers.go: "exact",
// "at least" or "could not read".
func wantForm(mode, source string) string {
	if mode == "live index missing" {
		if source == "queue" {
			return "at least"
		} // this helper is supplied a known positive count
		if source == "live" || source == "status" || source == "remaining" {
			return "could not read"
		}
		return "exact"
	}
	if source == "live" {
		source = "runs"
	}
	if source == "metadata" || source == "status" || source == "selection" || source == "remaining" {
		source = "aggregate"
	}
	if (source == "queue" || source == "pending") && mode == "run not listed" {
		return "at least"
	}
	if source == "pending" && mode == "reader failed" {
		return "at least"
	}
	if source == "exact" {
		return "exact"
	}
	lowers := map[string][]string{
		"truncated":               {"window", "history", "vault"},
		"evicted":                 {"window", "history", "vault"},
		"runs omitted":            {"runs", "aggregate", "window", "pending", "unanswered", "queue", "history", "daily", "vault"},
		"history limit":           {"history"},
		"malformed line":          {"aggregate", "window", "pending", "unanswered", "history", "daily", "vault"},
		"malformed line, running": {"aggregate", "window", "pending", "unanswered", "queue", "history", "daily", "vault"},
		"waiting list cut":        {"pending", "unanswered", "queue"},
	}
	errors := map[string][]string{
		"reader failed":  {"aggregate", "window", "unanswered", "history", "daily", "vault", "mcp"},
		"run not listed": {"candidates", "runs", "aggregate", "window", "pending", "unanswered", "queue", "history", "daily", "vault"},
	}
	switch {
	case slices.Contains(errors[mode], source):
		return "could not read"
	case slices.Contains(lowers[mode], source):
		return "at least"
	}
	return "exact"
}

// TestNumberInventoryQualifiesEverySource renders every inventory row through the "quantity" template in every
// completeness mode and checks its words: exact, "at least N" with a reason, or "could not read" with the reason.
func TestNumberInventoryQualifiesEverySource(t *testing.T) {
	defs, err := numberDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	ids := slices.Sorted(func(yield func(string) bool) {
		for id := range defs {
			if !yield(id) {
				return
			}
		}
	})
	for _, mode := range numberModes() {
		t.Run(mode.name, func(t *testing.T) {
			snap := mode.snap()
			scopes := snapshotNumbers(snap)
			if snap.Runs[0].Live || snap.Runs[0].Cut || snap.Runs[0].Bad > 0 || snap.Runs[0].ReadError != "" {
				// A run page qualifies "pending" by its own run.
				scopes.Pending = runNumbers(snap.Runs[0]).Pending
			}
			scopes.Vault, scopes.MCP = mode.vault, mode.mcp
			if mode.historyCut {
				scopes.History = worse(scopes.History, countScope{Lower: true, Reason: "Answer history shows only the newest 200 answers."})
			}
			for _, id := range ids {
				def := defs[id]
				q, err := quantityOf(id, 7, scopes)
				if err != nil {
					t.Fatal(err)
				}
				var b bytes.Buffer
				if err := pages["overview"].ExecuteTemplate(&b, "quantity", q); err != nil {
					t.Fatal(err)
				}
				got := numberMarkers(t, b.String())[id]
				want := map[string]string{"exact": "7", "at least": "at least 7", "could not read": "could not read"}[wantForm(mode.name, def.Source)]
				if len(got) != 1 || got[0] != want {
					t.Errorf("%s (source %s): %v, want %q", id, def.Source, got, want)
				}
				if want != "7" && q.Reason == "" {
					t.Errorf("%s: a qualified number has no reason", id)
				}
				if want == "7" && q.Reason != "" {
					t.Errorf("%s: an exact number carries a reason %q", id, q.Reason)
				}
			}
		})
	}
	if _, err := quantityOf("runs.uninventoried-new-number", 1, countScopes{}); err == nil {
		t.Error("a number missing from the inventory rendered")
	}
}

// numberMarkers is each marker's words on a page, by inventory id.
func numberMarkers(t *testing.T, body string) map[string][]string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(inventoryDocument(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	walk(doc, func(n *html.Node) {
		if id, ok := attr(n, "data-number"); ok {
			out[id] = append(out[id], strings.Join(strings.Fields(markerWords(n)), " "))
		}
	})
	return out
}

// marker is one rendered number: its id, words, reason (title), and the run of the row it sits in.
type marker struct{ id, words, reason, run string }

// markersIn is every marker on a page with its row's run, from the nearest data-k that names a fixture run.
func markersIn(t *testing.T, body string) []marker {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(inventoryDocument(body)))
	if err != nil {
		t.Fatal(err)
	}
	var out []marker
	walk(doc, func(n *html.Node) {
		for _, a := range n.Attr {
			if strings.HasPrefix(a.Key, "data-number-") && !strings.HasPrefix(a.Key, "data-number-exclude") {
				words, _ := attr(n, strings.TrimPrefix(a.Key, "data-number-"))
				if !quantityVocabulary.MatchString(words) && !strings.Contains(words, "could not read") && !strings.Contains(words, "could not tell") {
					continue
				}
				reason, _ := attr(n, "title")
				for _, id := range strings.Fields(a.Val) {
					out = append(out, marker{id: id, words: words, reason: reason, run: inventoryRunOf(n)})
				}
			}
		}
		id, ok := attr(n, "data-number")
		if !ok {
			return
		}
		m := marker{id: id, words: strings.Join(strings.Fields(markerWords(n)), " ")}
		m.reason, _ = attr(n, "title")
		for p := n; p != nil && m.run == ""; p = p.Parent {
			k, _ := attr(p, "data-k")
			for _, r := range []string{numRichRun, harmRun, cleanRun} {
				if strings.HasPrefix(k, r) {
					m.run = r
				}
			}
		}
		out = append(out, m)
	})
	reasons := map[string]string{}
	for i := range out {
		m := &out[i]
		if (strings.Contains(m.words, "not fully known:") || strings.Contains(m.words, "could not be read:")) && strings.Contains(m.words, ": ") {
			_, m.reason, _ = strings.Cut(m.words, ": ")
		}
		if m.reason != "" {
			reasons[m.id+"/"+m.run] = m.reason
		}
	}
	for i := range out {
		m := &out[i]
		if m.reason == "" {
			m.reason = reasons[m.id+"/"+m.run]
		}
	}

	return out
}

// markerWords is a marker's text, including hidden screen-reader words.
func markerWords(n *html.Node) string {
	var b strings.Builder
	var rec func(*html.Node)
	rec = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rec(c)
		}
	}
	rec(n)
	return b.String()
}

// standaloneNumber is a word that is a number on its own: "12", "1,204", "×3", "(2)", "3+".

// numberExclusions names individual template elements, each with a recorded reason.
// Styling is never evidence that a quantity is not a count.
type numberExclusion struct{ ID, Element, Reason string }

// Private layers register only the exclusions for the elements they build.
var layerNumberExclusions []numberExclusion

func numberExclusions(t *testing.T) map[string]string {
	t.Helper()
	b, err := numberInventory.ReadFile("inventory/number_inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct{ Exclusions []numberExclusion }
	if err := json.Unmarshal(b, &inventory); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, x := range append(inventory.Exclusions, layerNumberExclusions...) {
		if x.ID == "" || x.Element == "" || x.Reason == "" || out[x.ID] != "" {
			t.Fatalf("invalid exclusion: %+v", x)
		}
		out[x.ID] = x.Reason
	}
	return out
}

var zeroForm = regexp.MustCompile(`(?i)\b(no (?:[a-z]|$)|no$|never asked\b|nowhere\b|not seen\b|none\b|nothing\b|your first run will appear|waiting list incomplete)`)
var numberToken = regexp.MustCompile(`[0-9]`)

// unmarkedNumbers reads text and every shown or spoken attribute, including title.
// Only non-content scripts/styles and hidden form inputs are outside the audience.
func unmarkedNumbers(t *testing.T, body string) []string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(inventoryDocument(body)))
	if err != nil {
		t.Fatal(err)
	}
	exclusions := numberExclusions(t)
	var out []string
	var rec func(*html.Node, bool)
	check := func(n *html.Node, field, words string, marked bool) {
		if !marked && (numberToken.MatchString(words) || zeroForm.MatchString(words)) {
			attrs := ""
			for _, key := range []string{"class", "id", "href"} {
				if value, ok := attr(n, key); ok {
					attrs += fmt.Sprintf(" %s=%q", key, value)
				}
			}
			out = append(out, fmt.Sprintf("<%s%s> %s %q", n.Data, attrs, field, strings.Join(strings.Fields(words), " ")))
		}
	}
	rec = func(n *html.Node, marked bool) {
		textExcluded := false
		attributeExcluded := false
		if n.Type == html.ElementNode {
			if n.Data == "script" || n.Data == "style" {
				return
			}
			if ty, _ := attr(n, "type"); n.Data == "input" && ty == "hidden" {
				return
			}
			if id, ok := attr(n, "data-number-exclude-text"); ok {
				if exclusions[id] == "" {
					out = append(out, "unknown exclusion "+id)
				} else {
					textExcluded = true
				}
			}
			if id, ok := attr(n, "data-number-exclude"); ok {
				if exclusions[id] == "" {
					out = append(out, "unknown exclusion "+id)
				} else {
					textExcluded = true
					attributeExcluded = true
				}
			}
			if _, ok := attr(n, "data-number"); ok {
				marked = true
			}
			for _, a := range n.Attr {
				ty, _ := attr(n, "type")
				shown := shownQuantityAttribute(n.Data, ty, a.Key)
				if !shown {
					continue
				}
				_, own := attr(n, "data-number-"+a.Key)
				if ex, ok := attr(n, "data-number-exclude-"+a.Key); ok {
					if exclusions[ex] == "" {
						out = append(out, "unknown exclusion "+ex)
					} else {
						own = true
					}
				}
				check(n, a.Key, a.Val, marked || own || attributeExcluded)
			}
		}
		if n.Type == html.TextNode && n.Parent != nil {
			check(n.Parent, "text", n.Data, marked)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if textExcluded && c.Type == html.TextNode {
				continue
			}
			rec(c, marked)
		}
	}
	rec(doc, false)
	return out
}

// TestUnmarkedNumbersAreFound: the page walk finds a number outside a marker wherever it sits in a sentence, and
// leaves clock times, identifiers and marked numbers alone.
func TestUnmarkedNumbersAreFound(t *testing.T) {
	page := `<p>of 12 runs</p><p>3 refused</p><p>(2) waiting</p><p><span data-number="runs.all">12</span> runs</p>`
	got := unmarkedNumbers(t, page)
	if len(got) != 3 {
		t.Errorf("unmarked numbers: %v", got)
	}
}

// Rich ledger for the rendered-page walk.
const (
	numRichRun   = "r-aaaaaaaa-0000000000005-richxx"
	numUnlisted  = "r-aaaaaaaa-0000000000099-unlist"
	numRichAgent = "Counter12"
)

// numberLedger is the MCP fixture (a live run with a waiting request and MCP tools seen) plus an ended run with
// refusals, programs, connections, file writes, answered requests, secret reads and routine lines, and a contract.
func numberLedger(t *testing.T) string {
	t.Helper()
	root := lockedMCPFixture(t)
	dir := filepath.Join(root, numRichRun)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	var b strings.Builder
	seq := 0
	pidField := regexp.MustCompile(`,?"pid":(\d+)`)
	add := func(kind, extra string) {
		pid := "10"
		if m := pidField.FindStringSubmatch(extra); m != nil {
			pid, extra = m[1], strings.TrimPrefix(pidField.ReplaceAllString(extra, ""), ",")
		}
		l := line(numRichRun, numRichAgent, seq, at.Add(time.Duration(seq)*time.Second), kind, extra)
		b.WriteString(strings.Replace(l, `"pid":10,`, `"pid":`+pid+`,`, 1))
		seq++
	}
	add("run_start", `"tier":"landlock","contract_source":{"path":"/work/demo.yaml"},"cwd":"/work","command":["sh","agent.sh"]`)
	add("exec", `"verdict":"allow","op":"exec","path":"/bin/sh","pid":200,"ppid":10`)
	add("exec", `"verdict":"allow","op":"exec","path":"/usr/bin/curl","pid":300,"ppid":200`)
	add("refused", `"op":"read","target":"/home/u/.ssh/id_rsa","rule":"fs.deny_read[/home/u/.ssh/]","pid":300`)
	add("fs", `"verdict":"allow","op":"open","flags":0,"path":"/home/u/.aws/credentials","pid":300`)
	add("net", `"verdict":"allow","rule":"net.allow[pypi.org]","proto":"tcp","dst":"151.101.0.223:443","host":"pypi.org","pid":300`)
	add("net", `"verdict":"allow","rule":"net.allow[pypi.org]","proto":"tcp","dst":"151.101.0.223:443","host":"pypi.org","pid":300`)
	add("refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"203.0.113.9:8443","pid":300`)
	add("refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"203.0.113.9:8443","pid":300`)
	add("fs", `"verdict":"allow","op":"open","path":"/work/out/a.txt","flags":577,"pid":200`)
	add("fs", `"verdict":"allow","op":"open","path":"/work/out/b.txt","flags":577,"pid":200`)
	add("refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/etc/passwd","pid":200`)
	for range 6 {
		add("refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket","pid":200`)
	}
	add("net", `"verdict":"ask","rule":"net.ask[example.com]","proto":"tcp","dst":"93.184.216.34:443","host":"example.com","pid":300`)
	add("ask", `"ask_id":"q-1","hold":"net","op":"connect","target":"example.com:443"`)
	add("answer", `"ask_id":"q-1","approved":true,"by":"uid:1000 pid:9 dashboard","after_s":2`)
	add("ask", `"ask_id":"q-2","hold":"fs","op":"open","target":"/work/secret.txt"`)
	add("answer", `"ask_id":"q-2","approved":false,"by":"uid:1000 pid:9 dashboard","after_s":3`)
	for range 20 {
		add("exec", `"verdict":"allow","op":"exec","path":"/bin/true","pid":400,"ppid":200`)
	}
	add("net", `"verdict":"allow","rule":"credential[fake]","proto":"tcp","dst":"127.0.0.1:9511","host":"127.0.0.1","pid":300`)
	add("run_end", `"reason":"exit","exit_code":3`)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	contract := "version: 1\nname: counter\ncommand: [sh, agent.sh]\nfs:\n  deny_read: [/home/u/.ssh/]\n  write: [./out/]\nnet:\n  allow: [pypi.org]\n  ask: [example.com]\n"
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mcptools.WriteSeen(filepath.Join(root, harmRun), mcptools.Seen{"files": {"read_file", "write_file", "delete_file"}}); err != nil {
		t.Fatal(err)
	}
	return root
}

// numberPages are the pages the rule covers, with their kind: "snapshot" pages read every run; "run" pages read the
// rich run's own record, and their waiting count the whole queue; "other run" pages the live run's whole record.
func numberPages() []struct{ path, kind string } {
	r := "/runs/" + numRichRun
	pages := []struct{ path, kind string }{
		{"/compare", "snapshot"}, {"/compare?a=" + numRichRun + "&b=" + cleanRun, "compare"}, {"/machine", "machine"}, {"/glossary", "snapshot"}, {"/glossary?q=no-such-word", "snapshot"}, {"/severity", "snapshot"}, {"/routes", "snapshot"}, {"/no-such-page", "snapshot"}, {"/", "snapshot"}, {"/runs", "snapshot"}, {"/runs?state=ended", "snapshot"},
		{r, "run"}, {r + "/refusals", "run"}, {r + "/receipt", "run"}, {r + "/processes", "run"}, {r + "/unused", "run"},
		{r + "?before=20", "run"}, {r + "/least-privilege", "run"}, {r + "?details=1", "run"},
		{"/logs", "snapshot"}, {"/logs?filters=1", "snapshot"}, {"/logs?group=rule", "snapshot"},
		{"/logs?group=process", "snapshot"}, {"/logs?group=target", "snapshot"}, {"/logs?group=severity", "snapshot"},
		{"/detections", "snapshot"}, {"/refusals", "snapshot"}, {"/approvals", "snapshot"}, {"/approvals?tab=history", "snapshot"},
		{"/rules", "snapshot"}, {"/rules?run=" + numRichRun, "snapshot"},
		{"/mcp?run=" + harmRun, "mcp"},
		{"/runs/" + cleanRun, "other run"}, {"/runs/" + cleanRun + "/receipt", "other run"}, {"/runs/" + cleanRun + "/refusals", "other run"}, {"/runs/" + harmRun, "other run"}, {"/runs/" + harmRun + "/receipt", "other run"},
		{r + "/rows?after=0", "run"}, {"/logs/rows", "snapshot"}, {"/logs/line?run=" + numRichRun + "&seq=43", "run"}, {"/logs?sys=hide", "snapshot"}, {"/logs?where=prog%3Acurl", "snapshot"}, {"/logs?q=nscd&group=target", "snapshot"},
	}
	for _, pg := range append([]struct{ path, kind string }(nil), pages...) {
		if !strings.Contains(pg.path, "/rows") && !strings.Contains(pg.path, "/line?") {
			pages = append(pages, struct{ path, kind string }{"regions:" + pg.path, pg.kind})
		}
	}
	return pages
}

// numberWalkLayers let a layer kept out of some builds add its pages to the rendered walk, with the setup they
// need, from its own test file (vault_numbers_test.go), as the vault seam requires.
var numberWalkLayers []func(t *testing.T, s *Server, c *http.Cookie) []struct{ path, kind string }

// renderedNumberModes are the ledger states the rendered walk builds for real: the ledgerview bounds are lowered,
// a malformed line is appended, or a run's events file is replaced by a directory.
var renderedNumberModes = []string{"complete", "live index missing", "truncated", "evicted", "malformed line", "run not listed", "runs omitted", "waiting list cut"}

// pageForm is wantForm for a page of kind: a run page reads the rich run's own record; its queue is the snapshot's.
func pageForm(mode, kind, source string) string {
	if mode == "live index missing" {
		if source == "queue" {
			return "could not read"
		} // the cold page cannot establish an active request
		return wantForm(mode, source)
	}
	if source == "live" {
		source = "runs"
	}
	if source == "status" || source == "selection" || source == "remaining" {
		source = "aggregate"
	}
	switch kind {
	case "machine":
		if source == "aggregate" {
			return "exact"
		}
	case "compare":
		if (mode == "run not listed" || mode == "runs omitted" || mode == "waiting list cut") && source != "runs" && source != "queue" {
			return "exact"
		}
	case "run":
		if source == "queue" || source == "runs" {
			return wantForm(mode, source)
		}
		if mode == "run not listed" || mode == "evicted" || mode == "runs omitted" || mode == "waiting list cut" {
			// Another run could not be read, or a root snapshot evicted windows: a run page reloads its own
			// bounded window, which holds this small run whole.
			return "exact"
		}
	case "mcp":
		if source == "mcp" {
			return "exact" // the MCP run itself reads whole through the strict reader
		}
	case "other run":
		if mode == "waiting list cut" && (source == "pending" || source == "unanswered") {
			return "at least"
		}
		if source != "queue" && source != "runs" {
			return "exact" // the live run's small record is never cut, malformed or unlisted here
		}
	}
	if source == "vault" && (mode == "truncated" || mode == "evicted" || mode == "malformed line") {
		return "at least"
	}
	if source == "vault" && mode == "runs omitted" {
		return "at least"
	}
	if source == "vault" && mode == "waiting list cut" {
		return "exact"
	}
	return wantForm(mode, source)
}

// TestNumberInventoryRenderedPages renders every page the rule covers through the real handlers in each ledger
// state and reads its numbers back by their markers: no number sits outside a marker, every marker is in the
// inventory, and each marked number has the form its source's completeness calls for, with a way to the complete
// record when it is qualified. It also reports which inventory rows the walk saw.
func TestNumberInventoryRenderedPages(t *testing.T) {
	defs, err := numberDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]map[string]bool{} // id → forms seen
	seenEx := map[string]bool{}
	recordEx := func(body string) {
		doc, err := html.Parse(strings.NewReader(inventoryDocument(body)))
		if err != nil {
			t.Fatal(err)
		}
		walk(doc, func(n *html.Node) {
			for _, a := range n.Attr {
				if a.Key == "data-number-exclude" || strings.HasPrefix(a.Key, "data-number-exclude-") {
					seenEx[a.Val] = true
				}
			}
		})
	}
	for _, mode := range renderedNumberModes {
		t.Run(mode, func(t *testing.T) {
			switch mode {
			case "truncated":
				old := ledgerview.MaxLines
				ledgerview.MaxLines = 16
				t.Cleanup(func() { ledgerview.MaxLines = old })
			case "runs omitted":
				old := ledgerview.MaxRuns
				ledgerview.MaxRuns = 2
				t.Cleanup(func() { ledgerview.MaxRuns = old })
			case "evicted":
				old := ledgerview.MaxResidentBytes
				ledgerview.MaxResidentBytes = 1
				t.Cleanup(func() { ledgerview.MaxResidentBytes = old })
			}
			root := numberLedger(t)
			holdLock(t, filepath.Join(root, harmRun))
			if mode == "runs omitted" {
				// The two runs kept are the two newest by their record files' times, and the run with the waiting
				// asks must be one of them. Set the times, as a kernel that stamps files written within one tick alike
				// (a Debian 6.12 guest did) would otherwise decide which run is left out.
				base := time.Now().Add(-time.Hour)
				for i, run := range []string{cleanRun, harmRun, numRichRun} {
					at := base.Add(time.Duration(i) * time.Minute)
					if err := os.Chtimes(filepath.Join(root, run, "events.jsonl"), at, at); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch mode {
			case "live index missing":
				if err := os.RemoveAll(filepath.Join(root, ".live")); err != nil {
					t.Fatal(err)
				}
			case "waiting list cut":
				for i := 0; i < 80; i++ {
					appendLine(t, root, harmRun, line(harmRun, "Counter", 100+i, time.Now(), "ask", fmt.Sprintf(`"ask_id":"cut-%d","hold":"net","op":"connect","target":"%s"`, i, strings.Repeat("a", 16384))))
				}
			case "malformed line":
				f, err := os.OpenFile(filepath.Join(root, numRichRun, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("{damaged record}\n")
				if cerr := f.Close(); err == nil {
					err = cerr
				}
				if err != nil {
					t.Fatal(err)
				}
			case "run not listed":
				if err := os.MkdirAll(filepath.Join(root, numUnlisted, "events.jsonl"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			snap, err := ledgerview.Load(root)
			if err != nil {
				t.Fatal(err)
			}
			rich := snap.Find(numRichRun)
			switch {
			case rich == nil:
				t.Fatal("the rich run is not listed")
			case (mode == "truncated" || mode == "evicted") != rich.Cut:
				t.Fatalf("mode %s: rich run cut=%v", mode, rich.Cut)
			case mode == "evicted" && len(rich.Events) != 0:
				t.Fatal("the fixture did not evict the rich run's window")
			case (mode == "malformed line") != (rich.Bad > 0):
				t.Fatalf("mode %s: rich run bad=%d", mode, rich.Bad)
			case (mode == "run not listed") != (snap.ReadError != ""):
				t.Fatalf("mode %s: snapshot error %q", mode, snap.ReadError)
			}
			s := newServer(t, root)
			c := login(t, s)
			pages := numberPages()
			for _, hook := range numberWalkLayers {
				pages = append(pages, hook(t, s, c)...)
			}
			for _, pg := range pages {
				t.Run(pg.path, func(t *testing.T) {
					body := inventoryResponse(t, s, c, pg.path)
					recordEx(body)
					for _, u := range unmarkedNumbers(t, body) {
						t.Errorf("a number outside a marker: %s", u)
					}
					qualified := false
					for _, m := range markersIn(t, body) {
						def, ok := defs[m.id]
						if !ok {
							t.Errorf("rendered number %q is missing from the inventory", m.id)
							continue
						}
						if seen[m.id] == nil {
							seen[m.id] = map[string]bool{}
						}
						form := formOf(m.words)
						seen[m.id][form] = true
						if form != "exact" {
							qualified = true
							if m.reason == "" && !isPhrase(m.id) {
								t.Errorf("%s reads %q with no reason", m.id, m.words)
							}
						}
						var want string
						switch {
						case isPhrase(m.id):
							continue // sentences and drawings: TestAttention*, TestScopedChip, TestQualifyChart
						case def.Source == "receipt":
							continue // the Receipt's own limits: TestReceiptBoundedListsQualifyCounts
						case def.Scope == "row" && pg.kind == "compare":
							r := snap.Find(m.run)
							want = "exact"
							if r != nil {
								if r.ReadError != "" {
									want = "could not read"
								} else if r.Bad > 0 || (def.Source == "window" && r.Cut) {
									want = "at least"
								}
							}
						case def.Scope == "row" && m.run != numRichRun, def.Scope == "row" && (mode == "run not listed" || mode == "runs omitted" || mode == "waiting list cut"):
							want = "exact" // a row of a run whose own record is whole
						case def.Scope == "row":
							want = wantForm(mode, def.Source)
						default:
							want = pageForm(mode, pg.kind, def.Source)
						}
						if form != want {
							t.Errorf("%s (source %s, run %q) reads %q, want the %s form", m.id, def.Source, m.run, m.words, want)
						}
					}
					recovery := body
					if strings.Contains(pg.path, "/rows") || strings.Contains(pg.path, "/line?") {
						parent := "/logs"
						if strings.HasPrefix(pg.path, "/runs/") {
							parent = strings.Split(pg.path, "/rows")[0]
						}
						recovery = getRaw(t, s, c, parent)
					}
					if qualified && !strings.Contains(recovery, "/logs.jsonl?run=") && !strings.Contains(recovery, `href="/runs"`) {
						t.Error("a qualified number has no way to the complete record")
					}
				})
			}
		})
	}
	for _, fixture := range append(numberBranchFixtures(t), numberSurfaceFixtures(t)...) {
		t.Run("branch/"+fixture.name, func(t *testing.T) {
			recordEx(fixture.body)
			for _, u := range unmarkedNumbers(t, fixture.body) {
				t.Errorf("a number outside a marker: %s", u)
			}
			for _, m := range markersIn(t, fixture.body) {
				if _, ok := defs[m.id]; !ok {
					t.Errorf("unknown inventory row %s", m.id)
				}
				if seen[m.id] == nil {
					seen[m.id] = map[string]bool{}
				}
				seen[m.id][formOf(m.words)] = true
			}
		})
	}
	var unseen, unqualified []string
	for id, def := range defs {
		switch {
		case seen[id] == nil:
			unseen = append(unseen, id)
		case def.Source != "exact" && !seen[id]["at least"] && !seen[id]["could not read"]:
			unqualified = append(unqualified, id)
		}
	}
	sort.Strings(unseen)
	sort.Strings(unqualified)
	if len(unseen) > 0 {
		t.Errorf("inventory rows no fixture renders: %v", unseen)
	}
	t.Logf("rendered walk: %d of %d inventory rows seen; not seen on these fixture pages: %v", len(defs)-len(unseen), len(defs), unseen)
	for id, reason := range numberExclusions(t) {
		if !seenEx[id] {
			t.Errorf("exclusion matches no fixture element: %s (%s)", id, reason)
		}
	}
	t.Logf("exclusions: %d of %d source elements rendered", len(seenEx), len(numberExclusions(t)))
	t.Logf("rows with an incomplete-able source seen only exact: %v", unqualified)
}

// isPhrase names the markers whose words are a sentence or a drawing, not a number: their qualification is checked
// by the tests named in TestNumberInventoryRenderedPages.
func isPhrase(id string) bool {
	switch id {
	case "overview.attention", "run.attention", "approvals.attention", "overview.refusal-series", "overview.secret-series", "shared.secret-chip":
		return true
	}
	return false
}

// formOf is a marker's form from its words.
func formOf(words string) string {
	switch {
	case strings.Contains(strings.ToLower(words), "at least"), strings.Contains(words, "not fully known"), strings.Contains(words, "seen in what is retained"), regexp.MustCompile(`\d\+`).MatchString(words):
		return "at least"
	case strings.Contains(words, "(?)"), words == "?", strings.Contains(strings.ToLower(words), "could not read"), strings.Contains(words, "could not be read"), strings.Contains(words, "could not tell"):
		return "could not read"
	}
	return "exact"
}

// TestNumberInventoryCappedHistory: past the 200-answer limit, History and its session tallies are lower bounds with
// the reason and a way to the record of the oldest answer left out.
func TestNumberInventoryCappedHistory(t *testing.T) {
	root := t.TempDir()
	id := cleanRun
	if err := os.MkdirAll(filepath.Join(root, id), 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	var b strings.Builder
	b.WriteString(line(id, "History", 0, at, "run_start", `"tier":"observe","command":["sh"]`))
	for i := 1; i <= historyAnswers+1; i++ {
		b.WriteString(line(id, "History", 2*i-1, at, "ask", fmt.Sprintf(`"ask_id":"a%d","hold":"net"`, i)))
		b.WriteString(line(id, "History", 2*i, at, "answer", fmt.Sprintf(`"ask_id":"a%d","approved":true,"by":"operator"`, i)))
	}
	if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	body := getRaw(t, s, login(t, s), "/approvals?tab=history")
	markers := numberMarkers(t, body)
	for _, key := range []string{"approvals.history", "approvals.session-allowed", "approvals.session-denied"} {
		if len(markers[key]) == 0 {
			t.Errorf("missing %s", key)
		}
		for _, got := range markers[key] {
			if !strings.HasPrefix(got, "at least ") {
				t.Errorf("%s past the history limit looks exact: %q", key, got)
			}
		}
	}
	if !strings.Contains(body, "Answer history shows only the newest 200 answers") || !strings.Contains(body, "/logs.jsonl?run="+id) {
		t.Error("the history limit lacks its reason or the way to the complete record")
	}
}

// TestCoverageNoteSkipsWhatBannersSay: a reason a page banner already states (bounded windows, omitted runs, a cut
// waiting list) is not repeated in the count note, whose links stay and name their run.
func TestCoverageNoteSkipsWhatBannersSay(t *testing.T) {
	s := newServer(t, t.TempDir())
	snap := &ledgerview.Snapshot{LinesCut: true, Runs: []*ledgerview.Run{{ID: numRichRun, Agent: numRichAgent, Cut: true, Bad: 1}}}
	c := s.chromeOf(snap, "Overview", "overview")
	notes := c.CountNotes()
	if slices.Contains(notes, reasonWindow) || !slices.Contains(notes, reasonBadLines) {
		t.Errorf("count notes %q: want the malformed-line reason and not the bannered window reason", notes)
	}
	if !slices.Contains(c.Numbers.Links, countLink{Label: "Complete record of " + numRichAgent, URL: "/logs.jsonl?run=" + numRichRun}) {
		t.Errorf("links %v lack the run's named complete record", c.Numbers.Links)
	}
}

// Fragment rows need a table parsing context; a document parser discards bare tr tags.
func inventoryDocument(body string) string {
	if strings.HasPrefix(strings.TrimSpace(body), "<tr") {
		return "<table><tbody>" + body + "</tbody></table>"
	}
	return body
}

func inventoryRunOf(n *html.Node) string {
	for p := n; p != nil; p = p.Parent {
		k, _ := attr(p, "data-k")
		for _, r := range []string{numRichRun, harmRun, cleanRun} {
			if strings.HasPrefix(k, r) {
				return r
			}
		}
	}
	return ""
}

func inventoryResponse(t *testing.T, s *Server, c *http.Cookie, path string) string {
	t.Helper()
	if !strings.HasPrefix(path, "regions:") {
		w := doRaw(s, "GET", path, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Body.String()
	}
	req := httptest.NewRequest(http.MethodGet, strings.TrimPrefix(path, "regions:"), nil)
	req.Host = "127.0.0.1:8484"
	req.AddCookie(c)
	names := map[string]bool{}
	for _, n := range layoutRegions {
		names[n] = true
	}
	for _, ns := range pageRegions {
		for _, n := range ns {
			names[n] = true
		}
	}
	var header []string
	for _, n := range slices.Sorted(maps.Keys(names)) {
		header = append(header, n+":x")
	}
	req.Header.Set(regionHeader, strings.Join(header, ","))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}
