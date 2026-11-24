// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"golang.org/x/net/html"
)

func TestReceiptBoundedListsQualifyCounts(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, id string
		r        receipt.Receipt
	}{
		{"files", "run.files-written", receipt.Receipt{Run: secondRequestRun, Files: receipt.Files{Recorded: true, Written: []string{"/work/a"}, Truncated: true}}},
		{"sensitive", "run.receipt-sensitive-files", receipt.Receipt{Run: secondRequestRun, SensitiveReads: []receipt.SensitiveRead{{Path: "/home/u/.ssh/id_rsa"}}, SensitiveReadsTruncated: true}},
		{"unrecorded reads", "run.receipt-sensitive-files", receipt.Receipt{Run: secondRequestRun, SensitiveReads: []receipt.SensitiveRead{{Path: "/home/u/.ssh/id_rsa"}}, SensitiveReadsUnknown: true}},
		{"programs", "run.receipt-program-starts", receipt.Receipt{Run: secondRequestRun, Programs: []receipt.Program{{Path: "/bin/true", Count: 3}}, ProgramsMore: 1}},
		{"token statistics", "run.receipt-tokens", receipt.Receipt{Run: secondRequestRun, Tokens: receipt.Tokens{Recorded: true, ModelCalls: 2, Metered: 1, In: 30}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := pages["run"].ExecuteTemplate(&b, "receipt", &receiptView{R: &tc.r}); err != nil {
				t.Fatal(err)
			}
			found := false
			walk(parseHTML(t, "receipt", b.String()), func(n *html.Node) {
				if id, _ := attr(n, "data-number"); id == tc.id {
					found = true
					if !strings.HasPrefix(text(n), "at least ") {
						t.Errorf("bounded list count is exact: %q", text(n))
					}
				}
			})
			if !found {
				t.Errorf("missing inventory marker %s", tc.id)
			}
			if !strings.Contains(b.String(), "identity limit") && !strings.Contains(b.String(), "most frequent programs") && !strings.Contains(b.String(), "no token counts") && !strings.Contains(b.String(), "did not record every file read") {
				t.Error("bounded count lacks a plain reason")
			}
			if !strings.Contains(b.String(), "/logs.jsonl?run=") {
				t.Error("bounded count lacks complete-record recovery")
			}
		})
	}
}

func TestReceiptPlacesNamesOnlyTheListedScope(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	v := &receiptView{R: &receipt.Receipt{Run: secondRequestRun, Connections: []receipt.Connection{{Destination: "example.test:443", Count: 2}}, ConnectionTries: 100000, ConnectionsMore: 10000}}
	if got := v.Places(); got != 1 {
		t.Fatalf("listed places=%d; overflow attempts are not distinct identities", got)
	}
	var b bytes.Buffer
	if err := pages["run"].ExecuteTemplate(&b, "receipt", v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text(parseHTML(t, "receipt", b.String())), "1 listed place") {
		t.Error("place count does not name its exact listed scope")
	}
}

func TestProcessNumbersReflectSourceCompleteness(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, prefix string
		run          ledgerview.Run
	}{
		{"truncated", "at least ", ledgerview.Run{ID: secondRequestRun, Cut: true}},
		{"malformed line", "at least ", ledgerview.Run{ID: secondRequestRun, Bad: 1}},
		{"reader failed", "could not read", ledgerview.Run{ID: secondRequestRun, ReadError: "permission denied"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := procsFor(t.TempDir(), &tc.run, time.Now())
			var b bytes.Buffer
			if err := pages["run"].ExecuteTemplate(&b, "procs", v); err != nil {
				t.Fatal(err)
			}
			found := 0
			walk(parseHTML(t, "processes", b.String()), func(n *html.Node) {
				if id, _ := attr(n, "data-number"); strings.HasPrefix(id, "run.process") {
					found++
					if !strings.HasPrefix(text(n), tc.prefix) {
						t.Errorf("%s=%q missing %q", id, text(n), tc.prefix)
					}
				}
			})
			if found == 0 {
				t.Error("no process inventory metrics were checked")
			}
		})
	}
}

// TestReceiptNotesFollowShownNumbers: a Receipt states a count's reason in its own padded block, and only for a count
// it shows. A run that kept no file read has no sensitive-file count, and its section already says what is not known.
func TestReceiptNotesFollowShownNumbers(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	render := func(r receipt.Receipt) string {
		var b bytes.Buffer
		if err := pages["run"].ExecuteTemplate(&b, "receipt", &receiptView{R: &r}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	const note = "This run did not record every file read."
	if body := render(receipt.Receipt{Run: secondRequestRun, SensitiveReadsUnknown: true}); strings.Contains(body, note) {
		t.Error("a count the Receipt does not show has a note")
	}
	body := render(receipt.Receipt{Run: secondRequestRun, SensitiveReads: []receipt.SensitiveRead{{Path: "/home/u/.ssh/id_rsa"}}, SensitiveReadsUnknown: true})
	i := strings.Index(body, `<div class="panel-body rc-block rc-notes">`)
	if i < 0 || !strings.Contains(body[i:], note) || !strings.Contains(body[i:], "/logs.jsonl?run="+secondRequestRun) {
		t.Error("the note for a shown count is not in its own padded block with the complete record")
	}
}

func TestEmptyReceiptZeroBranchesCarrySources(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	r := receipt.Receipt{Run: secondRequestRun, Files: receipt.Files{Recorded: true}}
	var b bytes.Buffer
	if err := pages["run"].ExecuteTemplate(&b, "receipt", &receiptView{R: &r}); err != nil {
		t.Fatal(err)
	}
	doc := parseHTML(t, "empty receipt", b.String())
	for _, tc := range []struct{ words, id string }{
		{"never asked", "run.receipt-asked"},
		{"It wrote no file.", "run.files-written"},
		{"None: no file that looks like a secret, and none a read rule guards.", "run.receipt-sensitive-files"},
	} {
		t.Run(tc.words, func(t *testing.T) {
			found := false
			walk(doc, func(n *html.Node) {
				if id, _ := attr(n, "data-number"); id == tc.id && strings.Contains(text(n), tc.words) {
					found = true
				}
			})
			if !found {
				t.Fatalf("zero branch %q lacks its quantity source %s", tc.words, tc.id)
			}
		})
	}
}

func TestAdditionalZeroBranchesCarrySources(t *testing.T) {
	fixtures := numberBranchFixtures(t)
	for _, tc := range []struct{ words, id string }{
		{"The run named no rule and its contract declares no entry.", "run.empty-rule-list"},
		{"No contract copy", "run.contract-copy"},
		{"This run used every entry its contract grants: nothing to remove.", "run.proposal-entries"},
		{"No receipt", "run.receipt-availability"},
		{"No proposal could be made from this run:", "run.proposal-availability"},
		{"Nothing at this scope", "event.available-actions-zero"},
		{"Nothing to save", "editor.changes-zero"},
		{"The rules file already says so: nothing to change.", "editor.changes-zero"},
		{"No entries.", "editor.entries-zero"},
		{"No runs yet", "overview.runs"},
		{"No lines read", "overview.chain-lines-zero"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			found := false
			for _, f := range fixtures {
				if strings.HasPrefix(tc.id, "overview.") && f.name != "overview/r-ov-tiles" {
					continue
				}
				if !strings.Contains(text(parseHTML(t, f.name, f.body)), tc.words) {
					continue
				}
				found = true
				marked := false
				for _, m := range markersIn(t, f.body) {
					if m.id == tc.id && strings.Contains(m.words, tc.words) {
						marked = true
					}
				}
				if !marked {
					t.Errorf("%s lacks %s for %q", f.name, tc.id, tc.words)
				}
			}
			if !found {
				t.Errorf("zero fixture lacks %q", tc.words)
			}
		})
	}
}

func TestUnknownDriftDoesNotBecomeZeroUnused(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, tab := range []string{"unused", "least-privilege"} {
		var b bytes.Buffer
		p := page{Data: runData{Run: &ledgerview.Run{ID: numRichRun}, Tab: tab, Drift: &rulesview.Drifted{Unknown: true}}}
		if err := pages["run"].ExecuteTemplate(&b, "r-run-tab", p); err != nil {
			t.Fatal(err)
		}
		words := text(parseHTML(t, tab, b.String()))
		if strings.Contains(words, "contract declares no entry") || strings.Contains(words, "used every entry") || !strings.Contains(words, "not known") {
			t.Errorf("%s unknown declarations became an empty count: %s", tab, words)
		}
	}
}

func TestWatchZeroHasQuantitySource(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := pages["run"].ExecuteTemplate(&b, "blockwhy", true); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range markersIn(t, b.String()) {
		if m.id == "shared.watch-refusals" && strings.Contains(m.words, "refuses nothing") {
			found = true
		}
	}
	if !found {
		t.Fatal("watch-mode zero refusals lack their policy source")
	}
}
