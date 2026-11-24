// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/askpair"
	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/pricetable"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	receiptspec "github.com/attention-span-ai/tego/pkg/spec/receipt"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// recordedRun writes one recorded run under root through the ledger writer and returns its id; body adds the lines.
func recordedRun(t *testing.T, root, agentID string, start record.RunStartPayload, body func(add func(kind record.Kind, verdict record.Verdict, rule string, reason record.Reason, payload any)), end *record.RunEndPayload) string {
	t.Helper()
	id, err := identity.NewRunID([32]byte{}, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: agentID})
	if err != nil {
		t.Fatal(err)
	}
	if start.Command == nil {
		start.Command = []string{"agent"}
	}
	start.Cwd, start.TegoVersion, start.Kernel = "/w", "test", "test"
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	body(func(kind record.Kind, verdict record.Verdict, rule string, reason record.Reason, payload any) {
		t.Helper()
		e := &record.Event{Kind: kind, Source: record.SourceSupervisor, PID: 1, TID: 1, Verdict: verdict, Rule: rule, Reason: reason}
		if kind.IsAction() {
			e.Attr, e.Authority = record.Unattributed(), record.AuthorityRule
		}
		if err := e.SetPayload(payload); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	})
	if end != nil {
		if err := w.Close(*end); err != nil {
			t.Fatal(err)
		}
	} else if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// receiptRuns are the recorded runs the three readers of a run are held to: a normal one, one that refused, one with
// gaps, one that was partly unreadable, an adopted one, a watched one, an unanswered ask at the end, and a priced one.
type receiptRun struct {
	name  string
	start record.RunStartPayload
	body  func(add func(kind record.Kind, verdict record.Verdict, rule string, reason record.Reason, payload any))
	end   *record.RunEndPayload
	// damage edits the run's events file after it was written (a line the record cannot read).
	damage func(t *testing.T, events string)
	// malformed says the asks of the run are malformed in the ways askpair names: how many ask lines repeat an id and
	// how many answer lines pair with no ask, and what the readers must then say of its asks: how many were asked,
	// approved and left unanswered. ids are the ask ids the run names.
	malformed *malformedAsks
}

type malformedAsks struct {
	repeated, unpaired, asked, approved, unanswered int
	ids                                             []string
}

type adder = func(kind record.Kind, verdict record.Verdict, rule string, reason record.Reason, payload any)

func parityAsk(id, target string) map[string]any {
	return map[string]any{"ask_id": id, "hold": "open", "op": "open", "target": target, "ask_rule": "fs.ask_read[/w/]"}
}

func parityAnswer(id string) map[string]any {
	return map[string]any{"ask_id": id, "by": "uid:1000 pid:9", "after_s": 1.0, "approved": true}
}

func receiptRuns() []receiptRun {
	three := 3
	return []receiptRun{
		{name: "normal", start: record.RunStartPayload{Tier: "landlock", Capture: "uprobe"}, body: func(add adder) {
			add(record.KindFS, record.VerdictAllow, "fs.write[/w/]", "", record.FSPayload{Op: record.FSOpen, Path: "/w/out.txt", Flags: 0o1101, Created: true})
			add(record.KindAsk, "", "", "", map[string]any{"ask_id": "q-1", "hold": "open", "op": "open", "target": "/w/x", "ask_rule": "fs.ask_read[/w/]"})
			add(record.KindAnswer, "", "", "", map[string]any{"ask_id": "q-1", "by": "uid:1000 pid:9", "after_s": 1.0, "approved": true})
		}},
		{name: "refused", start: record.RunStartPayload{Tier: "landlock"}, end: &record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 3}, body: func(add adder) {
			add(record.KindNet, record.VerdictRefused, "unmatched", record.ReasonNetNotAllowed, record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9822"})
			add(record.KindRefused, "", "unmatched", record.ReasonNetNotAllowed,
				record.RefusedPayload{Op: "net", Target: "127.0.0.1:9822", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"})
			add(record.KindRefused, "", "unmatched", record.ReasonWriteOutsideContract, record.RefusedPayload{Op: "open", Target: "/etc/x", Reason: record.ReasonWriteOutsideContract, Rule: "unmatched"})
		}},
		{name: "gaps", start: record.RunStartPayload{Tier: "landlock", Capture: "uprobe"}, body: func(add adder) {
			add(record.KindGap, "", "", "", record.GapPayload{What: "capture", Why: "no-openssl", Binary: "/usr/bin/curl", Count: 1})
			add(record.KindGap, "", "", "", record.GapPayload{What: "record", Why: "channel-full", Count: 3})
			add(record.KindGap, "", "", "", record.GapPayload{What: "capture", Why: "no-openssl", Binary: "/usr/bin/gh", Count: 1})
		}},
		{name: "an ask unanswered at the end", start: record.RunStartPayload{Tier: "landlock"}, end: &record.RunEndPayload{Reason: record.RunEndStopped}, body: func(add adder) {
			add(record.KindAsk, "", "", "", map[string]any{"ask_id": "q-9", "hold": "open", "op": "open", "target": "/w/y", "ask_rule": "fs.ask_read[/w/]"})
		}},
		{name: "partly unreadable", start: record.RunStartPayload{Tier: "landlock"}, body: func(add adder) {
			add(record.KindFS, record.VerdictAllow, "fs.read[/]", "", record.FSPayload{Op: record.FSOpen, Path: "/w/a"})
			add(record.KindFS, record.VerdictAllow, "fs.read[/]", "", record.FSPayload{Op: record.FSOpen, Path: "/w/b"})
		}, damage: func(t *testing.T, events string) {
			b, err := os.ReadFile(events)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.SplitAfter(string(b), "\n")
			lines[2] = "{not json at all\n" // a line in the middle of the record that cannot be read
			if err := os.WriteFile(events, []byte(strings.Join(lines, "")), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "adopted", start: record.RunStartPayload{Tier: "cgroup", AppliedLimits: &record.AppliedLimits{PidsMax: &three}}, body: func(add adder) {
			add(record.KindExec, record.VerdictObserved, "unmatched", "", record.ExecPayload{Path: "/usr/bin/agent", Argv: []string{"agent"}})
		}},
		{name: "watched", start: record.RunStartPayload{Tier: "landlock", ReadsNotified: &record.ReadsNotified{Notified: false, Why: record.ReadsNotifiedWhyRecordsOnly}}, body: func(add adder) {
			add(record.KindFS, record.VerdictObserved, "unmatched", "", record.FSPayload{Op: record.FSOpen, Path: "/w/secret.txt", Flags: 0o2000000})
			add(record.KindNet, record.VerdictObserved, "unmatched", "", record.NetPayload{Proto: "tcp", Dst: "93.184.216.34:443"})
		}},
		{name: "a repeated ask id", start: record.RunStartPayload{Tier: "landlock"}, body: func(add adder) {
			add(record.KindAsk, "", "", "", parityAsk("q-1", "/w/a"))
			add(record.KindAsk, "", "", "", parityAsk("q-1", "/w/other"))
			add(record.KindAnswer, "", "", "", parityAnswer("q-1"))
		}, malformed: &malformedAsks{repeated: 1, asked: 1, approved: 1, ids: []string{"q-1"}}},
		{name: "an answer before its ask", start: record.RunStartPayload{Tier: "landlock"}, body: func(add adder) {
			add(record.KindAnswer, "", "", "", parityAnswer("q-1"))
			add(record.KindAsk, "", "", "", parityAsk("q-1", "/w/a"))
		}, malformed: &malformedAsks{unpaired: 1, asked: 1, unanswered: 1, ids: []string{"q-1"}}},
		{name: "an answer to an id never asked", start: record.RunStartPayload{Tier: "landlock"}, body: func(add adder) {
			add(record.KindAsk, "", "", "", parityAsk("q-1", "/w/a"))
			add(record.KindAnswer, "", "", "", parityAnswer("q-9"))
		}, malformed: &malformedAsks{unpaired: 1, asked: 1, unanswered: 1, ids: []string{"q-1", "q-9"}}},
		{name: "priced", start: record.RunStartPayload{Tier: "landlock", Capture: "uprobe"}, body: func(add adder) {
			add(record.KindSSLResponse, "", "", "", map[string]any{"request_seq": 1, "status": 200, "parser_version": "1",
				"model": "claude-sonnet-4-5-20250929", "latency_ms": 1, "usage": map[string]int{"input": 1000000, "output": 100000}})
		}},
	}
}

// TestReceiptStatusAndDashboardAgree: one run, one story. For each recorded run the receipt `tego receipt` prints, the
// state `tego status` reports and what the dashboard reads of the run (its read model and the receipt behind its Receipt
// tab, priced with the machine's price table as the terminal prices it) say the same: how the run ended, the tier, the
// lines, the refusals, the asks and what is still waiting, the gaps and what they mean for the counts, and the cost. The
// receipt behind the Receipt tab is the receipt `tego receipt --json` prints, field for field, except the binding the
// terminal alone adds. A run whose record has a line nobody can read says so in all three.
func TestReceiptStatusAndDashboardAgree(t *testing.T) {
	root := gcRoot(t)
	table := filepath.Join(filepath.Dir(root), "prices.yaml")
	if err := os.WriteFile(table, []byte("version: 1\nupdated: 2026-09-22\nmodels:\n  claude-sonnet-4-5-20250929:\n    input_per_mtok: 3.00\n    output_per_mtok: 15.00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := os.Getenv("TEGO_CONFIG")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\nprices: "+table+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	pricing := ledgerview.Pricing{Prices: pricetable.NewLazy(func() pricetable.Coster {
		if tab, _ := pricetable.FromMachine(m); tab != nil {
			return tab
		}
		return nil
	})}
	store := ledgerview.Open(root)

	for _, rr := range receiptRuns() {
		t.Run(rr.name, func(t *testing.T) {
			id := recordedRun(t, root, "demo", rr.start, rr.body, rr.end)
			if rr.damage != nil {
				rr.damage(t, filepath.Join(root, id, ledger.EventsFile))
			}

			// The terminal.
			rcode, rout, rerr := run(t, "receipt", id, "--json")
			scode, sout, serr := run(t, "status", id, "--json")
			// The dashboard.
			drun, runErr := store.Run(id)
			drc, drcErr := ledgerview.LoadReceiptPriced(t.Context(), root, id, ledgerview.Sensitive{}, pricing)

			if rr.damage != nil {
				// Nobody may call a record with an unreadable line whole: each of the three says it did not read it all.
				if rcode == identity.ExitOK && drcErr == nil {
					t.Errorf("tego receipt exit %d (%q) and the Receipt tab (%v) both call a record with an unreadable line whole", rcode, rerr, drcErr)
				}
				if scode == identity.ExitOK && !strings.Contains(sout, "ledger_anomalies") && serr == "" {
					t.Errorf("tego status calls a record with an unreadable line whole: %s", sout)
				}
				if runErr == nil && drun.Bad == 0 && drun.ReadError == "" {
					t.Error("the dashboard's read model counts no unreadable line")
				}
				return
			}
			if rcode != identity.ExitOK || scode != identity.ExitOK || runErr != nil || drcErr != nil {
				t.Fatalf("receipt %d %q, status %d %q, run %v, dashboard receipt %v", rcode, rerr, scode, serr, runErr, drcErr)
			}
			var cli map[string]any
			if err := json.Unmarshal([]byte(rout), &cli); err != nil {
				t.Fatal(err)
			}
			delete(cli, "binding") // only `tego receipt --json` binds the receipt to its record
			var dash map[string]any
			b, err := json.Marshal(drc)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &dash); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cli, dash) {
				t.Errorf("the dashboard's receipt is not the terminal's:\n terminal  %s\n dashboard %s", mustJSON(cli), mustJSON(dash))
			}

			var st statusJSON
			if err := json.Unmarshal([]byte(sout), &st); err != nil {
				t.Fatal(err)
			}
			if st.State != "done" || st.Tier != drc.Tier || st.Tier != drun.Tier || st.Events != drc.Lines || st.Events != drun.Lines {
				t.Errorf("state %q tier %q/%q/%q lines status %d receipt %d dashboard %d", st.State, st.Tier, drc.Tier, drun.Tier, st.Events, drc.Lines, drun.Lines)
			}
			if drc.Ended != drun.Ended || drc.EndReason != drun.EndReason || st.ExitReason != drc.EndReason ||
				(drc.ExitCode != nil && (st.ExitCode == nil || *st.ExitCode != *drc.ExitCode || drun.ExitCode != *drc.ExitCode)) {
				t.Errorf("how it ended: receipt %v %q %v, status %q %v, dashboard %v %q %d", drc.Ended, drc.EndReason, drc.ExitCode, st.ExitReason, st.ExitCode, drun.Ended, drun.EndReason, drun.ExitCode)
			}
			if drc.Refusals.Total != drun.Refusals {
				t.Errorf("refusals: receipt %d, dashboard %d", drc.Refusals.Total, drun.Refusals)
			}
			if drc.Asks.Asked != drun.Asks {
				t.Errorf("asked: receipt %d, dashboard %d", drc.Asks.Asked, drun.Asks)
			}
			// A run that ended waits for nothing: the asks it left open are unanswered in the receipt, never pending.
			if st.PendingApprovals != 0 || len(drun.Pending) != 0 {
				t.Errorf("an ended run is waiting: status %d, dashboard %d pending", st.PendingApprovals, len(drun.Pending))
			}
			// The gaps: the capture gap lines the receipt counts are the ones status tallies.
			captureLines := 0
			for _, g := range st.Gaps {
				if g.What == "capture" {
					captureLines += g.Events
				}
			}
			checkOneVocabulary(t, drc, st, captureLines)
			if m := rr.malformed; m != nil {
				checkMalformedAsks(t, root, id, m, drc, drun, st)
			}
			if rr.name == "priced" && (drc.Tokens.Unpriced != 0 || !strings.Contains(drc.Tokens.CostText, "4.50")) {
				t.Errorf("the dashboard's receipt did not price the run as the terminal does: %+v", drc.Tokens)
			}
		})
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// checkMalformedAsks holds every reader of a run's asks to the same story for a record whose asks are malformed: the
// receipt, tego status, the dashboard (its read model, its signal and its refused lines) and the lookup behind
// `tego ask <run> <ask_id>` count the same asked, approved and unanswered, and each shows the repeated asks and the
// unpaired answers in askpair's words, with the same counts.
func checkMalformedAsks(t *testing.T, root, id string, m *malformedAsks, rc *ledgerview.Receipt, run *ledgerview.Run, st statusJSON) {
	t.Helper()
	// The receipt.
	if rc.Asks.Asked != m.asked || rc.Asks.Approved != m.approved || rc.Asks.Unanswered != m.unanswered {
		t.Errorf("receipt: asked %d approved %d unanswered %d; want %d %d %d", rc.Asks.Asked, rc.Asks.Approved, rc.Asks.Unanswered, m.asked, m.approved, m.unanswered)
	}
	repeated, unpaired := 0, 0
	for _, g := range rc.Coverage.Gaps {
		if g.Field != "asks" {
			continue
		}
		var n int
		fields := strings.Fields(g.Why[strings.Index(g.Why, "(")+1:])
		n, _ = strconv.Atoi(fields[0])
		switch {
		case strings.HasPrefix(g.Why, askpair.RepeatedWords):
			repeated = n
		case strings.HasPrefix(g.Why, askpair.UnpairedWords):
			unpaired = n
		}
	}
	if repeated != m.repeated || unpaired != m.unpaired {
		t.Errorf("receipt notes: %d repeated, %d unpaired; want %d, %d (%+v)", repeated, unpaired, m.repeated, m.unpaired, rc.Coverage.Gaps)
	}
	// tego status.
	said := strings.Join(st.LedgerAnomalies, "\n")
	for words, n := range map[string]int{askpair.RepeatedWords: m.repeated, askpair.UnpairedWords: m.unpaired} {
		if (n > 0) != strings.Contains(said, words+" ("+strconv.Itoa(n)+" line") {
			t.Errorf("status anomalies %q: want %q said for %d lines", said, words, n)
		}
	}
	// The dashboard: its ask count, its approvals and its refused lines.
	if run.Asks != m.asked || len(run.Pending) != 0 {
		t.Errorf("dashboard: %d asks, %d waiting", run.Asks, len(run.Pending))
	}
	approved, unanswered := 0, 0
	for _, a := range ledgerview.Signal(run, ledgerview.Sensitive{}).Approvals {
		switch a.State {
		case "approved":
			approved++
		case "unanswered":
			unanswered++
		}
	}
	if approved != m.approved || unanswered != m.unanswered {
		t.Errorf("dashboard approvals: %d approved %d unanswered; want %d %d", approved, unanswered, m.approved, m.unanswered)
	}
	r2, u2 := 0, 0
	for _, le := range run.LineErrors {
		switch {
		case strings.Contains(le.Reason, askpair.RepeatedWords):
			r2++
		case strings.Contains(le.Reason, askpair.UnpairedWords):
			u2++
		}
	}
	if r2 != m.repeated || u2 != m.unpaired {
		t.Errorf("dashboard refused lines: %d repeated, %d unpaired; want %d, %d (%+v)", r2, u2, m.repeated, m.unpaired, run.LineErrors)
	}
	// The lookup behind `tego ask <run> <ask_id>`, over the ids the run names.
	r3, u3 := 0, 0
	for _, ask := range m.ids {
		rec := recordedAsk(filepath.Join(root, id), ask)
		r3, u3 = r3+rec.Repeated, u3+rec.Unpaired
		if (rec.Repeated > 0 && !strings.Contains(rec.words(true), askpair.RepeatedWords)) ||
			(rec.Unpaired > 0 && !strings.Contains(rec.words(true), askpair.UnpairedWords)) {
			t.Errorf("ask lookup words for %s: %q", ask, rec.words(true))
		}
	}
	if r3 != m.repeated || u3 != m.unpaired {
		t.Errorf("ask lookup: %d repeated, %d unpaired; want %d, %d", r3, u3, m.repeated, m.unpaired)
	}
}

// checkOneVocabulary holds the words of a gap to one sentence in the three readers (C175, C165): the receipt's coverage
// note, `tego status`'s "in words" line and the sentences gaps and the specification own. A class of gap the receipt
// reports (capture gaps, lines that may have lost actions) is said in the receipt and in status in the same words, and a
// receipt's every gap carries its code's level.
func checkOneVocabulary(t *testing.T, rc *ledgerview.Receipt, st statusJSON, captureLines int) {
	t.Helper()
	said := map[string]string{}
	for _, g := range rc.Coverage.Gaps {
		said[g.Code] = g.Why
		if g.Level != receiptspec.LevelOf(g.Code) || receiptspec.Means(g.Code) == "" {
			t.Errorf("coverage gap %s/%s: level %q (the specification says %q), sentence %q", g.Field, g.Code, g.Level, receiptspec.LevelOf(g.Code), receiptspec.Means(g.Code))
		}
	}
	// The capture gap lines the receipt counts are the ones status tallies, in one sentence.
	if (captureLines > 0) != (said[receiptspec.CodeCaptureGap] != "") ||
		(captureLines > 0 && said[receiptspec.CodeCaptureGap] != gaps.CaptureWords(captureLines)) {
		t.Errorf("capture gap lines: status %d, receipt %q", captureLines, said[receiptspec.CodeCaptureGap])
	}
	for _, code := range []string{receiptspec.CodeCaptureGap, receiptspec.CodeMissedActions} {
		if why := said[code]; why != "" && !strings.Contains(st.GapWords, why) {
			t.Errorf("the receipt says %q (%s) and tego status says %q", why, code, st.GapWords)
		}
	}
	if said[receiptspec.CodeMissedActions] == "" && strings.Contains(st.GapWords, "in the record (counts are a minimum") {
		t.Errorf("tego status counts gaps in the record the receipt does not: %q", st.GapWords)
	}
}
