// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestReceiptWordsOneRecordBothSurfaces: for one record, each sentence tego receipt says about a run's connections and
// refusals is on the Receipt tab word for word, from the receipt's own methods (NoConnectionWords, RoutineAlsoWords,
// RefusedWords, NoneOverTime), so the two cannot drift apart again. The tab had its own copy of each: "None recorded,
// besides routine socket calls that name no place." where tego receipt said "None, besides 2 routine socket calls
// that name no place (...)", and "Nothing refused" under Refusals over time and on the Refused tile for a run that
// does not record its refused reads (GAPS C58, C60). The words themselves are pinned here once, for both.
func TestReceiptWordsOneRecordBothSurfaces(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Millisecond) }
	const (
		unspec   = `"rule":"net.unspec","verdict":"observed","dst":"unspec","proto":"udp"`
		netlink  = `"rule":"route-query","verdict":"allow","dst":"family(16)","proto":"raw"`
		place    = `"rule":"unmatched","verdict":"observed","dst":"151.101.0.223:443","proto":"tcp"`
		lookup   = `"rule":"unmatched","verdict":"observed","dst":"unix:/run/systemd/userdb/io.systemd.DynamicUser","proto":"unix"`
		refused  = `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`
		readsOff = `,"reads_notified":{"notified":false,"why":"reason-off"}`
		readsOn  = `,"reads_notified":{"notified":true,"why":"reason"}`
	)
	type line struct{ kind, extra string }
	for i, c := range []struct {
		name  string
		tier  string
		start string
		lines []line
		// want are the receipt's sentences for this record, as both surfaces must print them; notOnTab are the tab's
		// old words, which no longer stand beside them.
		want     []string
		notOnTab []string
	}{
		{name: "nothing", tier: "observe", want: []string{"None recorded.", "Nothing was refused.", "None to show."}},
		{name: "routine sockets, no place", tier: "observe", lines: []line{{"net", unspec}, {"net", netlink}},
			want:     []string{"None, besides 2 routine socket calls that name no place (disconnects with AF_UNSPEC, the kernel's netlink socket)."},
			notOnTab: []string{"None recorded, besides"}},
		{name: "a place, a lookup and a reset", tier: "observe", lines: []line{{"net", place}, {"net", lookup}, {"net", unspec}},
			want: []string{"Also 1 routine system lookup (the name and user lookups any program makes), not counted above.",
				"Also 1 routine socket call that names no place (disconnects with AF_UNSPEC, the kernel's netlink socket), not counted above."}},
		{name: "refused reads unrecorded, none refused", tier: "landlock", start: readsOff,
			want:     []string{"No recorded action was refused; this run does not record refused reads (see Sensitive files read).", "None to show."},
			notOnTab: []string{"Nothing was refused.", "Nothing refused", "nothing refused"}},
		{name: "refused reads unrecorded, one refused", tier: "landlock", start: readsOff, lines: []line{{"refused", refused}},
			want: []string{"This run does not record refused reads, so a read it refused is not counted (see Sensitive files read)."}},
		{name: "refused reads recorded, none refused", tier: "landlock", start: readsOn,
			want: []string{"Nothing was refused.", "None to show."}, notOnTab: []string{"does not record refused reads"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := fmt.Sprintf("r-aaaaaaaa-00000000000%02d-rcword", 80+i)
			ls := []string{lineOf(run, 0, at(0), "run_start", `"tier":"`+c.tier+`","command":["python3","fetch.py"],"cwd":"/w"`+c.start)}
			for _, l := range c.lines {
				ls = append(ls, lineOf(run, len(ls), at(len(ls)), l.kind, l.extra))
			}
			ls = append(ls, lineOf(run, len(ls), at(len(ls)), "run_end", `"reason":"exit","exit_code":0`))
			page, text, rc := receiptBoth(t, run, ls...)
			said := append([]string{rc.NoConnectionWords(), rc.RefusedWords()}, rc.RoutineAlsoWords()...)
			if rc.Refusals.Total == 0 {
				said = append(said, receipt.NoneOverTime)
			}
			for _, w := range c.want {
				if !slices.Contains(said, w) {
					t.Errorf("the receipt's own words %q lack %q", said, w)
				}
			}
			for _, w := range said {
				if w == "" {
					continue
				}
				if !strings.Contains(text, "  "+w+"\n") {
					t.Errorf("tego receipt does not print %q:\n%s", w, text)
				}
				if !strings.Contains(page, ">"+html.EscapeString(w)+"</p>") {
					t.Errorf("the Receipt tab does not show %q", w)
				}
			}
			for _, w := range c.notOnTab {
				if strings.Contains(page, html.EscapeString(w)) {
					t.Errorf("the Receipt tab still says %q", w)
				}
			}
		})
	}
}

// TestRefusedTileSaysWhenRefusedReadsAreNotRecorded: the Receipt tab's Refused tile said "nothing refused" under a 0
// for a run whose refused reads leave no line, where tego receipt says no recorded action was refused (GAPS C60 (b)).
// It reads the receipt's RefusedReadsUnrecorded, as the sentence does.
func TestRefusedTileSaysWhenRefusedReadsAreNotRecorded(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000090-rctile"
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	page, _, rc := receiptBoth(t, run,
		lineOf(run, 0, t0, "run_start", `"tier":"landlock","command":["cat","secret.txt"],"cwd":"/w","reads_notified":{"notified":false,"why":"reason-off"}`),
		lineOf(run, 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":1`))
	if !rc.RefusedReadsUnrecorded() {
		t.Fatal("the receipt does not say refused reads are unrecorded")
	}
	const want = `<span class="rc-k">Refused</span><span class="rc-v">0</span><span class="rc-s">refused reads not recorded</span>`
	if !strings.Contains(page, want) {
		t.Errorf("the Refused tile is not %q", want)
	}
}

// TestKernelTLSLineIsBuiltInOnEveryPage: tego receipt, tego run's summary and the Receipt tab name tego's built-in
// refusal of setsockopt(TCP_ULP, "tls") "built in: kernel TLS", and every other page that names one line's rule (a
// run's timeline, its Refusals tab grouped and line by line, Logs, Detections) still called it "Not in contract", the
// default deny the record files it under, as if a rule could allow it (GAPS C59). Each now reads the receipt's rule,
// receipt.BuiltInRefusal, and a real refused connect of the same run keeps the default deny's words.
func TestKernelTLSLineIsBuiltInOnEveryPage(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000091-ktlspg"
	tls := `"rule":"unmatched","reason":"net-not-allowed","op":"setsockopt","target":"TCP_ULP \"tls\""`
	root := detectionsRoot(t, run, "landlock", [2]string{"refused", tls}, [2]string{"refused", tls},
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	rc, err := ledgerview.LoadReceipt(context.Background(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	kind := receipt.BuiltInRefusal("setsockopt", `TCP_ULP "tls"`, "unmatched", "net-not-allowed")
	if kind != "built in: kernel TLS" || rc.BuiltInKind(rc.Refusals.List[0]) != kind {
		t.Fatalf("the receipt's kind is %q, its first refusal's %q", kind, rc.BuiltInKind(rc.Refusals.List[0]))
	}
	s := newServer(t, root)
	c := login(t, s)
	for _, path := range []string{"/runs/" + run, "/runs/" + run + "/refusals", "/runs/" + run + "/refusals?view=lines",
		"/logs?run=" + run, "/detections", "/runs/" + run + "/receipt"} {
		page := get(t, s, c, path)
		if !strings.Contains(page, kind) {
			t.Errorf("%s does not name the kernel-TLS refusal %q", path, kind)
		}
	}
	// Line by line, each TCP_ULP line's own row names it built in, and the connect's row names the default deny.
	page := get(t, s, c, "/logs?run="+run)
	rows := strings.Split(page, `<tr role="row"`)
	var tlsRows, connRows int
	for _, r := range rows {
		switch {
		case strings.Contains(r, "TCP_ULP"):
			tlsRows++
			if !strings.Contains(r, kind) || strings.Contains(r, ruleName("unmatched")) {
				t.Errorf("a TCP_ULP row of Logs does not read %q alone:\n%s", kind, r)
			}
		case strings.Contains(r, "203.0.113.9:"):
			connRows++
			if strings.Contains(r, kind) {
				t.Errorf("the connect's row of Logs reads %q", kind)
			}
		}
	}
	if tlsRows == 0 || connRows == 0 {
		t.Errorf("Logs showed %d TCP_ULP rows and %d connect rows", tlsRows, connRows)
	}
}

// TestLogsSaysTheKernelTLSRefusalAsTheReceiptDoes: the Logs page named a refused kernel-TLS probe "built in: kernel TLS"
// in its Rule cell, but its why-line said "not on the allowed hosts" and its Rule facet counted it under "Not in
// contract" (acceptance 2B, 2026-11-11; GAPS C59). Both now read the receipt's own words: the row's why-line is the
// sentence tego receipt prints for it (receipt.BuiltInWords), the facet counts it under its built-in kind, and the
// facet's query keeps the two apart, so "Not in contract" counts and lists only the refused connect. The facet's
// counts are the receipt's by-rule counts (rc.RefusalGroups), so a drift between the two fails here.
func TestLogsSaysTheKernelTLSRefusalAsTheReceiptDoes(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000092-ktlslg"
	tls := `"rule":"unmatched","reason":"net-not-allowed","op":"setsockopt","target":"TCP_ULP \"tls\""`
	root := detectionsRoot(t, run, "landlock", [2]string{"refused", tls}, [2]string{"refused", tls},
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	rc, err := ledgerview.LoadReceipt(context.Background(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	kind := receipt.BuiltInRefusal("setsockopt", `TCP_ULP "tls"`, "unmatched", "net-not-allowed")
	words := receipt.BuiltInWords("setsockopt", `TCP_ULP "tls"`, "unmatched", "net-not-allowed")
	if kind == "" || !strings.HasPrefix(words, "built in, no rule allows it: kernel TLS") {
		t.Fatalf("the receipt's kind %q, words %q", kind, words)
	}
	var text strings.Builder
	if err := rc.Text(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), words) {
		t.Fatalf("tego receipt does not print %q:\n%s", words, text.String())
	}
	s := newServer(t, root)
	c := login(t, s)
	page := get(t, s, c, "/logs?run="+run)
	for _, r := range strings.Split(page, `<tr role="row"`) {
		if strings.Contains(r, "TCP_ULP") && (!strings.Contains(r, html.EscapeString(words)) || strings.Contains(r, "not on the allowed hosts")) {
			t.Errorf("a TCP_ULP row's why-line is not the receipt's %q:\n%s", words, r)
		}
		if strings.Contains(r, "203.0.113.9:") && !strings.Contains(r, "not on the allowed hosts") {
			t.Errorf("the connect's why-line changed:\n%s", r)
		}
	}
	// The facet's counts are the receipt's by-rule counts.
	want := map[string]int{}
	for _, g := range rc.RefusalGroups() {
		label := ruleName(g.Rule)
		if g.BuiltIn {
			label = g.Kind
		}
		want[label] += g.Count
	}
	if want[kind] != 2 || want[ruleName("unmatched")] != 1 {
		t.Fatalf("the receipt's groups: %v", want)
	}
	for label, n := range want {
		facet := `<span class="lq-l">` + html.EscapeString(label) + `</span><span class="lq-n">` + strconv.Itoa(n) + `</span>`
		if !strings.Contains(page, facet) {
			t.Errorf("the Rule facet does not count %q %d as the receipt does", label, n)
		}
	}
	// By rule gathers them apart from the default deny, under the same words.
	if page := get(t, s, c, "/logs?run="+run+"&group=rule"); !strings.Contains(page, html.EscapeString(kind)) {
		t.Errorf("By rule has no %q group", kind)
	}
	// Each facet value's query lists the lines it counts, and only those.
	for q, wantTLS := range map[string]bool{`rule:"` + kind + `"`: true, "rule:unmatched": false} {
		page := get(t, s, c, "/logs?run="+run+"&where="+url.QueryEscape(q))
		var tlsRows, connRows int
		for _, r := range strings.Split(page, `<tr role="row"`)[1:] {
			switch {
			case strings.Contains(r, "TCP_ULP"):
				tlsRows++
			case strings.Contains(r, "203.0.113.9:"):
				connRows++
			}
		}
		if (wantTLS && (tlsRows == 0 || connRows != 0)) || (!wantTLS && (tlsRows != 0 || connRows == 0)) {
			t.Errorf("%s lists %d TCP_ULP rows and %d connect rows", q, tlsRows, connRows)
		}
	}
}

// receiptBoth writes one run of lines under a fresh root and returns the Receipt tab, `tego receipt`'s text and the
// receipt both are made from.
func receiptBoth(t *testing.T, run string, lines ...string) (page, text string, rc *ledgerview.Receipt) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(lines, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, err := ledgerview.LoadReceipt(context.Background(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := rc.Text(&b); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	return get(t, s, login(t, s), "/runs/"+run+"/receipt"), b.String(), rc
}

// lineOf is line for an agent named py.
func lineOf(run string, seq int, ts time.Time, kind, extra string) string {
	return line(run, "py", seq, ts, kind, extra)
}

// TestRefusalsTabSaysWhatTheReceiptSays: a run that refused nothing recorded. Its Refusals tab, grouped and by line,
// says the receipt's sentence for that record (RefusedWords): "Nothing was refused." only when its refused reads would
// have left a line, and otherwise that no recorded action was refused and that this run does not record refused reads.
// Both views said "Nothing refused" for every such run, beside a receipt that said the reads were not recorded (GAPS
// C60 b).
func TestRefusalsTabSaysWhatTheReceiptSays(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	for i, c := range []struct{ name, start, want string }{
		{"reads off", `,"reads_notified":{"notified":false,"why":"reason-off"}`,
			"No recorded action was refused; this run does not record refused reads (see Sensitive files read)."},
		{"reads off, capability said", `,"capabilities":{"record_reads":false},"reads_notified":{"notified":false,"why":"reason-off"}`,
			"No recorded action was refused; this run does not record refused reads (see Sensitive files read)."},
		{"reads on", `,"reads_notified":{"notified":true,"why":"reason"}`, "Nothing was refused."},
		{"kernel record", `,"reads_notified":{"notified":false,"why":"kernel"}`, "Nothing was refused."},
		{"no reads_notified", ``, "Nothing was refused."},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := fmt.Sprintf("r-aaaaaaaa-00000000001%02d-rftab", i)
			_, _, rc := receiptBoth(t, run,
				lineOf(run, 0, t0, "run_start", `"tier":"landlock","command":["cat","secret.txt"],"cwd":"/w"`+c.start),
				lineOf(run, 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":1`))
			if rc.RefusedWords() != c.want {
				t.Fatalf("tego receipt says %q, the test wants %q", rc.RefusedWords(), c.want)
			}
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(
				lineOf(run, 0, t0, "run_start", `"tier":"landlock","command":["cat","secret.txt"],"cwd":"/w"`+c.start)+
					lineOf(run, 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":1`)), 0o644); err != nil {
				t.Fatal(err)
			}
			s := newServer(t, root)
			cookie := login(t, s)
			for _, view := range []string{"", "?view=lines"} {
				pg := get(t, s, cookie, "/runs/"+run+"/refusals"+view)
				rf := pg[strings.Index(pg, `id="h-rf"`):]
				rf = rf[:strings.Index(rf, "</section>")]
				if !strings.Contains(html.UnescapeString(rf), "<h3>"+c.want+"</h3>") {
					t.Errorf("refusals%s does not say the receipt's %q:\n%s", view, c.want, rf)
				}
				if strings.Contains(rf, "Nothing refused") {
					t.Errorf("refusals%s keeps its own words, \"Nothing refused\"", view)
				}
			}
		})
	}
}
