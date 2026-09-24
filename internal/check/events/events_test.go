// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fixtureReader opens the frozen v1 fixture ledger as a run directory. The fixture is the contract every
// view is built against (docs/P0-DESIGN.md §10), so the views can be written and tested before the runtime
// emits a single real event.
func fixtureReader(t *testing.T) *ledger.Reader {
	t.Helper()
	src := filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open fixture reader: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestJSONIsByteForByteWhatTheLedgerStored(t *testing.T) {
	r := fixtureReader(t)
	var out bytes.Buffer
	n, err := JSON(t.Context(), &out, r, Filter{})
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if n == 0 {
		t.Fatal("no events written")
	}
	src, err := os.ReadFile(filepath.Join(r.Dir(), ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	// Every line must come back exactly as stored: the chain hashed those bytes, so a caller can verify a
	// line copied out of this output. Re-encoding a decoded event could differ and would break that.
	if !bytes.Equal(bytes.TrimRight(src, "\n"), bytes.TrimRight(out.Bytes(), "\n")) {
		t.Error("JSON output is not byte-identical to the stored ledger")
	}
}

func TestFilterKindAndVerdict(t *testing.T) {
	r := fixtureReader(t)
	var out bytes.Buffer
	n, err := JSON(t.Context(), &out, r, Filter{Kinds: []record.Kind{record.KindFS}, Verdicts: []record.Verdict{record.VerdictRefused}})
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if n == 0 {
		t.Fatal("the fixture has a refused fs event; the filter found none")
	}
	for line := range strings.SplitSeq(strings.TrimRight(out.String(), "\n"), "\n") {
		var e record.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Kind != record.KindFS || e.Verdict != record.VerdictRefused {
			t.Errorf("filter let through kind=%s verdict=%s", e.Kind, e.Verdict)
		}
	}
}

func TestFilterLimitStopsEarly(t *testing.T) {
	r := fixtureReader(t)
	var out bytes.Buffer
	n, err := JSON(t.Context(), &out, r, Filter{Limit: 3})
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if n != 3 || strings.Count(strings.TrimRight(out.String(), "\n"), "\n") != 2 {
		t.Errorf("limit 3 produced %d events", n)
	}
}

func TestParseFilterRejectsUnknownValues(t *testing.T) {
	for _, tc := range []struct{ name, kind, source, verdict string }{
		{"kind", "fss", "", ""},
		{"source", "", "kernal", ""},
		{"verdict", "", "", "allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var kinds, sources, verdicts []string
			if tc.kind != "" {
				kinds = []string{tc.kind}
			}
			if tc.source != "" {
				sources = []string{tc.source}
			}
			if tc.verdict != "" {
				verdicts = []string{tc.verdict}
			}
			// A typo must be an error: silently matching nothing would read as "the run did not do that".
			if _, err := ParseFilter(kinds, sources, verdicts, nil, nil, 0); err == nil {
				t.Error("no error for an unknown value")
			}
		})
	}
}

func TestTableRendersEveryFixtureEvent(t *testing.T) {
	r := fixtureReader(t)
	var out bytes.Buffer
	n, err := Table(t.Context(), &out, r, Filter{})
	if err != nil {
		t.Fatalf("Table: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != n+1 {
		t.Fatalf("%d rows for %d events (plus a header)", len(lines), n)
	}
	if !strings.HasPrefix(lines[0], "SEQ") {
		t.Errorf("header = %q", lines[0])
	}
	for i, l := range lines[1:] {
		if strings.TrimSpace(l) == "" {
			t.Errorf("row %d is blank", i)
		}
	}
}

func TestSummaryCoversEveryKindInTheFixture(t *testing.T) {
	r := fixtureReader(t)
	seen := map[record.Kind]bool{}
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		seen[e.Kind] = true
		// A view must not fail on a payload a newer writer extended; Summary reads leniently and returns
		// "" rather than panicking on a missing or differently typed field.
		_ = Summary(e)
	}
	for _, k := range []record.Kind{record.KindRunStart, record.KindExec, record.KindFS, record.KindNet, record.KindRunEnd} {
		if !seen[k] {
			t.Errorf("fixture has no %s event; the views are built against it", k)
		}
	}
}

func TestSummaryToleratesAMissingPayload(t *testing.T) {
	for _, k := range record.Kinds {
		if got := Summary(&record.Event{Kind: k}); strings.Contains(got, "panic") {
			t.Errorf("%s: %q", k, got)
		}
	}
}

// TestSummaryShowsWhatAnExecRan: argv is a JSON array, and reading it as a string made every exec's summary
// its binary alone.
func TestSummaryShowsWhatAnExecRan(t *testing.T) {
	e := &record.Event{Kind: record.KindExec}
	if err := e.SetPayload(record.ExecPayload{Path: "/usr/bin/rg", Argv: []string{"rg", "-n", "needle"}}); err != nil {
		t.Fatal(err)
	}
	if got := Summary(e); got != "rg -n needle" {
		t.Errorf("Summary = %q, want the argv", got)
	}
	bare := &record.Event{Kind: record.KindExec}
	if err := bare.SetPayload(record.ExecPayload{Path: "/usr/bin/rg"}); err != nil {
		t.Fatal(err)
	}
	if got := Summary(bare); got != "/usr/bin/rg" {
		t.Errorf("Summary with no argv = %q, want the path", got)
	}
}

func TestSummaryKeepsFractionalLimitValues(t *testing.T) {
	e := &record.Event{Kind: record.KindLimit, Payload: []byte(`{"which":"cost_usd","value":0.52,"ceiling":0.5}`)}
	if got, want := Summary(e), "cost_usd=0.52 ceiling=0.5"; got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
	e = &record.Event{Kind: record.KindLimit, Payload: []byte(`{"which":"tokens","value":3,"ceiling":1e19}`)}
	if got := Summary(e); strings.Contains(got, "-9223372036854775808") {
		t.Errorf("Summary overflowed: %q", got)
	}
	e = &record.Event{Kind: record.KindAnswer, Payload: []byte(`{"by":"human","after_s":0.4}`)}
	if got := Summary(e); !strings.Contains(got, "after 0.4s") {
		t.Errorf("Summary = %q, want after 0.4s", got)
	}
}

// A held read and an alternate read plainly: the ask says read, the answer names the alternate,
// and the open it completed names the file delivered and the one it stands for.
func TestSummarySaysHeldReadsAndAlternates(t *testing.T) {
	for _, tc := range []struct {
		kind    record.Kind
		payload string
		want    string
	}{
		{record.KindAsk, `{"ask_id":"q-1","hold":"open","op":"read","target":"/home/u/.aws/credentials"}`, "open read /home/u/.aws/credentials"},
		{record.KindAsk, `{"ask_id":"q-1","hold":"open","op":"open","target":"/w/held/a"}`, "open /w/held/a"},
		{record.KindAnswer, `{"ask_id":"q-1","by":"uid:1000 pid:7","after_s":2,"approved":false,"alternate":"/home/u/fake","alternate_dev":2049,"alternate_ino":7}`, "alternate /home/u/fake (not the file asked for) by uid:1000 pid:7 after 2s"},
		{record.KindAnswer, `{"ask_id":"q-1","by":"standing:q-0","after_s":0,"approved":false,"alternate":"/home/u/fake"}`, "alternate /home/u/fake (not the file asked for) by standing:q-0 after 0s"},
		{record.KindAnswer, `{"ask_id":"q-1","by":"uid:1000 pid:7","after_s":2,"approved":true}`, "approved by uid:1000 pid:7 after 2s"},
		{record.KindAnswer, `{"ask_id":"q-1","by":"timeout","after_s":300,"approved":false,"answer_reason":"ask-timeout"}`, "refused ask-timeout by timeout after 300s"},
		{record.KindAnswer, `{"ask_id":"q-1","by":"human","after_s":1}`, "by human after 1s"},
		{record.KindFS, `{"op":"open","path":"/home/u/fake","alternate_for":"/home/u/.aws/credentials"}`, "open /home/u/fake (alternate for /home/u/.aws/credentials)"},
	} {
		if got := Summary(&record.Event{Kind: tc.kind, Payload: []byte(tc.payload)}); got != tc.want {
			t.Errorf("%s: Summary = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

// An mcp line says which server and, for a tool call, which tool (capture-derive.md R41): "mcp call
// db_query".
func TestSummarySaysMCPCalls(t *testing.T) {
	for payload, want := range map[string]string{
		`{"name":"postgres","command":["mcp-postgres"],"transport":"stdio"}`: "postgres stdio",
		`{"name":"postgres","transport":"http"}`:                             "postgres http",
		`{"name":"postgres","transport":"http","tool":"db_query"}`:           "postgres http call db_query",
	} {
		if got := Summary(&record.Event{Kind: record.KindMCP, Payload: []byte(payload)}); got != want {
			t.Errorf("Summary(%s) = %q, want %q", payload, got, want)
		}
	}
}
