// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const runID = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"

func writeRun(t *testing.T, evs ...*record.Event) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, runID)
	w, err := ledger.Open(dir, record.RunRef{ID: runID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if err := w.Append(e); err != nil {
			t.Fatalf("append %s: %v", e.Kind, err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func reader(t *testing.T, dir string) *ledger.Reader {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// eventsJSON renders every matching event of the run in dir with events.JSONOf.
func eventsJSON(t *testing.T, w io.Writer, dir string, f events.Filter) (int, error) {
	r := reader(t, dir)
	return events.JSONOf(t.Context(), w, r, r.Entries(), f)
}

// eventsTable renders every matching event of the run in dir with events.TableOf.
func eventsTable(t *testing.T, w io.Writer, dir string, f events.Filter) (int, error) {
	r := reader(t, dir)
	return events.TableOf(t.Context(), w, r, r.Entries(), f)
}

// keyringRefusal is the line supervisor/keyring.go writes when it refuses add_key: a refused-kind event
// with no action event it mirrors.
func keyringRefusal(t *testing.T) *record.Event {
	e := &record.Event{Kind: record.KindRefused, Source: record.SourceSupervisor, PID: 7, TID: 7,
		Rule: "keyring", Reason: record.ReasonReadDenied}
	if err := e.SetPayload(record.RefusedPayload{Op: "add_key", Reason: record.ReasonReadDenied, Rule: "keyring"}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestViewStandaloneRefusalInvisibleToDriftAndMeasure(t *testing.T) {
	dir := writeRun(t, keyringRefusal(t))
	rep, err := drift.ComputeCtx(t.Context(), reader(t, dir), &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := measure.ComputeAt(t.Context(), reader(t, dir), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Drifted() || m.Refused != 1 {
		t.Fatalf("ledger holds a refusal (keyring add_key) but drift.Drifted()=%v and measure.Refused=%d", rep.Drifted(), m.Refused)
	}
}

func TestViewTerminalEscapesReachEventsTable(t *testing.T) {
	fs := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 7, TID: 7,
		Rule: "fs.write[./out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
		Attr: record.Unattributed()}
	// ESC[1A ESC[2K: cursor up one line, erase it — the previous row (a refusal) vanishes on the terminal.
	if err := fs.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/work/out/x\x1b[1A\x1b[2K\rforged"}); err != nil {
		t.Fatal(err)
	}
	dir := writeRun(t, fs)
	var out bytes.Buffer
	if _, err := eventsTable(t, &out, dir, events.Filter{}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Fatalf("raw ESC from an agent-chosen path reaches the operator's terminal:\n%q", out.String())
	}
}

// The per-binary gap the uprobe source writes (count = processes of that binary, uprobe.go Gaps add(...,1))
// and the topology gap the supervisor writes (Count: 1, nothing dropped) both render as "events lost".
func TestViewGapCountRenderedAsEventsLost(t *testing.T) {
	g := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 7, TID: 7}
	_ = g.SetPayload(record.GapPayload{What: record.GapCapture, Why: "static-tls-no-symbols", Binary: "/usr/bin/claude", Count: 3})
	dir := writeRun(t, g)
	rep, err := drift.ComputeCtx(t.Context(), reader(t, dir), &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	line := gapsLine(rep)
	if strings.Contains(line, "events lost") {
		t.Fatalf("three uncaptured processes rendered as %q", line)
	}
}

func fsAt(t *testing.T, mono uint64) *record.Event {
	e := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 7, TID: 7, MonoNS: mono,
		Rule: "fs.write[./out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule, Attr: record.Unattributed()}
	_ = e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/work/out/a"})
	return e
}

// status' idle vs limits.Watcher's stall on one live ledger: the watcher ignores a gap event (R4) and takes the
// largest reading; status takes the last line's reading, gap included.
func TestViewStatusIdleDisagreesWithWatcher(t *testing.T) {
	const s = uint64(1e9)
	gap := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 7, TID: 7, MonoNS: 300 * s}
	_ = gap.SetPayload(record.GapPayload{What: record.GapRecord, Why: "channel-full", Count: 4})
	root := filepath.Join(t.TempDir(), "runs")
	_ = os.MkdirAll(root, 0o700)
	dir := filepath.Join(root, runID)
	w, err := ledger.Open(dir, record.RunRef{ID: runID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(record.RunEndPayload{Reason: "exit"})
	st := record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"x"}, Limits: &record.Limits{StallAfter: "120s"}}
	ev := &record.Event{Kind: record.KindRunStart, Source: record.SourceSupervisor, PID: 7, TID: 7, MonoNS: 100 * s}
	_ = ev.SetPayload(st)
	if err := w.Append(ev); err != nil {
		t.Fatal(err)
	}
	for _, e := range []*record.Event{fsAt(t, 200*s), gap} {
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	// now = 400 s: the agent last did something at 200 s, 200 s ago > stall_after 120 s. The watcher,
	// which skips the gap, has LastEventMonoNS=200s and kills; status reads the gap's 300s reading.
	snap, err := statusDerive(reader(t, dir), 400*s)
	if err != nil {
		t.Fatal(err)
	}
	if snap != "stalled" {
		t.Fatalf("status says %q while the watcher's R4 (gap excluded) says stalled", snap)
	}
}

// events --json streams a line Decode refuses (v:2, a kind outside the closed set); the table, status,
// measure and drift all stop there with ErrCorruptLedger.
func TestViewEventsJSONSkipsDecode(t *testing.T) {
	dir := writeRun(t)
	b, _ := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	lines := bytes.SplitAfter(b, []byte("\n"))
	bad := bytes.Replace(lines[0], []byte(`{"v":1,`), []byte(`{"v":2,`), 1)
	bad = bytes.Replace(bad, []byte(`"kind":"run_start"`), []byte(`"kind":"bogus"`), 1)
	data := append(append(append([]byte{}, lines[0]...), bad...), lines[1]...)
	d2 := t.TempDir()
	_ = os.WriteFile(filepath.Join(d2, ledger.EventsFile), data, 0o600)
	var tbl, js bytes.Buffer
	_, terr := eventsTable(t, &tbl, d2, events.Filter{})
	n, jerr := eventsJSON(t, &js, d2, events.Filter{})
	if (terr == nil) != (jerr == nil) {
		t.Fatalf("table err=%v; json err=%v after writing %d lines:\n%s", terr, jerr, n, js.String())
	}
}

func TestViewSharedTracingIsUncertainRatherThanEventsLost(t *testing.T) {
	e := &record.Event{Kind: record.KindGap, Source: record.SourceKernel}
	if err := e.SetPayload(record.GapPayload{What: record.GapRecord, Why: "bpf-trampoline-miss/shared-build", Count: 17}); err != nil {
		t.Fatal(err)
	}
	dir := writeRun(t, e)
	rep, err := drift.ComputeCtx(t.Context(), reader(t, dir), &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	text := gapsLine(rep)
	if strings.Contains(text, "events lost") || !strings.Contains(text, "17") || !strings.Contains(text, "other runs or ungoverned tasks") {
		t.Fatalf("drift loses the shared counter's meaning: %s", text)
	}
}
