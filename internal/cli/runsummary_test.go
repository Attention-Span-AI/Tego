// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// summaryLedger writes a finished run under root, anchored in anchor: one refused connection (with its mirroring
// refused line), one held read a person denied (its ask, answer and refused line), an observed read of an SSH key,
// three connections to one place, and a write to one file beside writes to /dev/null and the terminal. It returns the
// run id.
func summaryLedger(t *testing.T, root, anchor string) string {
	t.Helper()
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "minimal"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	// Every read recorded (record: full), so its summary has no reads line (TestReadsLineFollowsTheFieldNeverTheLevel).
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"agent"}, Cwd: "/w/proj", Tier: "landlock", Capture: "off",
		Capabilities:  map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): true},
		ReadsNotified: &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}}); err != nil {
		t.Fatal(err)
	}
	add := func(kind record.Kind, verdict record.Verdict, rule string, reason record.Reason, payload any) {
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
	}
	ask := "fs.ask_read[/home/u/.config/telemetry/]"
	add(record.KindNet, record.VerdictRefused, "unmatched", record.ReasonNetNotAllowed, record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9822"})
	add(record.KindRefused, "", "unmatched", record.ReasonNetNotAllowed,
		record.RefusedPayload{Op: "net", Target: "127.0.0.1:9822", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"})
	add(record.KindAsk, "", "", "", map[string]any{"ask_id": "q-1", "hold": "open", "op": "open",
		"target": "/home/u/.config/telemetry/token", "ask_rule": ask})
	add(record.KindAnswer, "", "", "", map[string]any{"ask_id": "q-1", "by": "uid:1000 pid:9", "after_s": 1.0, "approved": false,
		"answer_reason": "ask-denied"})
	add(record.KindFS, record.VerdictRefused, ask, record.ReasonAskDenied,
		record.FSPayload{Op: record.FSOpen, Path: "/home/u/.config/telemetry/token", Flags: 0o2000000})
	add(record.KindFS, record.VerdictAllow, "fs.read[/]", "", record.FSPayload{Op: record.FSOpen, Path: "/home/u/.ssh/id_rsa"})
	for range 3 {
		add(record.KindNet, record.VerdictAllow, "net[127.0.0.1:9823]", "", record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9823"})
	}
	for _, p := range []record.FSPayload{{Op: record.FSOpen, Path: "/dev/null", Flags: 0o1101},
		{Op: record.FSOpen, Path: "/dev/tty", Flags: 0o2}, {Op: record.FSOpen, Path: "/w/proj/out.txt", Flags: 0o1101, Created: true}} {
		add(record.KindFS, record.VerdictAllow, "fs.write[/w/proj/]", "", p)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// summaryHarness points run at a private ledger root and anchor, with a backend and no capture, and returns the root,
// the anchor and the stderr buffer the stub agent writes its own output to.
func summaryHarness(t *testing.T) (string, string) {
	t.Helper()
	requireLandlockABI(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "runs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	t.Setenv("HOME", "/home/u")
	anchor := filepath.Join(base, "chain.log")
	prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder := probeMachine, anchorPath, startRun, captureFor, recorderFor
	t.Cleanup(func() {
		probeMachine, anchorPath, startRun, captureFor, recorderFor = prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder
	})
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	anchorPath = func(*config.Machine) (string, error) { return anchor, nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	return root, anchor
}

// TestRunEndSummary: once the agent has exited, tego run's last words on stderr are the
// summary, after the agent's own output, with the receipt's numbers and a verified chain; --no-summary prints none.
func TestRunEndSummary(t *testing.T) {
	root, _ := summaryHarness(t)
	var stderr bytes.Buffer
	var id string
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		id = summaryLedger(t, root, d.AnchorPath)
		fmt.Fprintln(&stderr, "agent: my own last line") // the agent's output, which the summary must follow
		return tegoruntime.Result{RunID: id, Reason: record.RunEndExit}, nil
	}
	argv := []string{"tego", "run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--", "true"}
	if code := mainWith(t.Context(), argv, io.Discard, &stderr, []Command{cmdRun()}); code != identity.ExitOK {
		t.Fatalf("exit %d:\n%s", code, stderr.String())
	}
	out := stderr.String()
	head := "tego run: " + id + " ended (exited with code 0) · "
	i, j := strings.Index(out, "agent: my own last line"), strings.Index(out, head)
	if i < 0 || j < i {
		t.Fatalf("the summary does not follow the agent's output:\n%s", out)
	}
	summary := out[j:]
	if !strings.HasPrefix(summary, head+"tier landlock · refused 2 (") {
		t.Errorf("the summary does not name the run's tier right after how it ended:\n%s", summary)
	}
	// "wrote 1 file": the writes to /dev/null and /dev/tty are no file written (PW-12).
	for _, want := range []string{"refused 2 (", "not allowed by any rule 1", "asked 1 (0 approved, 1 denied)", "wrote 1 file · ",
		"chain verified\n"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
	if !strings.HasSuffix(out, "\n  more: tego receipt "+id+"\n") {
		t.Errorf("the summary's hint is not the last stderr output:\n%s", out)
	}
	if strings.Count(summary, "\n") != 2 {
		t.Errorf("the summary is not two lines:\n%s", summary)
	}

	stderr.Reset()
	argv = []string{"tego", "run", "--no-summary", filepath.Join("testdata", "minimal.yaml"), "--offline", "--", "true"}
	if code := mainWith(t.Context(), argv, io.Discard, &stderr, []Command{cmdRun()}); code != identity.ExitOK {
		t.Fatalf("--no-summary: exit %d:\n%s", code, stderr.String())
	}
	if out := stderr.String(); strings.Contains(out, " ended (") || strings.Contains(out, "more: tego receipt") {
		t.Errorf("--no-summary printed a summary:\n%s", out)
	}
}

// TestRunEndSummaryNamesTheTier is H08's "no tier": the summary's first line names the tier the run's run_start
// recorded, escaped for the terminal like every ledger string, and no tier for a run_start that holds none.
func TestRunEndSummaryNamesTheTier(t *testing.T) {
	zero := 0
	odd := "land\x1b[2Jlock"
	for tier, want := range map[string]string{
		"cgroup": "tego run: r1 ended (exited with code 0) · tier cgroup · refused 0 · asked 0 · chain verified\n",
		"":       "tego run: r1 ended (exited with code 0) · refused 0 · asked 0 · chain verified\n",
		odd:      "tego run: r1 ended (exited with code 0) · tier " + record.Printable(odd) + " · refused 0 · asked 0 · chain verified\n",
	} {
		s := &endSummary{run: "r1", rc: &receipt.Receipt{Tier: tier, Ended: true, ExitCode: &zero}, chain: "chain verified"}
		if got := s.text(); !strings.HasPrefix(got, want) || strings.Contains(got, "\x1b") {
			t.Errorf("tier %q: text = %q, want first line %q", tier, got, want)
		}
	}
}

// TestRunEndSummaryChainNotChecked: "chain verified" is said only after a real check; a run whose record could not
// be completed, a missing anchor, and an anchor that does not hold the run's head each say so instead.
func TestRunEndSummaryChainNotChecked(t *testing.T) {
	root, anchor := summaryHarness(t)
	id := summaryLedger(t, root, anchor)
	dir := filepath.Join(root, id)
	ctx := t.Context()
	res := tegoruntime.Result{RunID: id, Reason: record.RunEndExit}
	if got := chainClause(ctx, dir, anchor, res); got != "chain verified" {
		t.Errorf("an anchored run: %q", got)
	}
	if got := chainClause(ctx, dir, "", res); got != "chain not checked (no chain anchor)" {
		t.Errorf("no anchor: %q", got)
	}
	broken := res
	broken.RecordErr = errors.New("fsync: no space left on device")
	if got := chainClause(ctx, dir, anchor, broken); !strings.HasPrefix(got, "chain not checked (") {
		t.Errorf("an incomplete record: %q", got)
	}
	other := filepath.Join(t.TempDir(), "chain.log")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := chainClause(ctx, dir, other, res); strings.Contains(got, "verified") && !strings.Contains(got, "not") {
		t.Errorf("an anchor without the run's head: %q", got)
	}
}

// TestWatchFooterCounts: tego watch's footer says how the run ended and gains a counts line, the connections and the
// sensitive files the run read; with no summary it is the old two lines.
func TestWatchFooterCounts(t *testing.T) {
	root, anchor := summaryHarness(t)
	id := summaryLedger(t, root, anchor)
	m := &config.Machine{}
	prevRoot := ledgerRootOf
	t.Cleanup(func() { ledgerRootOf = prevRoot })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	res := tegoruntime.Result{RunID: id, Reason: record.RunEndExit}
	sum := summarizeRun(t.Context(), m, anchor, res, agent.RecordFull)
	got := watchFooter(res, sum)
	for _, want := range []string{"tego watch: recorded as run " + id + ": ended (exited with code 0) · refused 2",
		"\n  seen: 4 connections to 2 places (most: 127.0.0.1:9823) · 2 sensitive files read (first: ~/.config/telemetry/token)\n",
		"\n  more: tego receipt " + id + "    tego events " + id} {
		if !strings.Contains(got, want) {
			t.Errorf("footer lacks %q:\n%s", want, got)
		}
	}
	if old := watchFooter(res, nil); old != watchReport(res) {
		t.Errorf("footer with no summary = %q, want watchReport's", old)
	}
}

// TestWatchFooterNeverNamesASystemLookup: a real Codex under tego watch asks nscd for every name it resolves. The
// footer's "seen:" line counts the network places the receipt lists (5 nscd connects are routine system lookups,
// counted apart in the dashboard's words), and "most:" names a network place, never a unix socket, even one the run
// used more often.
func TestWatchFooterNeverNamesASystemLookup(t *testing.T) {
	root, anchor := summaryHarness(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "watch"}, ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"agent"}, Cwd: "/w/proj", Tier: "observe", Capture: "off",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): true}}); err != nil {
		t.Fatal(err)
	}
	conn := func(dst string, n int) {
		for range n {
			e := &record.Event{Kind: record.KindNet, Source: record.SourceSupervisor, PID: 1, TID: 1, Verdict: record.VerdictObserved,
				Rule: "unmatched", Attr: record.Unattributed(), Authority: record.AuthorityRule}
			if err := e.SetPayload(record.NetPayload{Proto: "tcp", Dst: dst}); err != nil {
				t.Fatal(err)
			}
			if err := w.Append(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	conn("unix:/var/run/nscd/socket", 5)
	conn("unix:/tmp/agent-helper.sock", 4)
	conn("127.0.0.1:9821", 3)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	prevRoot := ledgerRootOf
	t.Cleanup(func() { ledgerRootOf = prevRoot })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	res := tegoruntime.Result{RunID: id, Reason: record.RunEndExit}
	sum := summarizeRun(t.Context(), &config.Machine{}, anchor, res, agent.RecordFull)
	got := watchFooter(res, sum)
	if want := "\n  seen: 7 connections to 2 places (most: 127.0.0.1:9821) · no sensitive file read\n"; !strings.Contains(got, want) {
		t.Errorf("footer lacks %q:\n%s", want, got)
	}
	code, out, _ := run(t, "receipt", id)
	if code != identity.ExitOK {
		t.Fatalf("receipt exit %d", code)
	}
	for _, want := range []string{"\nConnections\n  7 connections to 2 places.\n",
		"  Also 5 routine system lookups (the name and user lookups any program makes), not counted above.\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("receipt lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(got+out, "nscd") {
		t.Errorf("the footer or the receipt names the nscd socket:\n%s\n%s", got, out)
	}
}

// TestSummaryWithoutReceiptSaysHowItEnded: when the receipt cannot be built, the summary line still says how a run
// that did not simply exit ended, as tego's one-line report did before the summary.
func TestSummaryWithoutReceiptSaysHowItEnded(t *testing.T) {
	s := &endSummary{run: "r1", how: endedHow(record.RunEndOOM), err: errors.New("no such file"), chain: "chain not checked (no chain anchor)"}
	if want := "tego run: r1 ended (out of memory) · summary not available (no such file) · chain not checked (no chain anchor)\n"; !strings.HasPrefix(s.text(), want) {
		t.Errorf("text = %q, want prefix %q", s.text(), want)
	}
	s.how = endedHow(record.RunEndExit)
	if want := "tego run: r1 ended · summary not available"; !strings.HasPrefix(s.text(), want) {
		t.Errorf("an exited run: text = %q", s.text())
	}
	res := tegoruntime.Result{RunID: "r1", Reason: record.RunEndStopped}
	s.how = endedHow(res.Reason)
	if got := watchFooter(res, s); !strings.HasPrefix(got, "tego watch: recorded as run r1: ended (stopped) · summary not available") {
		t.Errorf("watch footer = %q", got)
	}
}

// TestRecordOffRunSaysSoAtItsEnd: a run whose record was off kept its refusals and no exec or allowed action, and its
// end said nothing of it: a contract's own record: off is no start notice (the quiet start), so the summary is where it
// is said, before the chain clause, whether or not the receipt could be built. A watch's footer says it too, with no
// "seen:" line: it read "no connections · no sensitive file read" off a ledger that records neither.
func TestRecordOffRunSaysSoAtItsEnd(t *testing.T) {
	root, anchor := summaryHarness(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "quiet"}, ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	// The capability line of a run under record: off: every record row false (runstart.go's recordRows).
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"agent"}, Cwd: "/w/proj", Tier: "landlock", Capture: "off",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): false, string(backend.CapRecordReads): false,
			string(backend.CapLogAllowed): false}}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []*record.Event{
		{Kind: record.KindNet, Verdict: record.VerdictRefused, Rule: "unmatched", Reason: record.ReasonNetNotAllowed},
		{Kind: record.KindRefused, Rule: "unmatched", Reason: record.ReasonNetNotAllowed},
	} {
		e.Source, e.PID, e.TID = record.SourceSupervisor, 1, 1
		var payload any = record.RefusedPayload{Op: "net", Target: "127.0.0.1:9822", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"}
		if e.Kind == record.KindNet {
			e.Attr, e.Authority = record.Unattributed(), record.AuthorityRule
			payload = record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9822"}
		}
		if err := e.SetPayload(payload); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	prevRoot := ledgerRootOf
	t.Cleanup(func() { ledgerRootOf = prevRoot })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	res := tegoruntime.Result{RunID: id, Reason: record.RunEndExit}

	off := summarizeRun(t.Context(), &config.Machine{}, anchor, res, agent.RecordOff)
	if off == nil || off.rc == nil {
		t.Fatalf("no receipt for the run: %+v", off)
	}
	if got, want := off.text(), "tego run: "+id+" ended (exited with code 0) · tier landlock · refused 1 (not allowed by any rule 1) · asked 0 · "+
		"record off: refusals only · chain verified\n  more: tego receipt "+id+"\n"; got != want {
		t.Errorf("the summary of a record: off run:\n got %q\nwant %q", got, want)
	}
	footer := watchFooter(res, off)
	if want := "tego watch: recorded as run " + id + ": ended (exited with code 0) · refused 1 (not allowed by any rule 1) · " +
		"record off: refusals only · chain verified\n"; !strings.HasPrefix(footer, want) || strings.Contains(footer, "seen:") {
		t.Errorf("the footer of a record: off watch has no record off clause, or a seen: line it did not record:\n%s", footer)
	}
	// Said with no receipt as well: the record mode is the run's table's, not the ledger's.
	off.rc, off.err = nil, errors.New("no such file")
	if got := off.text(); !strings.HasSuffix(strings.SplitN(got, "\n", 2)[0], " · summary not available (no such file) · record off: refusals only · chain verified") {
		t.Errorf("a record: off run with no receipt: %q", got)
	}

	// The same ledger summarized as a run that recorded says nothing of it, and its footer counts what it saw.
	plain := summarizeRun(t.Context(), &config.Machine{}, anchor, res, agent.RecordSummary)
	if got := plain.text() + watchFooter(res, plain); strings.Contains(got, "record off") || !strings.Contains(got, "\n  seen: ") {
		t.Errorf("a run that recorded is said to be record off, or its footer lost the seen: line:\n%s", got)
	}
}

// TestReceiptQuietWithoutModelResponses: `tego receipt` of a capture-off run reads no price table, so it prints
// nothing on stderr (every receipt warned "no price table").
func TestReceiptQuietWithoutModelResponses(t *testing.T) {
	root, anchor := summaryHarness(t)
	id := summaryLedger(t, root, anchor)
	code, out, errs := run(t, "receipt", id)
	if code != identity.ExitOK || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	for _, want := range []string{"\nConnections\n", "127.0.0.1:9823  3  allowed", "\nSensitive files read\n", "~/.ssh/id_rsa  1  allowed"} {
		if !strings.Contains(out, want) {
			t.Errorf("receipt lacks %q:\n%s", want, out)
		}
	}
}

// BenchmarkEndSummary is the summary's cost over a 10,000-line run (the receipt's pass and the chain check): the
// time tego run adds after the agent exits. Divide by 10 for the cost per 1,000 lines.
func BenchmarkEndSummary(b *testing.B) {
	root := b.TempDir()
	anchor := filepath.Join(b.TempDir(), "chain.log")
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "bench"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		b.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"agent"}, Cwd: "/w", Tier: "landlock"}); err != nil {
		b.Fatal(err)
	}
	for i := range 9998 {
		e := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 1, TID: 1, Verdict: record.VerdictAllow,
			Rule: "fs.read[/]", Attr: record.Unattributed(), Authority: record.AuthorityRule}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: fmt.Sprintf("/w/src/file%d.go", i%500)}); err != nil {
			b.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			b.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		b.Fatal(err)
	}
	prev := ledgerRootOf
	b.Cleanup(func() { ledgerRootOf = prev })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	res := tegoruntime.Result{RunID: string(id), Reason: record.RunEndExit}
	for b.Loop() {
		if s := summarizeRun(b.Context(), &config.Machine{}, anchor, res, agent.RecordSummary); s == nil || s.rc == nil || s.chain != "chain verified" {
			b.Fatalf("summary %+v", s)
		}
	}
}
