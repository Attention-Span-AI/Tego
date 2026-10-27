// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// line is one synthetic ledger line: its kind, its offset from the run's start, and the fields the receipt reads.
type line struct {
	kind    record.Kind
	at      time.Duration
	verdict record.Verdict
	rule    string
	reason  record.Reason
	payload any
}

const t0 = uint64(1_000_000_000_000)

// ledgerOf writes lines as a run directory's events.jsonl, chained as a writer would, and opens a reader on it.
func ledgerOf(t *testing.T, lines []line) *ledger.Reader {
	t.Helper()
	var buf bytes.Buffer
	prev := ""
	for i, in := range lines {
		mono := t0 + uint64(in.at)
		e := &record.Event{V: record.Version, Seq: uint64(i), Prev: prev, MonoNS: mono, TS: time.Unix(0, int64(mono)).UTC(),
			Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "fixture", PID: 1, TID: 1, Kind: in.kind,
			Source: record.SourceSupervisor, Verdict: in.verdict, Rule: in.rule, Reason: in.reason}
		if in.kind.IsAction() {
			e.Attr = record.Unattributed()
			if e.Rule != "" {
				e.Authority = record.AuthorityRule
			}
		}
		if in.payload != nil {
			if err := e.SetPayload(in.payload); err != nil {
				t.Fatal(err)
			}
		}
		b, err := e.MarshalLine()
		if err != nil {
			t.Fatalf("marshal line %d: %v", i, err)
		}
		prev = e.ID
		buf.Write(b)
		buf.WriteByte('\n')
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func start(capture string, recordsOpens bool) line {
	return line{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "landlock", Capture: capture,
		Command: []string{"sh", "agent.sh"}, Cwd: "/p",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): recordsOpens}}}
}

func end(at time.Duration, code int) line {
	return line{kind: record.KindRunEnd, at: at, payload: record.RunEndPayload{Reason: "exit", ExitCode: code}}
}

func compute(t *testing.T, lines []line, opt Options) *Receipt {
	t.Helper()
	rc, err := Compute(context.Background(), ledgerOf(t, lines), opt)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

func TestRefusalsCountOnceByRuleAndOverTime(t *testing.T) {
	rw := "fs.write[./out/]"
	rc := compute(t, []line{
		start("off", false),
		// a refused write and its mirroring refused line: one refusal
		{kind: record.KindFS, at: 10 * time.Second, verdict: record.VerdictRefused, rule: rw, reason: record.ReasonWriteOutsideContract,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/home/u/.bashrc", Flags: 0o1101}},
		{kind: record.KindRefused, at: 10 * time.Second, rule: rw, reason: record.ReasonWriteOutsideContract,
			payload: record.RefusedPayload{Op: "open", Target: "/home/u/.bashrc", Reason: record.ReasonWriteOutsideContract, Rule: rw}},
		// a second write refusal in minute 2, and a net refusal in minute 0
		{kind: record.KindFS, at: 130 * time.Second, verdict: record.VerdictRefused, rule: rw, reason: record.ReasonWriteOutsideContract,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/p/.git/hooks/pre-commit", Flags: 0o1101}},
		{kind: record.KindNet, at: 20 * time.Second, verdict: record.VerdictRefused, rule: "unmatched", reason: record.ReasonNetNotAllowed,
			payload: record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:8787"}},
		// an exec refusal: the target is the program path, never its argv
		{kind: record.KindExec, at: 30 * time.Second, verdict: record.VerdictRefused, rule: "unmatched", reason: record.ReasonExecNotAllowed,
			payload: record.ExecPayload{Path: "/usr/bin/curl", Argv: []string{"curl", "-H", "Authorization: Bearer sk-SECRET"}, ExecID: "x"}},
		// a refused line on its own (no action before it): a refusal of its own
		{kind: record.KindRefused, at: 40 * time.Second, rule: "builtin.keyring", reason: record.ReasonFSGate,
			payload: record.RefusedPayload{Op: "keyctl", Target: "keyring", Reason: record.ReasonFSGate, Rule: "builtin.keyring"}},
		end(3*time.Minute, 0),
	}, Options{})
	if rc.Refusals.Total != 5 {
		t.Fatalf("total = %d, want 5: %+v", rc.Refusals.Total, rc.Refusals.List)
	}
	if got := rc.Refusals.ByRule[0]; got.Rule != rw || got.Count != 2 || got.Reason != string(record.ReasonWriteOutsideContract) {
		t.Errorf("by_rule[0] = %+v", got)
	}
	if got, want := rc.OverTime.Counts, []int{4, 0, 1, 0}; !equalInts(got, want) {
		t.Errorf("over time = %v, want %v", got, want)
	}
	var out bytes.Buffer
	_ = rc.JSON(&out)
	_ = rc.Text(&out)
	if strings.Contains(out.String(), "sk-SECRET") {
		t.Error("an exec refusal's argv reached the receipt")
	}
	if !strings.Contains(out.String(), "/usr/bin/curl") {
		t.Error("the exec refusal's program is missing")
	}
	if rc.ExitCode == nil || *rc.ExitCode != 0 || rc.Time.Seconds != 180 || rc.Time.SoFar {
		t.Errorf("outcome/time = %v %v %v", rc.ExitCode, rc.Time.Seconds, rc.Time.SoFar)
	}
}

func TestFilesChanged(t *testing.T) {
	rc := compute(t, []line{
		start("off", true),
		{kind: record.KindFS, at: 1, verdict: record.VerdictAllow, rule: "w", payload: record.FSPayload{Op: record.FSOpen, Path: "/p/out/a", Flags: 0o1101, Created: true}},
		{kind: record.KindFS, at: 2, verdict: record.VerdictAllow, rule: "w", payload: record.FSPayload{Op: record.FSOpen, Path: "/p/out/a", Flags: 0o2001}},
		{kind: record.KindFS, at: 3, verdict: record.VerdictAllow, rule: "r", payload: record.FSPayload{Op: record.FSOpen, Path: "/p/src/read-only"}},
		{kind: record.KindFS, at: 4, verdict: record.VerdictAllow, rule: "w", payload: record.FSPayload{Op: record.FSUnlink, Path: "/p/out/old"}},
		{kind: record.KindFS, at: 5, verdict: record.VerdictAllow, rule: "w", payload: record.FSPayload{Op: record.FSRename, Path: "/p/out/x", Path2: "/p/out/y"}},
		{kind: record.KindFS, at: 6, verdict: record.VerdictAllow, rule: "w", payload: record.FSPayload{Op: record.FSOpen, Path: "/p/out/failed", Flags: 0o1101, Errno: 13}},
		{kind: record.KindFS, at: 7, verdict: record.VerdictRefused, rule: "w", reason: record.ReasonWriteOutsideContract,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/etc/passwd", Flags: 0o1}},
		end(time.Second, 0),
	}, Options{})
	f := rc.Files
	if !f.Recorded || !equalStrs(f.Written, []string{"/p/out/a"}) || !equalStrs(f.Created, []string{"/p/out/a"}) ||
		!equalStrs(f.Deleted, []string{"/p/out/old"}) || len(f.Renamed) != 1 || f.Renamed[0].To != "/p/out/y" {
		t.Errorf("files = %+v", f)
	}
	if f.Changed() != 3 {
		t.Errorf("changed = %d, want 3", f.Changed())
	}

	// a tier that records only refusals says the field is not recorded, and lists nothing as if complete
	rc = compute(t, []line{start("off", false), end(time.Second, 0)}, Options{})
	if rc.Files.Recorded || !strings.HasPrefix(rc.Files.Note, "not recorded") {
		t.Errorf("files at tier landlock = %+v", rc.Files)
	}
}

func TestAsksAndAnswers(t *testing.T) {
	yes, no := true, false
	rc := compute(t, []line{
		start("off", false),
		{kind: record.KindAsk, at: 1, payload: map[string]any{"ask_id": "ask-1", "hold": "open", "op": "open", "target": "/p/.env", "ask_rule": "ask.read"}},
		{kind: record.KindAsk, at: 2, payload: map[string]any{"ask_id": "ask-2", "hold": "connect", "op": "connect", "target": "example.com:443", "ask_rule": "ask.net"}},
		{kind: record.KindAsk, at: 3, payload: map[string]any{"ask_id": "ask-3", "hold": "open", "op": "open", "target": "/p/x", "ask_rule": "ask.read"}},
		{kind: record.KindAsk, at: 4, payload: map[string]any{"ask_id": "ask-4", "hold": "open", "op": "open", "target": "/p/y", "ask_rule": "ask.read"}},
		{kind: record.KindAnswer, at: 5, payload: map[string]any{"ask_id": "ask-1", "by": "uid:1000 pid:9", "after_s": 2.5, "approved": yes}},
		{kind: record.KindAnswer, at: 6, payload: map[string]any{"ask_id": "ask-2", "by": "uid:1000 pid:9", "after_s": 1.0, "approved": no, "answer_reason": "ask-denied"}},
		{kind: record.KindAnswer, at: 7, payload: map[string]any{"ask_id": "ask-3", "by": "timeout", "after_s": 60.0, "approved": no, "answer_reason": "ask-timeout"}},
		end(time.Second, 0),
	}, Options{})
	a := rc.Asks
	if a.Asked != 4 || a.Approved != 1 || a.Denied != 1 || a.TimedOut != 1 || a.Unanswered != 1 || a.WaitS != 63.5 {
		t.Errorf("asks = %+v", a)
	}
	if a.List[0].Answer != "approved" || a.List[0].Target != "/p/.env" || a.List[0].Rule != "ask.read" || a.List[3].Answer != "" {
		t.Errorf("ask list = %+v", a.List)
	}
}

func TestStallAndTokens(t *testing.T) {
	gap := record.GapPayload{What: record.GapRecord, Why: "channel-full"}
	rc := compute(t, []line{
		start("forwarder", false),
		{kind: record.KindExec, at: time.Minute, verdict: record.VerdictAllow, rule: "e", payload: record.ExecPayload{Path: "/bin/sh", ExecID: "x"}},
		// a 12-minute quiet window: a stall
		{kind: record.KindSSLRequest, at: 13 * time.Minute, payload: record.SSLRequestPayload{Endpoint: "messages", Method: "POST", Host: "h"}},
		// 10 minutes waiting on the model: not a stall
		{kind: record.KindSSLResponse, at: 23 * time.Minute, payload: map[string]any{"request_seq": 2, "status": 200, "parser_version": "1",
			"model": "m", "latency_ms": 1, "usage": map[string]int{"input": 100, "output": 20, "cache_read": 5, "cache_write": 1}}},
		// a 6-minute window that ends at a gap line: unknown, not a stall
		{kind: record.KindGap, at: 29 * time.Minute, payload: gap},
		end(30*time.Minute, 0),
	}, Options{})
	if rc.Stall.Windows != 1 || rc.Stall.Minutes != 12 || rc.Stall.ThresholdSeconds != 300 || rc.Stall.Note != "" {
		t.Errorf("stall = %+v", rc.Stall)
	}
	tk := rc.Tokens
	if !tk.Recorded || tk.ModelCalls != 1 || tk.In != 100 || tk.Out != 20 || tk.CacheRead != 5 || tk.CacheWrite != 1 {
		t.Errorf("tokens = %+v", tk)
	}
	// a threshold override, and capture off: tokens not recorded, stall partial
	rc = compute(t, []line{start("off", false), {kind: record.KindGap, at: 0, payload: gap},
		{kind: record.KindExec, at: 2 * time.Second, verdict: record.VerdictAllow, rule: "e", payload: record.ExecPayload{Path: "/bin/sh", ExecID: "x"}},
		end(4*time.Second, 0)}, Options{StallThreshold: time.Second})
	if rc.Stall.Windows != 1 || rc.Stall.Note == "" || rc.Tokens.Recorded || !strings.HasPrefix(rc.Tokens.Note, "not recorded") {
		t.Errorf("capture off: stall %+v tokens %+v", rc.Stall, rc.Tokens)
	}
	if rc.Tests.Recorded || !strings.HasPrefix(rc.Tests.Note, "not recorded") {
		t.Errorf("tests = %+v", rc.Tests)
	}
}

func TestLiveRunAndNoRun(t *testing.T) {
	rc := compute(t, []line{start("off", false),
		{kind: record.KindExec, at: time.Second, verdict: record.VerdictAllow, rule: "e", payload: record.ExecPayload{Path: "/bin/sh", ExecID: "x"}}},
		Options{NowMonoNS: t0 + uint64(10*time.Second)})
	if rc.Ended || !rc.Time.SoFar || rc.Time.Seconds != 10 || rc.Outcome() != "still running" {
		t.Errorf("live = %+v %q", rc.Time, rc.Outcome())
	}
	_, err := Compute(context.Background(), ledgerOf(t, []line{{kind: record.KindGap, payload: record.GapPayload{What: "record", Why: "x"}}}), Options{})
	if !errors.Is(err, ErrNoRun) {
		t.Errorf("no run_start: %v", err)
	}
}

func TestTextEscapesLedgerText(t *testing.T) {
	rc := compute(t, []line{start("off", false),
		{kind: record.KindFS, at: 1, verdict: record.VerdictRefused, rule: "w", reason: record.ReasonWriteOutsideContract,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/p/\x1b[2Jevil\nforged", Flags: 1}},
		end(time.Second, 0)}, Options{})
	var b bytes.Buffer
	if err := rc.Text(&b); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\x1b") || strings.Contains(b.String(), "\nforged") {
		t.Errorf("text carries raw control bytes:\n%s", b.String())
	}
	var round Receipt
	b.Reset()
	if err := rc.JSON(&b); err != nil || json.Unmarshal(b.Bytes(), &round) != nil || round.Refusals.Total != 1 || round.V != Version {
		t.Errorf("json round trip: %v %+v", err, round.Refusals)
	}
}

// flatPrices prices every response at one dollar per thousand input tokens, and none whose model is "unpriced".
type flatPrices struct{}

func (flatPrices) Cost(u ledger.TokenUsage) (float64, bool) {
	if u.Model == "unpriced" {
		return 0, false
	}
	return float64(u.In) / 1000, true
}

func TestCostAndCoverage(t *testing.T) {
	resp := func(at time.Duration, seq int, model string) line {
		return line{kind: record.KindSSLResponse, at: at, payload: map[string]any{"request_seq": seq, "status": 200, "parser_version": "1",
			"model": model, "latency_ms": 1, "usage": map[string]int{"input": 500, "output": 10}}}
	}
	req := line{kind: record.KindSSLRequest, payload: record.SSLRequestPayload{Endpoint: "messages", Method: "POST", Host: "h"}}
	lines := []line{start("forwarder", true), req, resp(time.Second, 1, "m"), req, resp(2*time.Second, 3, "unpriced"), end(3*time.Second, 0)}
	rc := compute(t, lines, Options{Prices: flatPrices{}})
	if rc.Tokens.EstCostUSD != 0.5 || rc.Tokens.Unpriced != 1 || rc.Tokens.CostText != "$0.50 est. (1 unpriced)" {
		t.Errorf("cost = %+v", rc.Tokens)
	}
	if rc.Coverage.Complete || len(rc.Coverage.Gaps) != 1 || rc.Coverage.Gaps[0].Field != "tokens.est_cost_usd" {
		t.Errorf("coverage = %+v", rc.Coverage)
	}
	// every field recorded and priced: complete
	rc = compute(t, []line{start("forwarder", true), req, resp(time.Second, 1, "m"), end(2*time.Second, 0)}, Options{Prices: flatPrices{}})
	if !rc.Coverage.Complete || len(rc.Coverage.Gaps) != 0 {
		t.Errorf("complete run: coverage = %+v", rc.Coverage)
	}
	// capture off and a gap line each name a gap
	rc = compute(t, []line{start("off", false), {kind: record.KindGap, at: 1, payload: record.GapPayload{What: record.GapRecord, Why: "x"}},
		end(time.Second, 0)}, Options{})
	fields := map[string]bool{}
	for _, g := range rc.Coverage.Gaps {
		fields[g.Field] = true
	}
	if !fields["files"] || !fields["tokens"] || !fields["record"] || !fields["stall"] || rc.Coverage.Complete {
		t.Errorf("capture off: coverage = %+v", rc.Coverage)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
