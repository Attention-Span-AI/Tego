// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var updateFixtures = flag.Bool("update", false, "rewrite spec/record/v1/fixtures from the generator")

// fixturesDir is spec/record/v1/fixtures relative to this package.
const fixturesDir = "../../spec/record/v1/fixtures"

// fixtureRun is the frozen M0 run: agent "retriever" (a Python agent), 20 model steps through the forwarder,
// tool execs, writes under ./out, one refusal (a read of ~/.ssh), a capture gap (a static Go binary) and a
// record gap (dropped events), a token limit, run_end reason=limit. It is written through the real Writer with
// a scripted clock so every byte, id and prev is what the product would produce.
type fixtureRun struct {
	t     *testing.T
	w     *Writer
	clk   *stepClock
	step  int
	total int // input+output tokens so far
}

const (
	fxPID     = 48212 // the python agent
	fxTID     = 48212
	fxWorker  = 48215 // a worker thread of the agent
	fxCgroup  = 44821
	fxMCPPID  = 48230
	fxTraceID = "6b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e"
	fxSpanPfx = "a3f1c9e2d4b6"
)

func (f *fixtureRun) execID(pid int, startNS uint64) string {
	return fmt.Sprintf("%s/%d/%d", f.w.ref.ID, pid, startNS)
}

// emit advances the clock by dt and appends e.
func (f *fixtureRun) emit(dt time.Duration, e *record.Event) *record.Event {
	f.t.Helper()
	f.clk.Advance(dt)
	if err := f.w.Append(e); err != nil {
		f.t.Fatalf("fixture seq %d (%s): %v", f.w.Seq(), e.Kind, err)
	}
	return e
}

func (f *fixtureRun) action(kind record.Kind, source record.Source, tid int, rule string, verdict record.Verdict,
	reason record.Reason, attr *record.Attribution, payload any) *record.Event {
	e := &record.Event{Kind: kind, Source: source, PID: fxPID, TID: tid, Cgroup: fxCgroup, Rule: rule,
		Verdict: verdict, Authority: record.AuthorityRule, Reason: reason, Attr: attr}
	if err := e.SetPayload(payload); err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f *fixtureRun) plain(kind record.Kind, source record.Source, pid, tid int, payload any) *record.Event {
	e := &record.Event{Kind: kind, Source: source, PID: pid, TID: tid, Cgroup: fxCgroup}
	if err := e.SetPayload(payload); err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f *fixtureRun) attr() *record.Attribution { return record.AttributedByTime("t1", f.step) }

// model performs one step: request through the forwarder, response, and one tool_use decision.
func (f *fixtureRun) model(latency time.Duration, stopReason, tool, argHash string) {
	f.step++
	k := f.step
	req := f.emit(90*time.Millisecond, f.plain(record.KindSSLRequest, record.SourceForwarder, fxPID, fxTID,
		record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages",
			Host: "api.anthropic.com", RequestID: fmt.Sprintf("req_011CS%04d", k), Size: 1800 + 210*k,
			TraceID: fxTraceID, SpanID: fmt.Sprintf("%s%04x", fxSpanPfx, k),
			Headers: map[string]string{"anthropic-version": "2023-06-01", "content-type": "application/json",
				"user-agent": "anthropic-sdk-python/0.69.0"}}))
	in, out := 800+200*k, 100+2*k
	f.total += in + out
	f.emit(latency, f.plain(record.KindSSLResponse, record.SourceForwarder, fxPID, fxTID,
		record.SSLResponsePayload{RequestSeq: new(req.Seq), Status: 200, Model: "claude-sonnet-4-5-20250929",
			ResponseID: fmt.Sprintf("msg_01Xq%04dZ", k), StopReason: stopReason,
			Usage:     &record.Usage{Input: in, Output: out, CacheRead: 512 * (k - 1), CacheWrite: 512},
			LatencyMS: latency.Milliseconds(), RequestID: fmt.Sprintf("req_011CS%04d", k),
			ContentEncoding: "gzip", ParserVersion: "anthropic/1"}))
	if tool != "" {
		f.emit(2*time.Millisecond, f.plain(record.KindDecision, record.SourceForwarder, fxPID, fxTID,
			record.DecisionPayload{Step: k, ToolUseID: fmt.Sprintf("toolu_01%04dA", k), Tool: tool,
				InputHash: strings.Repeat(argHash, 16), Text: false, Unparsed: false}))
	}
}

func (f *fixtureRun) exec(dt time.Duration, path string, argv []string, pid int, startNS uint64, parent string, attr *record.Attribution) {
	f.emit(dt, f.action(record.KindExec, record.SourceSupervisor, fxTID, "exec["+filepath.Base(path)+"]",
		record.VerdictAllow, "", attr, record.ExecPayload{Path: path, Argv: argv, ExecID: f.execID(pid, startNS),
			ParentExecID: parent}))
}

func (f *fixtureRun) write(dt time.Duration, path string) {
	f.emit(dt, f.action(record.KindFS, record.SourceLandlock, fxTID, "fs.write[./out]", record.VerdictAllow, "",
		f.attr(), record.FSPayload{Op: record.FSOpen, Path: path, Flags: 0x241}))
}

func (f *fixtureRun) reads(dt time.Duration, path string, count int, attr *record.Attribution) {
	f.emit(dt, f.action(record.KindFS, record.SourceLandlock, fxTID, "fs.read[.]", record.VerdictAllow, "",
		attr, record.FSPayload{Op: record.FSOpen, Path: path, Count: count}))
}

// generateFixture writes the frozen run into dir and returns the run_end id.
func generateFixture(t *testing.T, dir string, anchor ChainAnchor) string {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, 250*time.Microsecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor), WithContract([]byte("name: retriever\n")))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211 // the launcher, pinned so the fixture does not depend on the test process
	f := &fixtureRun{t: t, w: w, clk: clk}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	const proj = "/home/u/proj"
	pyExec := f.execID(fxPID, 812_346_000_000)
	// Startup: the agent, its MCP server, aggregated reads, the first connection to the forwarder.
	f.exec(12*time.Millisecond, "/usr/bin/python3.12", []string{"python3", "agent.py", "--query", "summarize the repo"},
		fxPID, 812_346_000_000, "", record.Unattributed())
	f.reads(30*time.Millisecond, proj, 37, record.Unattributed())
	f.exec(8*time.Millisecond, "/usr/bin/node", []string{"npx", "@modelcontextprotocol/server-filesystem", proj},
		fxMCPPID, 812_384_000_000, pyExec, record.Unattributed())
	f.emit(15*time.Millisecond, f.action(record.KindMCP, record.SourceHook, fxTID, "mcp[fs]", record.VerdictAllow, "",
		record.Unattributed(), record.MCPPayload{Name: "fs", Command: []string{"npx", "@modelcontextprotocol/server-filesystem", proj},
			Transport: "stdio"}))
	f.emit(40*time.Millisecond, f.action(record.KindNet, record.SourceSupervisor, fxTID, "models[anthropic]",
		record.VerdictAllow, "", record.Unattributed(), record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:41337",
			Host: "api.anthropic.com", Propagated: []string{"header:X-Tego-Run", "header:traceparent", "header:tracestate"}}))

	f.model(1400*time.Millisecond, "tool_use", "bash", "1a")
	f.exec(20*time.Millisecond, "/usr/bin/rg", []string{"rg", "-n", "def ", "src"}, 48240, 812_500_000_000, pyExec, f.attr())
	f.reads(35*time.Millisecond, proj+"/src", 120, f.attr())

	f.model(1100*time.Millisecond, "tool_use", "read_file", "2b")
	f.reads(10*time.Millisecond, proj+"/src/main.py", 1, f.attr())

	f.model(1700*time.Millisecond, "tool_use", "write_file", "3c")
	f.write(12*time.Millisecond, proj+"/out/notes.md")

	f.model(900*time.Millisecond, "tool_use", "bash", "4d")
	f.exec(18*time.Millisecond, "/usr/bin/git", []string{"git", "log", "--oneline", "-20"}, 48251, 812_900_000_000, pyExec, f.attr())
	f.reads(25*time.Millisecond, proj+"/.git", 45, f.attr())

	f.model(1300*time.Millisecond, "tool_use", "bash", "5e")
	f.exec(15*time.Millisecond, "/usr/bin/cat", []string{"cat", "/home/u/.ssh/id_ed25519"}, 48262, 813_200_000_000, pyExec, f.attr())
	f.emit(3*time.Millisecond, f.action(record.KindFS, record.SourceLandlock, fxTID, "fs.deny_read[~/.ssh]",
		record.VerdictRefused, record.ReasonReadDenied, f.attr(),
		record.FSPayload{Op: record.FSOpen, Path: "/home/u/.ssh/id_ed25519"}))
	f.emit(time.Millisecond, f.plain(record.KindRefused, record.SourceLandlock, fxPID, fxTID,
		record.RefusedPayload{Op: "open", Target: "/home/u/.ssh/id_ed25519", Reason: record.ReasonReadDenied,
			Rule: "fs.deny_read[~/.ssh]"}))

	f.model(1000*time.Millisecond, "tool_use", "bash", "6f")
	f.exec(16*time.Millisecond, "/usr/bin/gh", []string{"gh", "api", "repos/tego/tego/pulls"}, 48270, 813_600_000_000, pyExec, f.attr())
	f.emit(60*time.Millisecond, f.action(record.KindNet, record.SourceSupervisor, fxTID, "net[api.github.com]",
		record.VerdictAllow, "", f.attr(), record.NetPayload{Proto: "tcp", Dst: "140.82.112.5:443", Host: "api.github.com"}))
	f.emit(5*time.Millisecond, f.plain(record.KindGap, record.SourceSSL, 48270, 48270,
		record.GapPayload{What: record.GapCapture, Why: "no-openssl", Binary: "/usr/bin/gh"}))

	f.model(1500*time.Millisecond, "tool_use", "write_file", "7a")
	f.write(11*time.Millisecond, proj+"/out/summary.md")

	f.model(1200*time.Millisecond, "tool_use", "bash", "8b")
	f.exec(22*time.Millisecond, "/usr/bin/python3.12", []string{"python3", "-c", "import json; json.dump({}, open('out/data.json','w'))"},
		48281, 814_100_000_000, pyExec, f.attr())
	f.write(30*time.Millisecond, proj+"/out/data.json")

	f.model(800*time.Millisecond, "tool_use", "list_directory", "9c")
	f.emit(6*time.Millisecond, f.action(record.KindMCP, record.SourceHook, fxTID, "mcp[fs]", record.VerdictAllow, "",
		f.attr(), record.MCPPayload{Name: "fs", Transport: "stdio", Tool: "list_directory"}))

	f.model(950*time.Millisecond, "tool_use", "bash", "0d")
	f.exec(19*time.Millisecond, "/usr/bin/rg", []string{"rg", "-n", "deprecated", "src"}, 48290, 814_500_000_000, pyExec, f.attr())
	f.reads(20*time.Millisecond, proj+"/src", 118, f.attr())

	f.model(1600*time.Millisecond, "tool_use", "write_file", "1e")
	f.write(9*time.Millisecond, proj+"/out/todo.md")

	f.model(700*time.Millisecond, "tool_use", "bash", "2f")
	f.emit(14*time.Millisecond, f.action(record.KindFS, record.SourceSupervisor, fxTID, "fs.write[./out]",
		record.VerdictAllow, "", f.attr(), record.FSPayload{Op: record.FSMkdir, Path: proj + "/out/reports"}))

	f.model(1450*time.Millisecond, "tool_use", "write_file", "3a")
	f.write(10*time.Millisecond, proj+"/out/reports/r1.md")

	f.model(750*time.Millisecond, "tool_use", "bash", "4b")
	f.emit(13*time.Millisecond, f.action(record.KindFS, record.SourceSupervisor, fxTID, "fs.write[./out]",
		record.VerdictAllow, "", f.attr(), record.FSPayload{Op: record.FSUnlink, Path: proj + "/out/data.json"}))

	f.model(1350*time.Millisecond, "tool_use", "write_file", "5c")
	f.emit(4*time.Millisecond, f.plain(record.KindGap, record.SourceSupervisor, 48211, 48211,
		record.GapPayload{What: record.GapRecord, Why: "channel-full", Count: 12}))
	f.write(8*time.Millisecond, proj+"/out/reports/r2.md")

	f.model(820*time.Millisecond, "tool_use", "read_file", "6d")
	f.emit(7*time.Millisecond, f.action(record.KindMCP, record.SourceHook, fxTID, "mcp[fs]", record.VerdictAllow, "",
		f.attr(), record.MCPPayload{Name: "fs", Transport: "stdio", Tool: "read_file"}))

	f.model(980*time.Millisecond, "tool_use", "bash", "7e")
	f.exec(17*time.Millisecond, "/usr/bin/git", []string{"git", "status", "--short"}, 48301, 815_400_000_000, pyExec, f.attr())
	f.reads(21*time.Millisecond, proj+"/.git", 52, f.attr())

	f.model(1550*time.Millisecond, "tool_use", "write_file", "8f")
	f.write(9*time.Millisecond, proj+"/out/final.md")

	f.model(870*time.Millisecond, "tool_use", "bash", "9a")
	f.emit(24*time.Millisecond, f.action(record.KindExec, record.SourceSupervisor, fxWorker, "exec[rg]",
		record.VerdictAllow, "", f.attr(), record.ExecPayload{Path: "/usr/bin/rg", Argv: []string{"rg", "-c", "import", "src"},
			ExecID: f.execID(48312, 815_900_000_000), ParentExecID: pyExec}))

	f.model(1250*time.Millisecond, "tool_use", "write_file", "0b")
	f.write(3*time.Millisecond, proj+"/out/reports/r3.md") // lands before the watcher's kill
	limit := f.plain(record.KindLimit, record.SourceSupervisor, 48211, 48211,
		record.LimitPayload{Which: record.LimitTokens, Value: float64(f.total), Ceiling: 60000})
	limit.Reason = record.ReasonLimitTokens
	f.emit(time.Millisecond, limit)
	f.clk.Advance(35 * time.Millisecond)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndLimit, Signal: 9,
		Supervisor: record.Supervisor{Notifications: 233, HeldMS: 41}}); err != nil {
		t.Fatal(err)
	}
	if f.step != 20 || f.total <= 60000 {
		t.Fatalf("fixture story: %d steps, %d tokens", f.step, f.total)
	}
	return w.Head()
}

// generateKinds writes one line per v1 kind (fifteen lines, one chain) into dir.
func generateKinds(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	a := f.attr()
	f.emit(0, f.plain(record.KindAsk, record.SourceSupervisor, 48211, 48211, record.AskPayload{AskID: "ask-01", Hold: "exec"}))
	f.emit(0, f.plain(record.KindAnswer, record.SourceHook, 48211, 48211, record.AnswerPayload{AskID: "ask-01", By: "human", AfterS: 2.5}))
	f.emit(0, f.plain(record.KindBoundary, record.SourceProxy, fxPID, fxTID, record.BoundaryPayload{ContextBytes: 20480,
		DockerfileSHA256: strings.Repeat("d0", 32), Tags: []string{"app:dev"}, NetworkMode: "none"}))
	f.emit(0, f.plain(record.KindDecision, record.SourceForwarder, fxPID, fxTID, record.DecisionPayload{Step: 1,
		ToolUseID: "toolu_010001A", Tool: "bash", InputHash: strings.Repeat("1a", 32)}))
	f.exec(0, "/usr/bin/rg", []string{"rg", "-n", "x"}, 48240, 812_500_000_000, f.execID(fxPID, 812_346_000_000), a)
	f.write(0, "/home/u/proj/out/a.md")
	f.emit(0, f.plain(record.KindGap, record.SourceSSL, 48270, 48270, record.GapPayload{What: record.GapCapture, Why: "h2", Binary: "/usr/bin/gh"}))
	l := f.plain(record.KindLimit, record.SourceSupervisor, 48211, 48211, record.LimitPayload{Which: record.LimitCostUSD, Value: 2.01, Ceiling: 2})
	l.Reason = record.ReasonLimitCost
	f.emit(0, l)
	f.emit(0, f.action(record.KindMCP, record.SourceHook, fxTID, "mcp[fs]", record.VerdictAllow, "", a,
		record.MCPPayload{Name: "fs", Transport: "stdio", Tool: "read_file"}))
	f.emit(0, f.action(record.KindNet, record.SourceSupervisor, fxTID, "unmatched", record.VerdictRefused,
		record.ReasonNetNotAllowed, a, record.NetPayload{Proto: "tcp", Dst: "93.184.216.34:443", Host: "example.com"}))
	f.emit(0, f.plain(record.KindRefused, record.SourceSupervisor, fxPID, fxTID, record.RefusedPayload{Op: "connect",
		Target: "93.184.216.34:443", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"}))
	f.model(500*time.Millisecond, "end_turn", "", "")
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 9, HeldMS: 1}}); err != nil {
		t.Fatal(err)
	}
}

// profilesRef is the profiles fixture's run: one whose contract extends a built-in profile and a profiles-directory
// one (ADR 0066 D6, record_minor 15).
var profilesRef = record.RunRef{ID: runID(fixedStart, "p3fl15"), Agent: "retriever"}

// generateProfiles writes a short run whose run_start carries profiles, as `tego run` writes it for a contract with
// `extends: [tego/python, team]` where team extends base: base first, then the list left to right.
func generateProfiles(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, profilesRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.RecordMinor = record.MinorProfiles
	// No home directory: test/fixtures replays this run as a recorded one, and those name no account.
	start.Cwd = "/srv/proj"
	sum := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
	start.Profiles = []record.ProfileRef{
		{Name: "tego/python", Source: record.ProfileSourceBuiltin, SHA256: sum("tego/python")},
		{Name: "base", Source: record.ProfileSourceDir, SHA256: sum("base")},
		{Name: "team", Source: record.ProfileSourceDir, SHA256: sum("team")},
	}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	f.write(0, "/srv/proj/out/a.md")
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
}

// generateHostSockets writes a short run in ADR 0070's unix-only state (no net: section, host_sockets not set,
// record minor 16): a connect to the Docker daemon's socket refused host-sockets, its line naming what the socket gives,
// one to an abstract name no socket of the run holds, the run's own socket under its write entry admitted, and an
// IP destination no entry names allowed unmatched, as every IP destination is with no net: section.
func generateHostSockets(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	a := record.Unattributed()
	f.emit(0, f.action(record.KindNet, record.SourceSupervisor, fxTID, "host-sockets", record.VerdictRefused,
		record.ReasonNetNotAllowed, a, record.NetPayload{Proto: "unix", Dst: "unix:/run/docker.sock",
			What: "the Docker daemon, root-equivalent"}))
	f.emit(0, f.plain(record.KindRefused, record.SourceSupervisor, fxPID, fxTID, record.RefusedPayload{Op: "connect",
		Target: "unix:/run/docker.sock", Reason: record.ReasonNetNotAllowed, Rule: "host-sockets"}))
	f.emit(0, f.action(record.KindNet, record.SourceSupervisor, fxTID, "host-sockets", record.VerdictRefused,
		record.ReasonNetNotAllowed, a, record.NetPayload{Proto: "unix", Dst: "unix:@/tmp/dbus-session"}))
	f.emit(0, f.plain(record.KindRefused, record.SourceSupervisor, fxPID, fxTID, record.RefusedPayload{Op: "connect",
		Target: "unix:@/tmp/dbus-session", Reason: record.ReasonNetNotAllowed, Rule: "host-sockets"}))
	f.emit(0, f.action(record.KindNet, record.SourceSupervisor, fxTID, "fs.write[./out]", record.VerdictAllow, "", a,
		record.NetPayload{Proto: "unix", Dst: "unix:/home/u/proj/out/agent.sock"}))
	f.emit(0, f.action(record.KindNet, record.SourceSupervisor, fxTID, "unmatched", record.VerdictAllow, "", a,
		record.NetPayload{Proto: "tcp", Dst: "93.184.216.34:443", Host: "example.com"}))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 4, HeldMS: 1}}); err != nil {
		t.Fatal(err)
	}
}

// runIdentityRef is the run identity fixture's run: a check run a root launcher started under sudo, nested in another
// run, with labels and a contract revision (ADR 0073, record_minor 17).
var runIdentityRef = record.RunRef{ID: runID(fixedStart, "r1d20x"), Agent: "retriever"}

// generateRunIdentity writes a short run whose run_start carries every run identity key, as `sudo tego run` writes it
// for a contract with revision 2026.10.25+1 when TEGO_PARENT_RUN names a run.
func generateRunIdentity(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, runIdentityRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.RecordMinor = record.MinorRunIdentity
	// No home directory and no real account: test/fixtures replays this run as a recorded one, and those name none
	// (u is nobody's, and root is no account name there).
	start.Cwd = "/srv/proj"
	root, invoker := uint32(0), uint32(1000)
	start.LauncherUID, start.LauncherUser = &root, "root"
	start.SudoUID, start.SudoUser = &invoker, "u"
	start.Host = "build-7"
	start.ParentRun = runID(fixedStart.Add(-time.Minute), "p4r3nt")
	start.Labels = map[string]string{"team": "infra", "ticket": "ops-12"}
	start.Role = "check"
	start.ContractRevision = "2026.10.25+1"
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	f.write(0, "/srv/proj/out/a.md")
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
}

// heldReadsRef is the held-reads fixture's run: one at tier landlock whose read opens were held (ADR 0069,
// record_minor 18).
var heldReadsRef = record.RunRef{ID: runID(fixedStart, "h7rd18"), Agent: "retriever"}

// generateHeldReads writes a short run at tier landlock whose reads were held, as `tego run` writes it for fs.write
// ["./out/"] with an out/.env the compile's .env scan found inside that write entry (ADR 0069): run_start says
// fs_reads held, why nested, naming the entry, and the deny_read capability rows; the agent's cat of the .env is
// refused read-denied by the nested entry on the object the open deputy reached, and its cat of a .env.local made
// during the run by the built-in name rule, each one refused fs line (source seccomp: the supervisor answered). The
// allowed held read of out/src/a.txt has no line under record: summary.
func generateHeldReads(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, heldReadsRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.RecordMinor = record.MinorHeldReads
	// No home directory: test/fixtures replays this run as a recorded one, and those name no account.
	start.Cwd = "/srv/proj"
	// launcher_uid, which every run_start at MinorRunIdentity or later carries (ADR 0073); no launcher_user, as a
	// passwd database that names no account for the uid leaves it out.
	launcher := uint32(1000)
	start.LauncherUID = &launcher
	nested := "fs.deny_read[/srv/proj/out/.env]"
	start.FSReads = &record.FSReads{Reads: record.FSReadsHeld, Why: record.FSReadsWhyNested, Nested: []string{nested}}
	start.Capabilities = map[string]bool{"fs.deny_read": true, "fs.deny_read.nested": true,
		"fs.deny_read.created_later": true, "fs.deny_read.moved": false}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	f.exec(4*time.Millisecond, "/usr/bin/cat", []string{"cat", "out/.env"}, 48262, 812_400_000_000, "", record.Unattributed())
	f.heldReadRefusal(nested, "/srv/proj/out/.env")
	f.exec(6*time.Millisecond, "/usr/bin/cat", []string{"cat", "out/src/a.txt"}, 48263, 812_410_000_000, "", record.Unattributed())
	f.exec(9*time.Millisecond, "/usr/bin/cat", []string{"cat", "out/.env.local"}, 48264, 812_420_000_000, "", record.Unattributed())
	f.heldReadRefusal("fs.deny_read[/srv/proj/**/.env.*]", "/srv/proj/out/.env.local")
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 1,
		Supervisor: record.Supervisor{Notifications: 14, HeldMS: 1}}); err != nil {
		t.Fatal(err)
	}
}

// heldReadRefusal is one held read the supervisor refused on the pinned object: its one refused fs line, which the
// reason file mirrors (the supervisor writes no separate refused line for it).
func (f *fixtureRun) heldReadRefusal(rule, path string) {
	f.emit(time.Millisecond, f.action(record.KindFS, record.SourceSeccomp, fxTID, rule, record.VerdictRefused,
		record.ReasonReadDenied, record.Unattributed(), record.FSPayload{Op: record.FSOpen, Path: path, Flags: 0x80000}))
}

// reasonReadsRef is the reason-reads fixture's run: one at tier landlock whose read opens were told to the supervisor
// for the reason channel (ADR 0077, record_minor 23).
var reasonReadsRef = record.RunRef{ID: runID(fixedStart, "r3as23"), Agent: "retriever"}

// generateReasonReads writes a short run at tier landlock under record: summary whose reads were notified for the
// reason channel, as `tego run` writes it for a contract with reason.reads: on, fs.write ["./out/"] and the built-in
// deny_read list (ADR 0077): run_start says reads_notified, why reason, and fs_reads direct, none-nested; the agent's cat of
// ~/.ssh/id_ed25519 is one refused read-denied fs line under fs.deny_read[~/.ssh] with mechanism landlock (source
// seccomp: the supervisor was told of the open and continued it, and Landlock refused it), and its refused mirror,
// which the reason file holds, says mechanism landlock too. The allowed read of out/a.txt has no line.
func generateReasonReads(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, reasonReadsRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.RecordMinor = record.MinorReasonReads
	start.Cwd = "/srv/proj"
	launcher := uint32(1000)
	start.LauncherUID = &launcher
	start.FSReads = &record.FSReads{Reads: record.FSReadsDirect, Why: record.FSReadsWhyNoneNested}
	start.ReadsNotified = &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyReason}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	f.exec(4*time.Millisecond, "/usr/bin/cat", []string{"cat", "/srv/u/.ssh/id_ed25519"}, 48262, 812_400_000_000, "", record.Unattributed())
	f.emit(time.Millisecond, f.action(record.KindFS, record.SourceSeccomp, fxTID, "fs.deny_read[~/.ssh]", record.VerdictRefused,
		record.ReasonReadDenied, record.Unattributed(),
		record.FSPayload{Op: record.FSOpen, Path: "/srv/u/.ssh/id_ed25519", Flags: 0x80000, Mechanism: record.MechanismLandlock}))
	// The mirror, as the runtime's pipeline writes it: no verdict, authority or attribution (pkg/spec/record Validate).
	m := f.action(record.KindRefused, record.SourceSeccomp, fxTID, "fs.deny_read[~/.ssh]", "", record.ReasonReadDenied, nil,
		record.RefusedPayload{Op: record.FSOpen, Target: "/srv/u/.ssh/id_ed25519", Mechanism: record.MechanismLandlock})
	m.Authority = ""
	f.emit(0, m)
	f.exec(6*time.Millisecond, "/usr/bin/cat", []string{"cat", "out/a.txt"}, 48263, 812_410_000_000, "", record.Unattributed())
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 1,
		Supervisor: record.Supervisor{Notifications: 9}}); err != nil {
		t.Fatal(err)
	}
}

// generateUserDenyWrite writes a short run at record minor 19 (ADR 0071) whose contract writes ./ and ./deploy/tmp/ and
// declares fs.deny_write: [./deploy/] at tier landlock: run_start's best_effort lists fs.deny_write, a write of the CI
// file in the entry is refused by the supervisor under fs.deny_write[./deploy/] with its refused line, and a write in
// the subtree the nested write entry reopens is allowed under that entry. Its run_start carries launcher_uid and
// fs_reads, as every run_start at MinorRunIdentity and MinorHeldReads or later does (no deny_read target lies inside a
// write entry, so its reads are direct).
func generateUserDenyWrite(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.RecordMinor = record.MinorUserDenyWrite
	launcher := uint32(1000)
	start.LauncherUID = &launcher
	start.FSReads = &record.FSReads{Reads: record.FSReadsDirect, Why: record.FSReadsWhyNoneNested}
	start.BestEffort = []string{"fs.deny_write"}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	a := record.Unattributed()
	const ci = "/home/u/proj/deploy/ci.yml"
	f.emit(0, f.action(record.KindFS, record.SourceSeccomp, fxTID, "fs.deny_write[./deploy/]", record.VerdictRefused,
		record.ReasonWriteOutsideContract, a, record.FSPayload{Op: record.FSOpen, Path: ci, Flags: 0x241}))
	f.emit(0, f.plain(record.KindRefused, record.SourceSeccomp, fxPID, fxTID, record.RefusedPayload{Op: record.FSOpen,
		Target: ci, Reason: record.ReasonWriteOutsideContract, Rule: "fs.deny_write[./deploy/]"}))
	f.emit(0, f.action(record.KindFS, record.SourceLandlock, fxTID, "fs.write[./deploy/tmp/]", record.VerdictAllow, "", a,
		record.FSPayload{Op: record.FSOpen, Path: "/home/u/proj/deploy/tmp/build.log", Flags: 0x241}))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 2, HeldMS: 1}}); err != nil {
		t.Fatal(err)
	}
}

// TestFixturesFrozen regenerates the fixtures into a temp directory and compares them byte for byte with the
// committed files; -update rewrites them. The generator is the spec's executable form.
func TestFixturesFrozen(t *testing.T) {
	root := t.TempDir()
	anchor := NewFileChainAnchor(filepath.Join(root, ChainLogFile))
	generateFixture(t, filepath.Join(root, "runs", testRef.ID), anchor)
	got := map[string][]byte{
		"run-fixture.jsonl": readFile(t, filepath.Join(root, "runs", testRef.ID, EventsFile)),
		"chain.log":         readFile(t, filepath.Join(root, ChainLogFile)),
	}
	kindsRoot := t.TempDir()
	generateKinds(t, filepath.Join(kindsRoot, testRef.ID), &memAnchor{})
	got["kinds.jsonl"] = readFile(t, filepath.Join(kindsRoot, testRef.ID, EventsFile))
	profilesRoot := t.TempDir()
	generateProfiles(t, filepath.Join(profilesRoot, profilesRef.ID), NewFileChainAnchor(filepath.Join(profilesRoot, ChainLogFile)))
	got["profiles.jsonl"] = readFile(t, filepath.Join(profilesRoot, profilesRef.ID, EventsFile))
	got["profiles.chain.log"] = readFile(t, filepath.Join(profilesRoot, ChainLogFile))
	hostRoot := t.TempDir()
	generateHostSockets(t, filepath.Join(hostRoot, testRef.ID), &memAnchor{})
	got["host-sockets.jsonl"] = readFile(t, filepath.Join(hostRoot, testRef.ID, EventsFile))
	identityRoot := t.TempDir()
	generateRunIdentity(t, filepath.Join(identityRoot, runIdentityRef.ID), NewFileChainAnchor(filepath.Join(identityRoot, ChainLogFile)))
	got["run-identity.jsonl"] = readFile(t, filepath.Join(identityRoot, runIdentityRef.ID, EventsFile))
	got["run-identity.chain.log"] = readFile(t, filepath.Join(identityRoot, ChainLogFile))
	heldRoot := t.TempDir()
	generateHeldReads(t, filepath.Join(heldRoot, heldReadsRef.ID), NewFileChainAnchor(filepath.Join(heldRoot, ChainLogFile)))
	got["held-reads.jsonl"] = readFile(t, filepath.Join(heldRoot, heldReadsRef.ID, EventsFile))
	got["held-reads.chain.log"] = readFile(t, filepath.Join(heldRoot, ChainLogFile))
	dwRoot := t.TempDir()
	generateUserDenyWrite(t, filepath.Join(dwRoot, testRef.ID), &memAnchor{})
	got["user-deny-write.jsonl"] = readFile(t, filepath.Join(dwRoot, testRef.ID, EventsFile))
	reasonRoot := t.TempDir()
	generateReasonReads(t, filepath.Join(reasonRoot, reasonReadsRef.ID), NewFileChainAnchor(filepath.Join(reasonRoot, ChainLogFile)))
	got["reason-reads.jsonl"] = readFile(t, filepath.Join(reasonRoot, reasonReadsRef.ID, EventsFile))
	got["reason-reads.chain.log"] = readFile(t, filepath.Join(reasonRoot, ChainLogFile))
	for name, content := range got {
		path := filepath.Join(fixturesDir, name)
		if *updateFixtures {
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run with -update to generate)", name, err)
		}
		if !bytes.Equal(want, content) {
			t.Errorf("%s differs from the generator output; run go test ./internal/ledger -run TestFixturesFrozen -update", name)
		}
	}
}

// TestFixtureLedgerReads: the fixture iterates, verifies against its anchor, and
// reads as ended.
func TestFixtureLedgerReads(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, testRef.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(fixturesDir, "run-fixture.jsonl"), filepath.Join(dir, EventsFile))
	copyFile(t, filepath.Join(fixturesDir, "chain.log"), filepath.Join(root, ChainLogFile))
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rep, err := r.Verify(context.Background(), NewFileChainAnchor(filepath.Join(root, ChainLogFile)))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Started || !rep.Ended || !rep.Anchored || rep.Lines < 90 {
		t.Fatalf("%+v", rep)
	}
	if s, err := r.State(); s != StateEnded || err != nil {
		t.Fatalf("state %s %v", s, err)
	}
	if refs, err := NewRunRepository(root).List(context.Background()); err != nil || len(refs) != 1 || refs[0] != testRef {
		t.Fatalf("List = %v %v", refs, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.WriteFile(dst, readFile(t, src), 0o600); err != nil {
		t.Fatal(err)
	}
}
