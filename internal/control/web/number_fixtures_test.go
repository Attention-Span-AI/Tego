// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/contractsrc"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/mcpact"
	"github.com/attention-span-ai/tego/internal/control/routeact"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type numberFixture struct{ name, body string }

var numberZeroLayers []func(*testing.T) []numberFixture

// numberBranchFixtures exercises real templates with explicit presentation-boundary
// data. These supplement the handler ledgers with paging, identity-list, tree and
// verification branches that small ledgers cannot reach.
func numberBranchFixtures(t *testing.T) []numberFixture {
	t.Helper()
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	et, err := eventPage()
	if err != nil {
		t.Fatal(err)
	}
	pages["event"] = et
	mp, err := mcpPageSet()
	if err != nil {
		t.Fatal(err)
	}
	pages["mcp-tools"] = mp["mcp-tools"]

	var out []numberFixture
	emit := func(set, name string, data any) {
		t.Helper()
		var b bytes.Buffer
		if err := pages[set].ExecuteTemplate(&b, name, data); err != nil {
			t.Fatalf("fixture %s/%s: %v", set, name, err)
		}
		out = append(out, numberFixture{set + "/" + name, b.String()})
	}
	p := func(data any) page {
		l := map[string]*liveRegion{}
		for _, ns := range pageRegions {
			for _, n := range ns {
				l[n] = &liveRegion{Name: n}
			}
		}
		for _, n := range layoutRegions {
			l[n] = &liveRegion{Name: n}
		}
		return page{Data: data, L: l}
	}
	emit("run", "blockwhy", true)
	emit("run", "blockwhy", false)
	emit("run", "forselect", "1h")
	run := &ledgerview.Run{ID: numRichRun, Agent: "Counter", Live: true, Start: time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)}
	emit("stop", "content", p(stopData{Run: run}))
	emit("overview", "r-ov-guide", p(overviewData{Total: 1, Guide: &setupGuide{Done: true}}))
	mirror := uint64(4)
	emit("logs", "logline", lineView{LV: &ledgerview.LineView{Run: run.ID, MirroredBy: &mirror}, Ev: ledgerview.Event{Verdict: "refused"}})
	emit("compare", "cmpcell", withNumbers(ledgerview.CmpCell{Seen: true, Tone: "muted", Word: "Refused"}, countScopes{}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "unused", Drift: &rulesview.Drifted{FromText: true}}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "least-privilege", Keep: []string{"fs.deny_read[key]"}, Learn: &rulesview.Learned{}, Story: ledgerview.Verdict{Kind: "leak"}, Withheld: []string{"example.test"}}))
	for _, registry := range []bool{false, true} {
		emit("rules-new", "content", p(newData{Mode: "run", Plan: &rules.NewPlan{Registry: registry, Name: "fixture", FromRun: run.ID, Withheld: []string{"example.test"}, Text: []byte("agent: fixture"), OK: true}, Form: rules.NewReq{Withhold: []string{"example.test"}}}))
	}
	// The release line's surfaces: the builder's full view and compiler output, the general contract's source facts,
	// the compiler's diagnostics on a contract not run yet and the record refusals of a run page.
	emit("rules-new", "content", p(newData{View: "full", Mode: "presets", To: "registry", Editor: "version: 0\nname: fixture", Fields: []builderField{{Key: "net.proxy.http2", Meaning: "Allow HTTP/2 on declared model listeners."}}, Plan: &rules.NewPlan{Name: "fixture", File: "/work/agent.yaml", Text: []byte("version: 0"), OK: true, Diagnostics: []string{"error: /work/demo.yaml:1:10: version: bad"}}, Text: "version: 0"}))
	owner := 0
	emit("rules", "content", p(rulesData{General: &contractsrc.General{State: "valid", Scope: "System and user", Name: "general", Hash: "0a0a", Note: "A general contract is selected.",
		Sources:     []contractsrc.Source{{Layer: "system", Path: "/etc/tego/general.yaml", State: "read", SHA256: "0a0a", Resolved: "/etc/tego/general.yaml", Owner: &owner, Mode: "0644", Walk: []string{"/etc"}, Reason: "read"}},
		Profiles:    []contractsrc.Profile{{Name: "base", Kind: "user", SHA256: "0b0b"}},
		Diagnostics: []contractsrc.Diagnostic{{File: "/etc/tego/general.yaml", Line: 1, Column: 2, Code: "x", Message: "m", Severity: "warning"}}}, BaselineState: "No machine baseline entries are configured in this snapshot."}))
	emit("rules", "content", p(rulesData{NotRun: &notRunData{Plan: &rules.NewPlan{Diagnostics: []string{"error: /work/demo.yaml:1:10: version: bad"}}}}))
	refused := *run
	refused.ReadError = "line at byte offset 15278: record: malformed line"
	refused.LineErrors = []ledgerview.LineRefusal{{Offset: 15278, Reason: "line at byte offset 15278: record: malformed line"}}
	emit("run", "r-run-top", p(runData{Run: &refused}))
	f := &factsView{Local: "25 Oct 2026", UTC: "2026-10-25", LV: &ledgerview.LineView{}, MoreAbove: 2, ChainHead: "The programs above it: the nearest 1 of 3", Steps: []procStep{{ProcRef: ledgerview.ProcRef{PID: 1}, Label: "ancestor"}, {ProcRef: ledgerview.ProcRef{PID: 2}, Label: "self", Self: true}}}
	emit("event", "evwhat", eventData{Run: run, F: f, FullCommand: strings.Repeat("command ", 100)})
	emit("event", "evfacts", eventData{Run: run, F: f})
	unrecordedFacts := *f
	unrecordedFacts.Steps = []procStep{{ProcRef: ledgerview.ProcRef{PID: 3, Unrecorded: true}}, {ProcRef: ledgerview.ProcRef{PID: 4}, Self: true}}
	emit("event", "evfacts", eventData{Run: run, F: &unrecordedFacts})
	emit("event", "evchanges", eventData{Run: run, Changes: []changeRow{{FeedEntry: rules.FeedEntry{ID: "c1", Words: "May run git on 127.0.0.1:8484 → Cannot run git", Direction: "narrows", UndoneBy: "u1"}, Href: "/rules/change?c=00112233aabbccdd#h-hist"}}})
	for _, proc := range []ledgerview.ProcRef{{Unrecorded: true}, {}} {
		nf := *f
		nf.LV = &ledgerview.LineView{Proc: &proc}
		emit("event", "evfacts", eventData{Run: run, F: &nf})
	}
	emit("rules", "content", p(rulesData{Run: run, V: &rulesview.InForceView{}, Mode: "adjustable", Fence: &fenceView{Running: true}}))
	emit("rules", "content", p(rulesData{Run: run, V: &rulesview.InForceView{}, Mode: "adjustable", Fence: &fenceView{Running: true, Rows: []fenceRowView{{
		FenceRow: ledgerview.FenceRow{Kind: "exec", Value: "/usr/bin/psql", State: ledgerview.FenceLifted, Rule: "live.fence[exec:/usr/bin/psql]", LiftNote: "ticket 4411"},
		What:     "Run /usr/bin/psql", Chip: "Lifted for this run", ChipClass: "b-neutral", Verb: "Lift", Done: "Lifted"}}}}))
	emit("run", "firstrun-step", nil)
	emit("run", "hl-dest", withNumbers(map[string]any{"Run": run.ID, "V": ledgerview.Dest{Key: "second.example", NearSecret: true, Observed: 1}, "Obs": true, "Ref": "", "Lead": "first.example"}, countScopes{}))
	for _, state := range []struct {
		paused  bool
		why     string
		ask     pauseAsk
		pending bool
	}{
		{true, "run-paused", pauseAsk{Takes: true}, false},
		{true, "resume-failed", pauseAsk{Takes: true}, false},
		{true, "run-paused", pauseAsk{Takes: true, Waiting: true, At: run.Start}, false},
		{false, "", pauseAsk{Takes: true, Waiting: true, Paused: true, At: run.Start}, false},
		{false, "pause-failed", pauseAsk{Takes: true}, true},
		{false, "pause-failed", pauseAsk{Takes: true}, false},
	} {
		pr := *run
		if state.pending {
			pr.Pending = []ledgerview.Ask{{AskID: "pending", Run: run.ID, TS: run.Start}}
		}
		facts := ledgerview.LiveFacts{Paused: state.paused, Pause: state.why, PausedAt: run.Start, PauseSeq: 3}
		emit("run", "r-run-top", p(runData{Run: &pr, Live: liveView{Facts: facts, Pause: state.ask}}))
	}

	banner := p(runData{Run: run})
	banner.Nav = "run"
	banner.Pending = 1
	banner.Asks = []ledgerview.Ask{{Run: run.ID, AskID: "file", Target: "/work/complete/path/file.txt", Op: "read", TS: run.Start}}
	banner.AskMeta = map[string]askMeta{run.ID: {Cwd: "/work"}}
	emit("run", "askbanner", banner)
	emit("livefence", "content", p(liftData{Run: run, Err: "unavailable"}))

	emit("event", "r-act", p(eventData{Run: run, Act: &actView{Plan: &rules.ActPlan{Err: "unsupported action"}}}))
	emit("event", "r-act", p(eventData{Run: run, Act: &actView{Plan: &rules.ActPlan{Saved: true}}}))
	emit("run", "chainpill", ledgerview.Chain{State: ledgerview.ChainVerified, Lines: 3})
	emit("livefence", "content", p(liftData{Run: run, Permanent: true}))
	for _, live := range []bool{false, true} {
		emit("rules", "content", p(rulesData{Run: run, V: &rulesview.InForceView{}, Pending: &pendingView{Differs: true, Live: live}}))
	}
	pausedFacts := ledgerview.LiveFacts{Paused: true, PausedAt: run.Start, PauseSeq: 3}
	emit("run", "r-run-top", p(runData{Run: run, Live: liveView{Facts: pausedFacts, Pause: pauseAsk{Takes: true}}}))

	emit("detections", "content", p(detectionsData{Routine: 1, Leaks: []leakRow{{}}}))
	lostRun := *run
	lostRun.Live = false
	lostRun.Pending = []ledgerview.Ask{{Run: run.ID, AskID: "lost", TS: run.Start}}
	emit("run", "r-run-hl", p(runData{Run: &lostRun}))
	lostSignal := &ledgerview.RunSignal{Approvals: []ledgerview.Approval{{AskID: "lost", State: "lost"}}}
	emit("run", "highlights", withNumbers(runData{Run: &lostRun, Signal: lostSignal}, countScopes{}))
	emit("mcp-tools", "content", p(mcpData{State: &mcpact.State{Run: run.ID, Running: true, Servers: []mcpact.Server{{Name: "tools", Relayed: true, Tools: []mcpact.Tool{{Name: "lookup"}}}}}}))
	plan := &rules.ChangePlan{Sentences: []rules.Sentence{{After: "Allow example.test"}}}
	emit("rules-preview", "content", p(previewData{P: plan}))
	emit("rules-saved", "content", p(savedData{Applied: &rules.Applied{Plan: plan}}))
	completeReceipt := &receipt.Receipt{Run: run.ID, Files: receipt.Files{Recorded: true}, Coverage: receipt.Coverage{Complete: true}}
	emit("run", "receipt", &receiptView{R: completeReceipt})
	unknownReceipt := *completeReceipt
	unknownReceipt.SensitiveReadsUnknown = true
	emit("run", "receipt", &receiptView{R: &unknownReceipt})
	// A run under the root-only approval floor: the receipt names the authority and each answer's recorded root actor.
	localReceipt := *completeReceipt
	localReceipt.LocalApprovalAuthority = &record.LocalApprovalAuthority{Mode: "owner_only", SHA256: strings.Repeat("ab", 32), AgentUID: 1001}
	localReceipt.Asks = receipt.Asks{Asked: 1, Approved: 1, List: []receipt.Ask{{
		AskID: "q-local", Op: "read", Target: "/data/held", Answer: "approved",
		AnswerAuthority: record.AnswerAuthority{Actor: &record.LocalApprovalActor{UID: 0, PID: 42, StartBootNS: 10000000, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}},
	}}}
	emit("run", "receipt", &receiptView{R: &localReceipt})

	emit("approvals", "content", p(approvalsData{Lost: []ledgerview.Ask{{Run: run.ID, Agent: "Counter", AskID: "lost"}}, Now: run.Start}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "least-privilege", Drift: &rulesview.Drifted{Declared: 1}, Cut: []string{"net.allow[example.test]"}}))

	emit("run", "r-run-tab", p(runData{Run: run, Tab: "unused", Drift: &rulesview.Drifted{Declared: 1, Unused: 1, Rows: []rulesview.DriftRow{{Unused: true}}}}))

	emit("event", "r-act", p(eventData{Run: run, Act: &actView{Plan: &rules.ActPlan{Kind: "net"}}}))
	emit("event", "r-act", p(eventData{Run: run, Act: &actView{Plan: &rules.ActPlan{Kind: "exec"}, Held: &heldView{State: "recorded_only"}}}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "least-privilege", Learn: &rulesview.Learned{Err: "test source could not be read"}}))
	emit("rules-change", "content", p(changeData{C: &rules.ContractRef{Ref: "fixture"}, CanRaw: true, Raw: &rawView{Plan: &rules.ChangePlan{Err: "There is no change", Nothing: true}}}))
	emit("rules-preview", "content", p(previewData{P: &rules.ChangePlan{Nothing: true, Err: "There is no change"}}))

	emit("event", "evblob", map[string]any{"Run": run.ID, "Seq": 3, "Blob": &ledgerview.BlobRef{Size: 128, Verified: true}})
	for _, chain := range []ledgerview.LedgerChain{{Verifying: 1, Checked: 1}, {Checked: 1, Skipped: 2}} {
		emit("overview", "r-ov-tiles", p(overviewData{Total: 1, Chain: chain, MaxChain: 20, Charts: ovCharts{Unrecorded: 1}}))
	}
	emit("overview", "r-ov-recent", p(overviewData{Total: 1}))
	emit("overview", "refrow", withNumbers(map[string]any{"Run": "/home/u", "Fold": progFold{}, "V": ledgerview.Row{Event: ledgerview.Event{Run: numRichRun}, Count: 3}}, countScopes{}))
	setup := guidetest.Make(t, guidetest.Fresh)
	srv := newServer(t, setup.Ledger)
	srv.cfg.Guide = func(context.Context) guide.Inputs { in := setup.Inputs(t); in.Dir = ""; return in }
	snap, err := ledgerview.Load(setup.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	emit("overview", "guide", srv.setupGuide(context.Background(), snap))
	emit("run", "chainpill", ledgerview.Chain{State: ledgerview.ChainVerified, Anchored: true, Lines: 9})
	emit("runs", "r-runs-head", p(runsData{Count: map[string]int{"all": 3, "running": 1, "lost": 1}}))
	emit("runs", "r-runs-foot", p(runsData{Live: []*ledgerview.Run{run}, Runs: []*ledgerview.Run{run}, Older: "older", From: 2, To: 3, Rest: 8}))
	lost := *run
	lost.Live = false
	lost.Pending = []ledgerview.Ask{{AskID: "old", Run: numRichRun}}
	emit("run", "r-run-top", p(runData{Run: &lost}))
	emit("run", "r-tl-foot", p(runData{Run: run, Tab: "timeline", Total: 20, Shown: 3}))
	emit("logs", "r-logs-head", p(logsData{ExportLines: 10, ExportMore: 2}))
	emit("logs", "r-logs-facets", p(logsData{Facets: []facetGroup{{Name: "Program", More: 2, Items: []facetItem{{Label: "curl", Count: 1}}}}}))
	emit("logs", "content", p(logsData{RunsMore: 1}))
	emit("logs", "lgroups", withNumbers(logsData{Grouped: []groupView{{Lines: 1}}, GroupInfo: ledgerview.Grouped{Keyless: 2}}, countScopes{}))
	// Inline-line fragments use the same handler and rendered attributes as the page.
	root := numberLedger(t)
	s := newServer(t, root)
	c := login(t, s)
	out = append(out, numberFixture{"logs/line", getRaw(t, s, c, "/logs/line?run="+numRichRun+"&seq=3")})
	for _, path := range []string{"/logs?run=" + numRichRun, "/logs?noise=show", "/runs?state=lost"} {
		out = append(out, numberFixture{path, getRaw(t, s, c, path)})
	}
	group := ledgerview.Group{Event: ledgerview.Event{Run: numRichRun}, First: run.Start, Last: run.Start, Count: 3, Hosts: 2, Ports: []string{"80", "443"}, Targets: []string{"host-a", "host-b"}, Subject: "example.com", Class: "net"}
	group.NearSecret = true
	emit("detections", "content", p(detectionsData{Low: []detection{{Group: group, Run: numRichRun}}, Total: 1}))
	emit("investigate", "content", p(investigateData{D: detection{Group: group}, Pos: 1, OfSev: 1}))
	emit("run", "rgroup", withNumbers(group, countScopes{}))
	group.Ports = nil
	emit("run", "rgroup", withNumbers(group, countScopes{}))
	sig := &ledgerview.RunSignal{BackgroundDests: 2, BackgroundDestLines: 4, Blocks: []ledgerview.BlockHit{{Rule: "live.block[exec:/bin/curl]", Value: "exec:/bin/curl", N: 2}}, Unanswered: 1}
	for i := 0; i < 10; i++ {
		sig.Outbound = append(sig.Outbound, ledgerview.Dest{Key: fmt.Sprintf("host-%d.example", i), Observed: 1, NearSecret: true})
		sig.Programs = append(sig.Programs, ledgerview.ProgramHit{Program: fmt.Sprintf("program-%d", i), N: 2})
		sig.Approvals = append(sig.Approvals, ledgerview.Approval{AskID: "repeated-target", Target: "example.com", State: "approved", Rule: "net.ask[example.com]"})
	}
	sig.Approvals = append(sig.Approvals, ledgerview.Approval{AskID: "auto-answer", State: "approved", By: "standing:repeated-target"})
	emit("run", "highlights", withNumbers(runData{Run: run, Signal: sig, Blocks: []liveblock.Entry{{Kind: liveblock.KindExec, Value: "/bin/curl"}}, Now: time.Now()}, countScopes{}))
	watched := *run
	watched.Tier = "observe"
	emit("run", "highlights", withNumbers(runData{Run: &watched, Signal: sig}, countScopes{}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "least-privilege", Learn: &rulesview.Learned{Left: 1}}))
	// The receipt fixture comes from a complete streaming builder before its display
	// boundaries are varied; totals and list limits are the receipt's own fields.
	rv := loadReceipt(context.Background(), root, numRichRun, ledgerview.Sensitive{}, ledgerview.Pricing{})
	if rv.Err != "" {
		t.Fatal(rv.Err)
	}
	// Empty full-record receipt: exercise each zero activity branch, not only a rich receipt.
	emit("run", "receipt", &receiptView{R: &receipt.Receipt{Run: numRichRun, Files: receipt.Files{Recorded: true}}})
	emit("run", "receipt", (*receiptView)(nil))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "unused", Drift: &rulesview.Drifted{NoContract: true}}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "unused", Drift: &rulesview.Drifted{}}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "unused", Drift: &rulesview.Drifted{Unknown: true}}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "least-privilege", Drift: &rulesview.Drifted{Unknown: true}}))
	emit("run", "r-run-tab", p(runData{Run: run, Tab: "least-privilege", Drift: &rulesview.Drifted{Declared: 1}}))
	rv.R.Files.Recorded = true
	rv.R.SensitiveReadsTruncated = true
	for i := 0; i < 45; i++ {
		rv.R.Files.Written = append(rv.R.Files.Written, fmt.Sprintf("/work/file-%d", i))
	}
	rv.R.Files.Renamed = []receipt.Rename{{From: "/work/a", To: "/work/b"}}
	for i := 0; i < 25; i++ {
		rv.R.SensitiveReads = append(rv.R.SensitiveReads, receipt.SensitiveRead{Path: fmt.Sprintf("/home/u/.ssh/key-%d", i), Verdicts: receipt.Verdicts{Refused: 1}})
	}
	rv.R.Refusals.Total = 30
	rv.R.Tokens.Metered = 2
	rv.R.Tokens.Unpriced = 0
	rv.R.Asks.TimedOut = 1
	rv.R.Tokens.Recorded = true
	rv.R.Tokens.ModelCalls = 2
	rv.R.Tokens.In = 12
	rv.R.Tokens.Out = 8
	rv.R.Stall.Recorded = true
	rv.R.Stall.Windows = 1
	rv.R.Stall.Minutes = 2
	rv.R.Tokens.CostText = "$0.001 est."
	rv.R.Notes = []string{"The test fixture contains 2 gap lines"}
	for i := 0; i < 20; i++ {
		rv.R.Refusals.List = append(rv.R.Refusals.List, receipt.Refusal{Seq: uint64(i), Op: "read", Target: "/home/u/.ssh/key"})
	}
	emit("run", "receipt", rv)
	rv.R.Refusals.ByRule = nil
	emit("run", "receipt", rv)
	node := &ledgerview.ProcNode{Run: numRichRun, Name: "curl", PID: 20, Start: run.Start}
	item := &procItem{N: node, More: 2, Hosts: "example.com", HostsMore: 2, Tried: "/bin/curl", Tries: 3, Execs: []procExec{{ProcExec: ledgerview.ProcExec{Refused: true, Count: 3}, Others: 2}}}
	emit("run", "procs", &procsView{Tree: &ledgerview.ProcTree{Run: numRichRun, Procs: 3, NoPID: 1, Unrecorded: 1}, Root: item, Cut: 2, Notes: 1})
	emit("rules", "content", p(rulesData{Run: run, V: &rulesview.InForceView{}, Groups: []ruleGroup{{ID: "net", Title: "Network", Default: "Refuses all other destinations", DefaultHits: 2}}, EndedLive: []ruleRow{{Sentence: "Refused curl", Hits: 1}}}))
	emit("rules", "content", p(rulesData{NotRun: &notRunData{Plan: &rules.NewPlan{}, Groups: []newGroup{{ruleGroup: ruleGroup{ID: "net", Title: "Network", Rows: []ruleRow{{Sentence: "Allow example.com"}}}, More: []ruleRow{{Sentence: "Allow example.org"}}}}}}))
	// Explicit chooser boundaries and hidden/background comparison branches.
	emit("error", "content", p(errorData{Heading: "The ledger could not be read", Technical: true, Text: "read /ledger/12: not a directory"}))
	one := &ledgerview.Run{ID: cleanRun, Agent: "Only", Start: run.Start}
	emit("compare", "content", p(compareData{Runs: []*ledgerview.Run{one}}))
	emit("compare", "cmpcellw", withNumbers(ledgerview.CmpCell{Seen: true, Word: "Got through", Where: []string{"127.0.0.1:8801"}}, countScopes{}))
	cmp := &ledgerview.Comparison{A: ledgerview.CmpSide{Run: run}, B: ledgerview.CmpSide{Run: one}, Folded: 2, Rows: []ledgerview.CmpRow{{Class: "exec", Target: "curl", A: ledgerview.CmpCell{Seen: true, Word: "Allowed", Detail: "×2"}}}}
	emit("compare", "content", p(compareData{Runs: []*ledgerview.Run{run, one}, Cmp: cmp, Hidden: 1, Shown: cmp.Rows, AllURL: "/compare?all=1"}))
	// Route request counts and changes are from a complete strict stream, independently
	// of the dashboard's bounded event windows.
	routePages, err := routesPageSet()
	if err != nil {
		t.Fatal(err)
	}
	var preview bytes.Buffer
	if err := routePages["model-routes-preview"].ExecuteTemplate(&preview, "content", p(routesPreviewData{Plan: &routeact.Plan{Run: run.ID}})); err != nil {
		t.Fatal(err)
	}
	out = append(out, numberFixture{"routes/unchanged", preview.String()})
	var rb bytes.Buffer
	st := &routeact.State{Run: cleanRun, Models: []routeact.Model{{Endpoint: "api.example.com:443", Route: "direct", SendsTo: "api.example.com:443", Options: []routeact.Option{{Name: "direct", Authority: "api.example.com:443", Requests: 2}, {Name: "local", Authority: "127.0.0.1:11434"}}, Changes: []record.ModelRouteChange{{Route: "local", Authority: "127.0.0.1:11434", At: run.Start}}}, {Endpoint: "direct.example.com:443", Options: []routeact.Option{{Name: "direct"}}}}}
	if err := routePages["model-routes"].ExecuteTemplate(&rb, "content", p(routesData{State: st})); err != nil {
		t.Fatal(err)
	}
	out = append(out, numberFixture{"routes/content", rb.String()})
	emit("severity", "content", p(severityData{File: "/work/severity.json"}))
	emit("overview", "r-ov-tiles", p(overviewData{Guide: &setupGuide{}}))
	emit("overview", "r-ov-tiles", p(overviewData{Total: 1, Chain: ledgerview.LedgerChain{Broken: &ledgerview.Chain{Run: numRichRun}}}))
	emit("rules-change", "r-change", p(changeData{C: &rules.ContractRef{Ref: "fixture"}, Groups: []changeGroup{{groupMeta: groupMeta{Key: "net.allow", Title: "Network", Example: "example.test", Hint: "One host"}}}}))

	empty := newServer(t, t.TempDir())
	ec := login(t, empty)
	for _, path := range []string{"/", "/runs", "/logs", "/detections", "/approvals", "/approvals?tab=history", "/rules", "/mcp", "/compare", "/machine", "/routes", "/glossary?q=missing"} {
		out = append(out, numberFixture{"empty" + path, getRaw(t, empty, ec, path)})
	}
	for _, layer := range numberZeroLayers {
		out = append(out, layer(t)...)
	}

	return out
}
