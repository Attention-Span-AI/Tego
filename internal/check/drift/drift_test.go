// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fixturePath is the frozen run every view is built against (docs/P0-DESIGN.md §10).
var fixturePath = filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl")

// fixtureReader opens the frozen fixture as a run directory.
func fixtureReader(t *testing.T) *ledger.Reader {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return readerOver(t, data)
}

// readerOver writes one ledger's bytes into a fresh run directory and opens it.
func readerOver(t *testing.T, data []byte) *ledger.Reader {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// fixtureHash is the contract hash the fixture's run_start carries.
func fixtureHash() [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = 0x7a
	}
	return h
}

// fixtureTable is the retriever contract the frozen run declared, compiled:
// the entries the run used, plus one unused entry per section and one unused
// MCP server, so R14 and R15 have something to find.
func fixtureTable() *agent.RuleTable {
	return &agent.RuleTable{
		Hash: fixtureHash(),
		FS: []agent.FSRule{
			{Path: "/home/u/proj/out", Kind: agent.FSWrite, Raw: "./out", Access: agent.AccessWriteSet},
			{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, Raw: "~/.ssh"},
			{Path: "/home/u/proj/config", Kind: agent.FSWatch, Raw: "./config"},
			{Path: "/home/u/.tego/runs", Kind: agent.FSImplicit},
		},
		Net: []agent.NetRule{
			{Raw: "api.github.com", Host: "api.github.com", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow},
			{Raw: "api.internal:8080", Host: "api.internal", Port: 8080, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow},
		},
		Exec: []agent.ExecRule{
			{Raw: "rg", Basename: "rg", Verdict: agent.VerdictAllow, Source: "exec.allow"},
			{Raw: "git", Basename: "git", Verdict: agent.VerdictAllow, Source: "exec.allow"},
			{Raw: "cat", Basename: "cat", Verdict: agent.VerdictAllow, Source: "exec.allow"},
			{Raw: "gh", Basename: "gh", Verdict: agent.VerdictAllow, Source: "exec.allow"},
			{Raw: "jq", Basename: "jq", Verdict: agent.VerdictAllow, Source: "exec.allow"},
			{Basename: "python3.12", Verdict: agent.VerdictAllow, Source: "command"},
			{Basename: "node", Verdict: agent.VerdictAllow, Source: "mcp:fs"},
		},
		Contract: &agent.Contract{
			Name:   "retriever",
			MCP:    []agent.MCPServer{{Name: "fs"}, {Name: "postgres"}},
			Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}},
		},
	}
}

// find returns one rule's counts from a section.
func find(counts []RuleCount, rule string) (RuleCount, bool) {
	for _, c := range counts {
		if c.Rule == rule {
			return c, true
		}
	}
	return RuleCount{}, false
}

// TestComputeFixture is limits-check-doctor-cli.md R13, R14, R15 and R16 against the frozen run: every rule the run
// recorded is counted in its own bucket, every declared entry appears even
// with no events, and the contract hash matches what run_start recorded.
func TestComputeFixture(t *testing.T) {
	rep, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if rep.Run != "r-3f9c2a1b-0dllq06ts7400-k7m2pq" || rep.Agent != "retriever" || rep.Runs != 1 {
		t.Errorf("identity: %q %q %d", rep.Run, rep.Agent, rep.Runs)
	}
	if rep.ContractHash != hex.EncodeToString(bytes.Repeat([]byte{0x7a}, 32)) {
		t.Errorf("contract hash %q", rep.ContractHash)
	}
	if rep.CurrentHash != rep.ContractHash || rep.HashChanged {
		t.Errorf("hash: current %q changed %v", rep.CurrentHash, rep.HashChanged)
	}
	cases := []struct {
		section  Section
		counts   []RuleCount
		rule     string
		declared bool
		want     RuleCount
	}{
		{SectionFS, rep.FS, "fs.write[./out]", true, RuleCount{Allow: 10}},
		{SectionFS, rep.FS, "fs.deny_read[~/.ssh]", true, RuleCount{Refused: 1}},
		{SectionFS, rep.FS, "fs.watch[./config]", true, RuleCount{}},
		// The fixture names its aggregated reads fs.read[.], a rule kind the
		// compiled table has no entry for: an observed rule the contract does
		// not declare, which is exactly what drift is for.
		{SectionFS, rep.FS, "fs.read[.]", false, RuleCount{Allow: 6}},
		{SectionNet, rep.Net, "net[api.github.com]", true, RuleCount{Allow: 1}},
		{SectionNet, rep.Net, "models[anthropic]", true, RuleCount{Allow: 1}},
		{SectionNet, rep.Net, "net[api.internal:8080]", true, RuleCount{}},
		{SectionExec, rep.Exec, "exec[rg]", true, RuleCount{Allow: 3}},
		{SectionExec, rep.Exec, "exec[git]", true, RuleCount{Allow: 2}},
		{SectionExec, rep.Exec, "exec[cat]", true, RuleCount{Allow: 1}},
		{SectionExec, rep.Exec, "exec[gh]", true, RuleCount{Allow: 1}},
		{SectionExec, rep.Exec, "exec[jq]", true, RuleCount{}},
		{SectionExec, rep.Exec, "exec[python3.12]", true, RuleCount{Allow: 2}},
		{SectionExec, rep.Exec, "exec[node]", true, RuleCount{Allow: 1}},
		{SectionMCP, rep.MCP, "mcp[fs]", true, RuleCount{Allow: 3}},
		{SectionMCP, rep.MCP, "mcp[postgres]", true, RuleCount{}},
	}
	for _, tc := range cases {
		t.Run(string(tc.section)+"/"+tc.rule, func(t *testing.T) {
			got, ok := find(tc.counts, tc.rule)
			if !ok {
				t.Fatalf("missing from the %s section", tc.section)
			}
			want := tc.want
			want.Section, want.Rule, want.Declared = tc.section, tc.rule, tc.declared
			if got != want {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
	// Declared but never used, in every section.
	if want := []string{"exec[jq]", "fs.watch[./config]", "net[api.internal:8080]"}; !slices.Equal(rep.Undone, want) {
		t.Errorf("undone %v, want %v", rep.Undone, want)
	}
	if want := []string{"mcp[postgres]"}; !slices.Equal(rep.UnusedMCP, want) {
		t.Errorf("unused mcp %v, want %v", rep.UnusedMCP, want)
	}
	if !rep.Drifted() {
		t.Error("a refusal and an undone entry are drift")
	}
}

// TestComputePartitionsTheLedger is limits-check-doctor-cli.md I4 (and R13): the buckets partition the run's action
// events exactly — nothing counted twice (the refused event mirrors the fs
// event that already carried verdict=refused, R13), nothing dropped.
func TestComputePartitionsTheLedger(t *testing.T) {
	rep, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	sum := 0
	for _, s := range rep.Sections() {
		for _, c := range s.Counts {
			sum += c.Total()
		}
	}
	if sum != rep.Actions {
		t.Errorf("counts sum to %d, report says %d actions", sum, rep.Actions)
	}
	if sum != countActions(t) {
		t.Errorf("counts sum to %d, the fixture holds %d action events", sum, countActions(t))
	}
}

// countActions counts the fixture's fs, net, exec and mcp lines straight from
// the file, independently of the reader.
func countActions(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		switch e.Kind {
		case "fs", "net", "exec", "mcp":
			n++
		}
	}
	return n
}

// TestComputeHashChanged: the contract on disk was recompiled and no
// longer hashes to what the run recorded.
func TestComputeHashChanged(t *testing.T) {
	rt := fixtureTable()
	rt.Hash = [32]byte{0xde, 0xad, 0xbe, 0xef}
	rep, err := Compute(fixtureReader(t), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !rep.HashChanged || rep.CurrentHash == rep.ContractHash {
		t.Errorf("hash: %q -> %q changed %v", rep.ContractHash, rep.CurrentHash, rep.HashChanged)
	}
	if !rep.Drifted() {
		t.Error("a changed contract is drift")
	}
}

// TestComputeWithoutContract is §6 case 23: the run directory's contract.yaml
// copy is missing, so every observed rule is undeclared, CurrentHash is empty
// and nothing panics.
// (limits-check-doctor-cli.md E23.)
func TestComputeWithoutContract(t *testing.T) {
	for _, rt := range []*agent.RuleTable{nil, {}} {
		rep, err := Compute(fixtureReader(t), rt)
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		if rep.CurrentHash != "" || rep.HashChanged {
			t.Errorf("current hash %q changed %v", rep.CurrentHash, rep.HashChanged)
		}
		if len(rep.Undone) != 0 || len(rep.UnusedMCP) != 0 {
			t.Errorf("nothing is declared, so nothing is undone: %v %v", rep.Undone, rep.UnusedMCP)
		}
		for _, s := range rep.Sections() {
			for _, c := range s.Counts {
				if c.Declared {
					t.Errorf("%s: %q reported as declared", s.Section, c.Rule)
				}
			}
		}
		if rep.Actions != countActions(t) {
			t.Errorf("actions %d, want %d", rep.Actions, countActions(t))
		}
	}
}

// TestComputeEmptyAndTorn covers the two ledger shapes §6 cases 1-3 name: an
// empty run reports nothing, and a torn middle line is fatal.
func TestComputeEmptyAndTorn(t *testing.T) {
	rep, err := Compute(readerOver(t, nil), fixtureTable())
	if err != nil {
		t.Fatalf("empty ledger: %v", err)
	}
	if rep.Actions != 0 || rep.Run != "" {
		t.Errorf("empty ledger: %+v", rep)
	}
	if !rep.Drifted() {
		t.Error("a run that used nothing it declared is drift")
	}

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	lines[3] = []byte(`{"v":1,"seq":3,"kind":`) // a middle line the writer could never produce
	torn := append(bytes.Join(lines, []byte("\n")), '\n')
	if _, err := Compute(readerOver(t, torn), fixtureTable()); err == nil || !errors.Is(err, ErrRead) {
		t.Errorf("torn middle line: %v", err)
	}
	if _, err := Compute(nil, fixtureTable()); err == nil {
		t.Error("nil reader accepted")
	}
}

// TestAggregate is limits-check-doctor-cli.md R17: counts sum, Undone and UnusedMCP come from the sum, and the
// distinct contract hashes are listed with their run counts.
func TestAggregate(t *testing.T) {
	first, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	// A second run of the same agent: same ledger, a contract that has moved
	// on, and jq exercised so it is no longer undone for the agent.
	second, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	second.ContractHash = strings.Repeat("b", 64)
	for i := range second.Exec {
		if second.Exec[i].Rule == "exec[jq]" {
			second.Exec[i].Allow = 1
		}
	}
	second.Undone = []string{"fs.watch[./config]", "net[api.internal:8080]"}

	out, err := Aggregate([]*Report{first, second})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if out.Runs != 2 || out.Agent != "retriever" || out.Run != "" {
		t.Errorf("identity: %+v", out)
	}
	if got, _ := find(out.Exec, "exec[rg]"); got.Allow != 6 {
		t.Errorf("exec[rg] allow %d, want 6", got.Allow)
	}
	if got, _ := find(out.Exec, "exec[jq]"); got.Allow != 1 || !got.Declared {
		t.Errorf("exec[jq] %+v", got)
	}
	// Intersection: jq ran in one run, so it is not undone for the agent.
	if want := []string{"fs.watch[./config]", "net[api.internal:8080]"}; !slices.Equal(out.Undone, want) {
		t.Errorf("undone %v, want %v", out.Undone, want)
	}
	if want := []string{"mcp[postgres]"}; !slices.Equal(out.UnusedMCP, want) {
		t.Errorf("unused mcp %v, want %v", out.UnusedMCP, want)
	}
	if !out.HashChanged || len(out.Hashes) != 2 {
		t.Errorf("hashes %+v changed %v", out.Hashes, out.HashChanged)
	}
	for _, h := range out.Hashes {
		if h.Runs != 1 {
			t.Errorf("hash %s: %d runs", h.Hash, h.Runs)
		}
	}
	if out.Actions != first.Actions+second.Actions {
		t.Errorf("actions %d", out.Actions)
	}

	if _, err := Aggregate(nil); !errors.Is(err, ErrMixedAgent) {
		t.Errorf("empty list: %v", err)
	}
	other := &Report{Agent: "other", Runs: 1}
	if _, err := Aggregate([]*Report{first, other}); !errors.Is(err, ErrMixedAgent) {
		t.Errorf("mixed agents: %v", err)
	}
	if _, err := Aggregate([]*Report{first, nil}); err == nil {
		t.Error("nil report accepted")
	}
}

// TestAggregateOneRun keeps a single-run aggregate identical to the report it
// came from, so `drift --aggregate` on a first run is not a special case.
func TestAggregateOneRun(t *testing.T) {
	rep, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	out, err := Aggregate([]*Report{rep})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if out.Runs != 1 || !slices.Equal(out.Undone, rep.Undone) || !slices.Equal(out.UnusedMCP, rep.UnusedMCP) {
		t.Errorf("got %+v, want the single report's findings", out)
	}
	if out.HashChanged || out.ContractHash != rep.ContractHash {
		t.Errorf("hash %q changed %v", out.ContractHash, out.HashChanged)
	}
	for _, s := range out.Sections() {
		for _, c := range s.Counts {
			orig, ok := find(sectionOfReport(rep, s.Section), c.Rule)
			if !ok || orig != c {
				t.Errorf("%s %q: %+v vs %+v", s.Section, c.Rule, c, orig)
			}
		}
	}
}

// sectionOfReport picks one section's counts by name.
func sectionOfReport(r *Report, s Section) []RuleCount {
	for _, sec := range r.Sections() {
		if sec.Section == s {
			return sec.Counts
		}
	}
	return nil
}

// BenchmarkCompute guards the streaming invariant (§6 case 10, §9 C5): memory
// grows with the number of rules, not with the number of events.
func BenchmarkCompute(b *testing.B) {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir()
	// ~30k events: the fixture repeated, which is what the budget is stated
	// against; the chain is not re-verified here, only decoded.
	var buf bytes.Buffer
	for range 300 {
		buf.Write(data)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		b.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = r.Close() })
	rt := fixtureTable()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compute(r, rt); err != nil {
			b.Fatal(err)
		}
	}
}

// execLine is one hand-built exec line; Compute decodes but never re-verifies
// the chain, so plausible ids are enough to exercise the counting (R13).
func execLine(seq int, rule, verdict, path string, search bool) string {
	extra := ""
	if search {
		extra = `,"path_search":true`
	}
	return `{"v":1,"seq":` + strconv.Itoa(seq) +
		`,"id":"` + strings.Repeat(strconv.Itoa(seq%10), 64) +
		`","prev":"` + strings.Repeat(strconv.Itoa((seq-1)%10), 64) +
		`","ts":"2026-09-22T09:00:00Z","mono_ns":1,"run":"r-1","agent":"retriever"` +
		`,"pid":1,"tid":1,"cgroup":0,"kind":"exec","source":"seccomp","rule":"` + rule +
		`","verdict":"` + verdict + `","authority":"rule"` +
		`,"attribution":{"confidence":"unattributed","method":"none"}` +
		`,"argv":["python3"],"exec_id":"r-1/1/1","path":"` + path + `"` + extra + "}\n"
}

// TestPathSearchCountsNoRefusal. The supervisor records
// every directory a PATH search walks before the granted binary as `observed`
// against the entry it was searching for (docs/p0/supervisor.md R28), so drift
// counts them without ever calling the run refused. The two sides share no
// code — the engine never imports the read side — so this test is where the
// agreement is written down on this side: `observed` is a non-decision, and
// only `refused` is drift.
func TestPathSearchCountsNoRefusal(t *testing.T) {
	var b strings.Builder
	// One execvp("python3"): four directories walked, then the grant.
	for i, p := range []string{
		"/opt/bin/python3", "/usr/local/sbin/python3", "/usr/local/bin/python3", "/usr/sbin/python3",
	} {
		b.WriteString(execLine(i+1, "exec[python3.12]", "observed", p, true))
	}
	b.WriteString(execLine(5, "exec[python3.12]", "allow", "/usr/bin/python3.12", false))

	rt := fixtureTable()
	rt.Hash = [32]byte{} // no run_start here, so leave the hash comparison out of it
	rep, err := Compute(readerOver(t, []byte(b.String())), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	got, ok := find(rep.Exec, "exec[python3.12]")
	if !ok {
		t.Fatalf("exec[python3.12] missing from %+v", rep.Exec)
	}
	if got.Refused != 0 {
		t.Errorf("refused = %d, want 0: a PATH search that reached its grant is not drift", got.Refused)
	}
	if got.Allow != 1 || got.Observed != 4 || !got.Declared {
		t.Errorf("counts = %+v, want one allow and four observed on a declared entry", got)
	}
	if _, ok := find(rep.Exec, UnmatchedRule); ok {
		t.Errorf("a PATH candidate landed in the unmatched bucket: %+v", rep.Exec)
	}
	// A genuinely forbidden binary in the same run must still read as drift.
	b.WriteString(execLine(6, UnmatchedRule, "refused", "/usr/bin/nmap", false))
	rep, err = Compute(readerOver(t, []byte(b.String())), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if got, _ := find(rep.Exec, UnmatchedRule); got.Refused != 1 {
		t.Errorf("unmatched refused = %d, want 1", got.Refused)
	}
	if !rep.Drifted() {
		t.Error("a refused exec must still drift")
	}
}

// fsLine is one hand-built fs line, the read half of what a tier stamps.
func fsLine(seq int, rule, verdict, path string) string {
	return `{"v":1,"seq":` + strconv.Itoa(seq) +
		`,"id":"` + strings.Repeat(strconv.Itoa(seq%10), 64) +
		`","prev":"` + strings.Repeat(strconv.Itoa((seq-1)%10), 64) +
		`","ts":"2026-09-22T09:00:00Z","mono_ns":1,"run":"r-1","agent":"retriever"` +
		`,"pid":1,"tid":1,"cgroup":0,"kind":"fs","source":"landlock","rule":"` + rule +
		`","verdict":"` + verdict + `","authority":"rule"` +
		`,"attribution":{"confidence":"unattributed","method":"none"}` +
		`,"op":"open","path":"` + path + `"}` + "\n"
}

// TestCollidingRuleNamesShareOneBucket is the case indexes were hiding. A rule
// is named after the entry its author declared, not after its position, so two
// compiled entries can carry one name: a glob that expanded to several paths
// (pkg/spec/agent compile_fs keeps the glob text as Raw on every match), or an
// entry written twice (Load warns and admits it). A reader of the contract
// wrote one entry and must see one bucket, counted once and reported undone
// once — never a bucket per position, which is a number no contract contains.
func TestCollidingRuleNamesShareOneBucket(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{
			// One `fs.watch: ["./logs/*"]` entry, expanded to two paths.
			{Path: "/proj/logs/a.log", Kind: agent.FSWatch, Raw: "./logs/*"},
			{Path: "/proj/logs/b.log", Kind: agent.FSWatch, Raw: "./logs/*"},
			// One `fs.write: ["./out"]`, plus an unused entry declared twice.
			{Path: "/proj/out", Kind: agent.FSWrite, Raw: "./out", Access: agent.AccessWriteSet},
			{Path: "/proj/tmp", Kind: agent.FSWrite, Raw: "./tmp", Access: agent.AccessWriteSet},
			{Path: "/proj/tmp", Kind: agent.FSWrite, Raw: "./tmp", Access: agent.AccessWriteSet},
		},
		Net: []agent.NetRule{
			{Raw: "api.github.com:443", Host: "api.github.com", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow},
			{Raw: "api.github.com:443", Host: "api.github.com", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow},
		},
	}
	var b strings.Builder
	b.WriteString(fsLine(1, "fs.watch[./logs/*]", "allow", "/proj/logs/a.log"))
	b.WriteString(fsLine(2, "fs.watch[./logs/*]", "allow", "/proj/logs/b.log"))
	b.WriteString(fsLine(3, "fs.write[./out]", "allow", "/proj/out/x"))
	rep, err := Compute(readerOver(t, []byte(b.String())), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	// One bucket for the glob, carrying both events, not two buckets of one.
	if n := len(rep.FS); n != 3 {
		t.Fatalf("%d fs buckets, want 3 (the glob, ./out and ./tmp): %+v", n, rep.FS)
	}
	got, ok := find(rep.FS, "fs.watch[./logs/*]")
	if !ok {
		t.Fatalf("the glob entry is missing: %+v", rep.FS)
	}
	if got.Allow != 2 || !got.Declared {
		t.Errorf("glob bucket = %+v, want 2 allows on a declared entry", got)
	}
	// Each duplicated entry is undone once, not once per position: ./tmp was
	// written twice in fs.write and api.github.com:443 twice in net.allow.
	want := []string{"fs.write[./tmp]", "net[api.github.com:443]"}
	if !slices.Equal(rep.Undone, want) {
		t.Errorf("undone %v, want %v: one declaration, one report", rep.Undone, want)
	}
	// The same on the net side: two identical declarations, one bucket.
	if n := len(rep.Net); n != 1 {
		t.Fatalf("%d net buckets, want 1: %+v", n, rep.Net)
	}
}

// TestBuiltInNeverDemotesTheAuthorsOwnEntry guards the ordering half of a name
// collision. A compiler-added entry (the built-in deny_read list, an implicit
// exec grant) is left out of a report the run never touched, but an entry the
// author also declared under that name is theirs whichever order the compiled
// table lists them in: demoting it would drop the bucket from the section
// table while it stayed in Undone (R14), which is a report that contradicts
// itself.
func TestBuiltInNeverDemotesTheAuthorsOwnEntry(t *testing.T) {
	for _, order := range []string{"declared first", "built-in first"} {
		t.Run(order, func(t *testing.T) {
			own := agent.FSRule{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, Raw: "/home/u/.ssh"}
			builtIn := agent.FSRule{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, BuiltIn: true}
			rules := []agent.FSRule{own, builtIn}
			if order == "built-in first" {
				rules = []agent.FSRule{builtIn, own}
			}
			rep, err := Compute(readerOver(t, nil), &agent.RuleTable{FS: rules})
			if err != nil {
				t.Fatalf("compute: %v", err)
			}
			const name = "fs.deny_read[/home/u/.ssh]"
			if _, ok := find(rep.FS, name); !ok {
				t.Errorf("%s is undone but absent from the section table: %+v", name, rep.FS)
			}
			if want := []string{name}; !slices.Equal(rep.Undone, want) {
				t.Errorf("undone %v, want %v", rep.Undone, want)
			}
		})
	}
}

// TestExecCommandAndAllowNamesTheEntry is the ExecRule.Source half. One binary
// that is both the agent's command and an exec.allow entry compiles to a
// single rule whose Source is the comma-joined "command,exec.allow"
// (pkg/spec/agent compile_exec). That string is provenance, not an entry:
// naming the event after it put a value the schema does not admit into the
// ledger ("the declared entry or unmatched", spec/record/v1/README.md). The
// rule is named after the entry, and the author did write it in exec.allow,
// so it is theirs and can be reported undone.
func TestExecCommandAndAllowNamesTheEntry(t *testing.T) {
	joined := agent.ExecRule{
		Raw: "python3", Path: "/usr/bin/python3", Basename: "python3",
		Verdict: agent.VerdictAllow,
		Source:  agent.ExecSourceCommand + "," + agent.ExecSourceAllow,
	}
	if got := joined.RuleName(); got != "exec[python3]" {
		t.Fatalf("RuleName = %q, want exec[python3]: Source is not a rule name", got)
	}
	rt := &agent.RuleTable{Exec: []agent.ExecRule{
		joined,
		// A pure implicit grant stays the compiler's: never reported undone.
		{Basename: "node", Path: "/usr/bin/node", Verdict: agent.VerdictAllow, Source: agent.ExecSourceMCP + ":fs"},
	}}
	rep, err := Compute(readerOver(t, nil), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if want := []string{"exec[python3]"}; !slices.Equal(rep.Undone, want) {
		t.Errorf("undone %v, want %v", rep.Undone, want)
	}
	if _, ok := find(rep.Exec, "exec[node]"); ok {
		t.Errorf("an untouched implicit grant must not be reported: %+v", rep.Exec)
	}
	// Now the run uses it: the recorded rule matches the declaration rather
	// than landing in its own undeclared bucket, and the run does not drift.
	line := execLine(1, "exec[python3]", "allow", "/usr/bin/python3", false)
	rep, err = Compute(readerOver(t, []byte(line)), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	got, ok := find(rep.Exec, "exec[python3]")
	if !ok || !got.Declared || got.Allow != 1 {
		t.Fatalf("exec[python3] = %+v (found %v), want one allow on a declared entry", got, ok)
	}
	if rep.Drifted() {
		t.Errorf("a run that used exactly what it declared drifted: undone=%v exec=%+v", rep.Undone, rep.Exec)
	}
}

// TestResolverTrafficIsNotDrift covers the finding that fired on every run. The supervisor allows a query
// to a configured resolver on its own authority, stamping agent.ResolverRule, because a contract that
// names hosts should not also have to name the machine's nameservers. Counted as an undeclared entry, it
// made `tego drift` exit 1 for any run that resolved a hostname, and a signal that fires every time is
// no signal.
func TestResolverTrafficIsNotDrift(t *testing.T) {
	rep := &Report{Runs: 1}
	b := newBuckets()
	b.entry(SectionNet, "net[api.example.com:443]", true)
	b.count(SectionNet, "net[api.example.com:443]", record.VerdictAllow)
	b.count(SectionNet, agent.ResolverRule, record.VerdictAllow)
	b.fill(rep)

	if rep.Drifted() {
		t.Errorf("resolver traffic reported as drift: %+v", rep.Sections())
	}
	// It must still be visible: not drifting is not the same as not happening.
	var seen bool
	for _, s := range rep.Sections() {
		for _, c := range s.Counts {
			if c.Rule == agent.ResolverRule {
				seen = true
				if c.Allow != 1 {
					t.Errorf("resolver bucket %+v, want one allow", c)
				}
			}
		}
	}
	if !seen {
		t.Errorf("the resolver bucket was dropped from the table, not just from the verdict")
	}
}

// TestRuntimeRuleRefusalIsDrift guards the runtime-grant exemption from covering refusals. The exemption is for the
// traffic a grant allows, which is not undeclared; a refusal is an action whose conformance the run did not establish.
// The harness hook's grant (ADR 0064) is the first runtime rule that refuses: an unlisted vector of the tego binary,
// which only the grant constrains, is refused under exec.harness-hook[<tego>] (execmatch.Result.Rule), where before
// the grant the same `tego run` was refused under unmatched and drifted. Each runtime rule kind is checked, so a later
// grant that refuses under its own name drifts too.
func TestRuntimeRuleRefusalIsDrift(t *testing.T) {
	for _, c := range []struct {
		section Section
		rule    string
	}{
		{SectionExec, "exec." + agent.HarnessHookGrant + "[/usr/local/bin/tego]"},
		{SectionFS, "fs." + agent.HarnessStateGrant + "[/run/user/1000/tego/r-1/hook-state]"},
		{SectionNet, agent.ResolverRule},
	} {
		t.Run(c.rule, func(t *testing.T) {
			if !agent.IsRuntimeRule(c.rule) {
				t.Fatalf("%q is not a runtime rule, so the case tests nothing", c.rule)
			}
			rep := &Report{Runs: 1}
			b := newBuckets()
			b.count(c.section, c.rule, record.VerdictAllow)
			b.fill(rep)
			if rep.Drifted() {
				t.Fatalf("an allow under the runtime grant %q drifted", c.rule)
			}
			rep = &Report{Runs: 1}
			b = newBuckets()
			b.count(c.section, c.rule, record.VerdictAllow)
			b.count(c.section, c.rule, record.VerdictRefused)
			b.fill(rep)
			if !rep.Drifted() {
				t.Errorf("a refusal under the runtime grant %q did not drift: %+v", c.rule, rep.Sections())
			}
		})
	}
}

// TestUndeclaredRuleIsStillDrift guards the exemption from being over-broad: every other name the
// contract never declared must still drift.
func TestUndeclaredRuleIsStillDrift(t *testing.T) {
	for _, rule := range []string{UnmatchedRule, "net[elsewhere.example:443]", "path-truncated"} {
		t.Run(rule, func(t *testing.T) {
			rep := &Report{Runs: 1}
			b := newBuckets()
			b.count(SectionNet, rule, record.VerdictAllow)
			b.fill(rep)
			if !rep.Drifted() {
				t.Errorf("%q did not drift", rule)
			}
		})
	}
}

// verdictLine is one hand-built fs-kind line whose verdict and rule the case controls; the read half of what a
// tier stamps. Iter (internal/ledger/reader.go) applies record.Decode only, never record.Validate, so this is a
// legitimate input to Compute even where the rule/verdict combination a healthy writer would never produce.
func verdictLine(seq int, rule, verdict string) string {
	ruleField := ""
	if rule != "" {
		ruleField = `,"rule":"` + rule + `"`
	}
	return `{"v":1,"seq":` + strconv.Itoa(seq) +
		`,"id":"` + strings.Repeat(strconv.Itoa(seq%10), 64) +
		`","prev":"` + strings.Repeat(strconv.Itoa((seq-1)%10), 64) +
		`","ts":"2026-09-22T09:00:00Z","mono_ns":1,"run":"r-1","agent":"retriever"` +
		`,"pid":1,"tid":1,"cgroup":0,"kind":"fs","source":"landlock"` + ruleField +
		`,"verdict":"` + verdict + `","authority":"rule"` +
		`,"attribution":{"confidence":"unattributed","method":"none"}` +
		`,"op":"open","path":"/p"}` + "\n"
}

// TestVerdictCounts is R13's four-way split, plus the forward-compatibility half of the same rule: "count
// `verdict` into `Allow/Ask/Refused/Observed`". The frozen fixture only ever carries allow and refused (checked
// directly: `grep -o '"verdict":"[a-z]*"' run-fixture.jsonl` returns only those two), so nothing before this
// test exercised the Ask branch or the default-case fallback the count method's own comment cites for I4
// ("observed, and any verdict a later schema adds: counted, never lost, so the buckets still partition the
// ledger exactly"). Each case is independent and driven by one hand-built line, so it stands on its own
// regardless of what the fixture happens to contain.
func TestVerdictCounts(t *testing.T) {
	cases := []struct {
		name    string
		verdict string
		want    RuleCount
	}{
		{"allow", string(record.VerdictAllow), RuleCount{Allow: 1}},
		{"ask", string(record.VerdictAsk), RuleCount{Ask: 1}},
		{"refused", string(record.VerdictRefused), RuleCount{Refused: 1}},
		{"observed", string(record.VerdictObserved), RuleCount{Observed: 1}},
		// Not one of the four v1 verdicts (record.Verdicts) at all: a future schema's addition, or a
		// stray value from a decoder that outpaced this reader. R13 does not name a fifth bucket, so this
		// must land where the code comment promises: Observed, never dropped and never miscounted as a
		// recognized verdict it is not.
		{"unrecognized verdict defaults to observed", "provisional", RuleCount{Observed: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const rule = "fs.watch[./p]"
			line := verdictLine(1, rule, tc.verdict)
			rep, err := Compute(readerOver(t, []byte(line)), nil)
			if err != nil {
				t.Fatalf("compute: %v", err)
			}
			got, ok := find(rep.FS, rule)
			if !ok {
				t.Fatalf("rule %q missing from %+v", rule, rep.FS)
			}
			want := tc.want
			want.Section, want.Rule = SectionFS, rule
			if got != want {
				t.Errorf("verdict %q: got %+v, want %+v", tc.verdict, got, want)
			}
			if got.Total() != 1 {
				t.Errorf("verdict %q: Total() = %d, want 1 (I4: every action event lands in exactly one count)", tc.verdict, got.Total())
			}
		})
	}
}

// TestActionWithoutRuleFallsToUnmatched pins the other half of R13's "unmatched its own bucket": count's own
// comment says "an event with no rule falls into the unmatched bucket" (SEMANTICS §2). record.Validate rejects
// an action event with an empty rule (validateAction: "%s event without rule"), but Compute reads through
// ledger.Reader.Iter, which decodes without validating (§6 case 2's reasoning extends here: a torn-tolerant,
// defensive read path does not get to assume every line is schema-clean). Without the empty-string guard in
// buckets.count, a ruleless action would open its own bucket keyed by "" instead of joining "unmatched" -- a
// blank line in every drift table, not a name a contract or an operator would ever recognize.
func TestActionWithoutRuleFallsToUnmatched(t *testing.T) {
	line := verdictLine(1, "", string(record.VerdictAllow))
	rep, err := Compute(readerOver(t, []byte(line)), nil)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	got, ok := find(rep.FS, UnmatchedRule)
	if !ok {
		t.Fatalf("a ruleless action did not land in %q: %+v", UnmatchedRule, rep.FS)
	}
	if got.Allow != 1 {
		t.Errorf("unmatched bucket = %+v, want one allow", got)
	}
	if _, ok := find(rep.FS, ""); ok {
		t.Errorf("a bucket keyed by the empty string exists: %+v", rep.FS)
	}
	if len(rep.FS) != 1 {
		t.Errorf("%d fs buckets, want exactly 1 (unmatched only): %+v", len(rep.FS), rep.FS)
	}
}

// TestAggregateIdenticalHashesIsNotDrift is R17's converse: "HashChanged true if any two runs differ, listing
// distinct hashes with counts" only ever exercised its true side (TestAggregate forces the second run's
// ContractHash to a different value). The far more common case -- several runs of the same agent against the
// same unmodified contract, `tego drift --aggregate` on a healthy history -- collapses to one Hashes entry and
// must not report drift on its own account. This is the good-path Aggregate exists to report correctly, and
// nothing before this test ran it.
// TestAggregateSecondRunChangedIsDrift: two runs recorded the same hash, and only the second run's copy
// recompiles to another one. `drift <run2>` says changed, so the aggregate over both must too, whatever
// the order; it took only the first run's CurrentHash and reported no drift.
func TestAggregateSecondRunChangedIsDrift(t *testing.T) {
	for _, secondFirst := range []bool{false, true} {
		first, err := Compute(fixtureReader(t), fixtureTable())
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		second, err := Compute(fixtureReader(t), fixtureTable())
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		first.CurrentHash = first.ContractHash
		first.HashChanged = false
		second.CurrentHash = strings.Repeat("c", 64)
		second.HashChanged = true
		reps := []*Report{first, second}
		if secondFirst {
			reps = []*Report{second, first}
		}
		out, err := Aggregate(reps)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if !out.HashChanged || !out.Drifted() || out.CurrentHash != second.CurrentHash {
			t.Errorf("order %v: changed %v drifted %v current %q, want the second run's change", secondFirst, out.HashChanged, out.Drifted(), out.CurrentHash)
		}
	}
}

func TestAggregateIdenticalHashesIsNotDrift(t *testing.T) {
	first, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	second, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if first.ContractHash == "" || first.ContractHash != second.ContractHash {
		t.Fatalf("fixture setup: expected both runs to share one non-empty hash, got %q and %q", first.ContractHash, second.ContractHash)
	}

	out, err := Aggregate([]*Report{first, second})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if out.HashChanged {
		t.Errorf("HashChanged = true for two runs of the identical contract; R17 only calls it changed when two runs differ")
	}
	if len(out.Hashes) != 1 {
		t.Fatalf("Hashes = %+v, want exactly one distinct hash", out.Hashes)
	}
	if out.Hashes[0].Hash != first.ContractHash || out.Hashes[0].Runs != 2 {
		t.Errorf("Hashes[0] = %+v, want {%s 2}", out.Hashes[0], first.ContractHash)
	}
	if out.ContractHash != first.ContractHash {
		t.Errorf("ContractHash = %q, want %q (the single surviving hash)", out.ContractHash, first.ContractHash)
	}
}

// TestAggregateTablelessRunHidesNothing: a run whose contract copy was missing or no longer compiles declares
// nothing, so its own Undone is empty; intersecting the lists emptied Undone and UnusedMCP for the agent.
func TestAggregateTablelessRunHidesNothing(t *testing.T) {
	a, err := Compute(fixtureReader(t), fixtureTable())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Undone) == 0 || len(a.UnusedMCP) == 0 {
		t.Fatalf("fixture has nothing unused: %v %v", a.Undone, a.UnusedMCP)
	}
	b, err := Compute(fixtureReader(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Aggregate([]*Report{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Undone, a.Undone) || !slices.Equal(out.UnusedMCP, a.UnusedMCP) {
		t.Errorf("undone %v unused mcp %v, want %v %v", out.Undone, out.UnusedMCP, a.Undone, a.UnusedMCP)
	}
}

// TestDriftExpandedDeclarations exercises actual Load/Compile output, not a
// handcrafted grant. The events use the same RuleName methods as producers.
func TestDriftExpandedDeclarations(t *testing.T) {
	const yaml = `version: 0
name: drift-expanded
command: [fixture]
capture: off
fs:
  write: [./out]
  ask: [./approved]
exec: {allow: [fixture]}
net:
  allow: ['192.0.2.1:443']
  ask: ['tcp://192.0.2.2:443']
  listen: ['tcp://127.0.0.1:8080']
`
	f := contracttest.Build(t, yaml, contracttest.Tree{"out/": "", "approved/": ""})
	rt := f.Rules
	if len(rt.FSAsk) != 1 || len(rt.NetAsk) != 1 || len(rt.Listen) != 1 {
		t.Fatalf("compiled scopes missing: %+v", rt)
	}
	var declaredExec agent.ExecRule
	for _, r := range rt.Exec {
		if strings.Contains(r.Source, agent.ExecSourceAllow) {
			declaredExec = r
			break
		}
	}
	if declaredExec.Path == "" {
		t.Fatal("compiled declared executable missing")
	}
	names := []struct {
		section Section
		rule    string
		kind    string
		fields  map[string]any
	}{
		{SectionFS, "fs.write[./out]", "fs", map[string]any{"op": "open", "path": f.Path("out/x")}},
		{SectionFS, rt.FSAsk[0].RuleName(), "fs", map[string]any{"op": "open", "path": f.Path("approved/x")}},
		{SectionNet, rt.Net[0].RuleName(), "net", map[string]any{"proto": "tcp", "dst": "192.0.2.1:443"}},
		{SectionNet, rt.NetAsk[0].RuleName(), "net", map[string]any{"proto": "tcp", "dst": "192.0.2.2:443"}},
		{SectionNet, rt.Listen[0].RuleName(), "net", map[string]any{"proto": "tcp", "dst": "127.0.0.1:8080", "op": "bind"}},
		{SectionExec, declaredExec.RuleName(), "exec", map[string]any{"path": f.Path("bin/fixture"), "argv": []string{"fixture"}}},
	}
	start := runStartLine()
	start["contract_hash"] = hex.EncodeToString(rt.Hash[:])
	start["capture"] = "off"
	lines := []map[string]any{start}
	for _, n := range names {
		line := map[string]any{"kind": n.kind, "source": "supervisor", "rule": n.rule, "verdict": "allow", "authority": "rule"}
		if n.rule == rt.FSAsk[0].RuleName() || n.rule == rt.NetAsk[0].RuleName() {
			line["authority"] = "human"
		}
		for k, v := range n.fields {
			line[k] = v
		}
		lines = append(lines, line)
	}
	lines = append(lines, runEndLine())
	t.Run("used-declarations", func(t *testing.T) {
		rep, e := Compute(readerOver(t, modelLedger(lines...)), rt)
		if e != nil {
			t.Fatal(e)
		}
		for _, n := range names {
			var counts []RuleCount
			for _, s := range rep.Sections() {
				if s.Section == n.section {
					counts = s.Counts
				}
			}
			c, ok := find(counts, n.rule)
			if !ok || !c.Declared || c.Allow != 1 {
				t.Errorf("declared used %s: found=%v count=%+v", n.rule, ok, c)
			}
		}
		if rep.Drifted() || len(rep.Undone) != 0 {
			t.Errorf("declared allowed/approved work reports drift: %+v", rep)
		}
	})
	t.Run("unused-declarations", func(t *testing.T) {
		rep, e := Compute(readerOver(t, modelLedger(start, runEndLine())), rt)
		if e != nil {
			t.Fatal(e)
		}
		for _, n := range names {
			if !slices.Contains(rep.Undone, n.rule) {
				t.Errorf("unused declaration missing: %s; undone=%v", n.rule, rep.Undone)
			}
		}
	})
	t.Run("truly-undeclared", func(t *testing.T) {
		extra := map[string]any{"kind": "net", "source": "supervisor", "rule": "net.listen[tcp://127.0.0.1:9090]", "verdict": "allow", "authority": "rule", "proto": "tcp", "dst": "127.0.0.1:9090", "op": "bind"}
		all := append([]map[string]any(nil), lines[:len(lines)-1]...)
		all = append(all, extra, runEndLine())
		rep, e := Compute(readerOver(t, modelLedger(all...)), rt)
		if e != nil {
			t.Fatal(e)
		}
		c, ok := find(rep.Net, extra["rule"].(string))
		if !ok || c.Declared || !rep.Drifted() {
			t.Fatalf("undeclared work hidden: %+v", rep)
		}
	})
}

// humanFSLine is an fs line a person's answer completed (authority human, verdict allow); alternateFor, when set, is
// the requested path an alternate stood for.
func humanFSLine(seq int, rule, path, alternateFor string) string {
	line := fsLine(seq, rule, "allow", path)
	line = strings.Replace(line, `"authority":"rule"`, `"authority":"human"`, 1)
	if alternateFor != "" {
		line = strings.Replace(line, `"path":"`+path+`"`, `"path":"`+path+`","alternate_for":"`+alternateFor+`"`, 1)
	}
	return line
}

// ADR 0057 D1: an open a person answered with another file is counted against the rule that held it as an
// alternate, never as an allow of that rule (what it was asked for was not granted); an approved held open is an
// allow; both partition the ledger (Total).
func TestAnAlternateIsNotAnAllowOfTheRuleThatHeldIt(t *testing.T) {
	rt := &agent.RuleTable{FS: []agent.FSRule{{Path: "/home/u/.aws", Kind: agent.FSDenyRead, AskRead: true, Raw: "~/.aws"}}}
	var b strings.Builder
	b.WriteString(humanFSLine(1, "fs.ask_read[~/.aws]", "/home/u/fake", "/home/u/.aws/credentials"))
	b.WriteString(humanFSLine(2, "fs.ask_read[~/.aws]", "/home/u/.aws/config", ""))
	rep, err := Compute(readerOver(t, []byte(b.String())), rt)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := find(rep.FS, "fs.ask_read[~/.aws]")
	if !ok || got.Alternate != 1 || got.Allow != 1 || got.Total() != 2 || rep.Actions != 2 {
		t.Fatalf("bucket %+v (actions %d): want one alternate and one allow", got, rep.Actions)
	}
	agg, err := Aggregate([]*Report{rep, rep})
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := find(agg.FS, "fs.ask_read[~/.aws]"); g.Alternate != 2 {
		t.Fatalf("aggregated bucket %+v: want the alternates summed", g)
	}
}
