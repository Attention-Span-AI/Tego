// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/check/internal/mirror"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Section is the part of a contract a rule belongs to: the event kind that
// carries it (docs/p0/limits-check-doctor-cli.md §5 R13 groups by (kind, rule)).
type Section string

// The sections drift counts. SectionOther holds refusals no action line carries: a refused line the
// supervisor writes on its own (a keyring call, a mount-family call), not as the mirror of an fs, net or exec
// action.
const (
	SectionFS    Section = "fs"
	SectionNet   Section = "net"
	SectionExec  Section = "exec"
	SectionMCP   Section = "mcp"
	SectionOther Section = "other"
)

// UnmatchedRule is the bucket of an action no declared entry covered
// (spec/policy/SEMANTICS.md §2); it is the one rule name that is never
// declared and never counted as undone.
const UnmatchedRule = agent.UnmatchedRule

// Errors a caller distinguishes.
var (
	// ErrMixedAgent is returned by Aggregate when the reports are not all the
	// same agent (R17); the CLI reports it as a usage error, exit 2.
	ErrMixedAgent = errors.New("runs are not the same agent")
	// ErrRead wraps a ledger read failure, including the fatal torn middle
	// line (§6 case 3).
	ErrRead = errors.New("read run")
)

// RuleCount is one rule's observed verdicts: a declared entry, or a rule the
// run recorded that the contract never declared ("unmatched" included).
type RuleCount struct {
	// Section is the contract section the rule belongs to.
	Section Section
	// Rule is the entry as an event names it, e.g. fs.write[./out]. A
	// models[] entry is the one exception: events name it two ways, and
	// both are counted under models[<provider>] (buckets.declare).
	Rule string
	// Declared is true when the compiled table carries this entry; false
	// marks a rule the run recorded but the contract does not declare.
	Declared bool
	// Allow, Ask, Refused and Observed count the verdicts of the action
	// events that carried this rule (R13).
	Allow, Ask, Refused, Observed int
	// Alternate counts the opens this rule held that a person answered with another file (ADR 0057 D1): the line's
	// verdict is allow, on the file delivered, but what the rule was asked for was not granted, so it is not an
	// Allow of this rule.
	Alternate int
}

// Total is every event counted against this rule.
func (c RuleCount) Total() int { return c.Allow + c.Ask + c.Refused + c.Observed + c.Alternate }

// HashCount is one contract hash and the number of aggregated runs that used
// it (R17).
type HashCount struct {
	Hash string
	Runs int
}

// UsedEntry names a declared entry a run used without an action verdict (Report.Used).
type UsedEntry struct {
	Section Section
	Rule    string
}

// Report is declared versus observed for one run, or for one agent's runs
// after Aggregate (docs/p0/limits-check-doctor-cli.md §2).
type Report struct {
	// Run is the run id; empty on an aggregated report.
	Run string
	// Agent is the agent id every aggregated run shares.
	Agent string
	// ContractHash is what the run recorded in run_start; CurrentHash is the
	// hash of the run directory's contract.yaml recompiled by today's
	// compiler, empty when that copy is missing (R16, §6 case 23).
	ContractHash, CurrentHash string
	// HashChanged: the two hashes differ, or two aggregated runs do.
	HashChanged bool
	// Hashes lists the distinct contract hashes an aggregated report covers,
	// most-used first (R17); nil for a single run.
	Hashes []HashCount
	// FS, Net, Exec and MCP hold one RuleCount per declared entry and per
	// rule the run recorded, sorted by rule name.
	FS, Net, Exec, MCP []RuleCount
	// Other holds the refusals written without an action line (SectionOther), by rule.
	Other []RuleCount
	// Undone lists declared fs, net and exec entries with no events at all
	// (R14): a models[] entry is used as well by an ssl_request its model
	// traffic produced, which counts in none of RuleCount's columns.
	// UnusedMCP lists declared mcp servers with no mcp event in a run
	// whose record could have carried one (R15).
	Undone, UnusedMCP []string
	// Used lists the declared entries the run exercised through a line that carries no action verdict (an
	// ssl_request naming a models[] entry's provider). Aggregate needs it: those uses are in no RuleCount
	// column, so summing the rows alone would report the entry undone for an agent whose every run used it.
	Used []UsedEntry
	// UnobservableMCP lists declared mcp servers with no mcp event in a run
	// whose record could not have carried one: no MCP producer ran, so the
	// ledger's silence says nothing about whether the server started (R15).
	// It is reported, never counted as drift.
	UnobservableMCP []string
	// UnobservableFS lists declared fs.deny_read and fs.watch entries with no
	// event in a run whose record could not carry a read: its capability
	// line says record.reads_mmap_chmod is false, or it recorded gap
	// why=unprivileged-tier (tier 1 without record: full, SEMANTICS §7).
	// Reads are the only events those entries name, and a read the kernel
	// refused leaves no line either, so the silence says nothing about
	// whether the protection was exercised. It is reported, never counted as
	// drift: calling such an entry unused invited deleting a protection that
	// had worked (R14).
	UnobservableFS []string
	// UnobservableRecord lists the other declared fs, net, exec and models[] entries with no event in a run
	// whose capability line says record.exec_open_connect is false (record: off): such a run keeps only
	// refusals, so an allowed entry's silence says nothing about whether it was used. Reported, never
	// drift (R14).
	UnobservableRecord []string
	// BestEffort is run_start's best_effort: the cells the run decided on copied syscall facts and
	// continued, never counted as enforced (ADR 0041 D1, D7); over an aggregate, the sorted union of its runs'.
	// Reported, never drift.
	BestEffort []string
	// GuardsNotExercised lists the exec.deny and exec.ask entries no line named (ADR 0048 (8)): a guard, not a grant,
	// so a run where the agent behaved leaves every one unfired. Reported like UnobservableFS, never drift; over an
	// aggregate, the guards no run exercised.
	GuardsNotExercised []string
	// Ended: the ledger holds a run_end. CutOff: the caller found no launcher behind a run with none (status.Lost), or
	// one aggregated run is such a run, so the record may stop short of what the run did (gaps.Words).
	Ended, CutOff bool
	// Gaps is every gap event the run recorded, grouped by what and why: the
	// gap line (R34), summed over the runs of an aggregated report.
	Gaps []gaps.Count
	// DeclaredUnknown is true when the contract's declared entries could not be recompiled here (its copy no
	// longer compiles, for one, and the reader's PATH or files are not the run's): a rule no entry covers is
	// then unknown, not undeclared, and is not counted as drift (R16). The hash comparison still stands. An
	// aggregated report carries it when any of its runs does.
	DeclaredUnknown bool
	// Actions is the number of action events counted, the total I4 partitions.
	Actions int
	// Runs is 1 for a per-run report and N for an aggregated one.
	Runs int
}

// Sections returns the four rule tables in a fixed order, so every renderer
// prints them the same way.
func (r *Report) Sections() []struct {
	Section Section
	Counts  []RuleCount
} {
	return []struct {
		Section Section
		Counts  []RuleCount
	}{
		{SectionFS, r.FS}, {SectionNet, r.Net}, {SectionExec, r.Exec}, {SectionMCP, r.MCP}, {SectionOther, r.Other},
	}
}

// Drifted reports whether the run did anything the contract does not describe:
// the contract changed since the run, a declared entry was never used, an
// MCP server the record could have seen start never did, an action was
// refused, or an action matched a rule the contract never declared (the
// "unmatched" bucket included). It is what the CLI turns into exit 1 (R25).
//
// A rule the runtime grants on its own authority is not one of those. The
// supervisor allows a query to a configured resolver ungated by net.allow, so
// that a contract naming hosts need not also name the machine's nameservers
// (agent.IsRuntimeRule, docs/p0/supervisor.md R14); counting it as an
// undeclared entry made every run that resolves a hostname report drift, which
// is nearly every run, and a finding that fires every time says nothing. The
// bucket is still printed, so the traffic stays visible in the table. The
// exemption covers what a grant allowed, never what was refused under its name:
// the harness hook's grant (ADR 0064) refuses every other vector of the tego
// binary under exec.harness-hook[<tego>], and that refusal is an action whose
// conformance the run did not establish, so it drifts like any refusal.
//
// An UnobservableMCP server is not one either. No producer could have written
// its mcp event, so calling it unused would be a finding about the recorder,
// not about the agent — and one that fired on every run declaring mcp[]. It is printed as unobservable instead.
func (r *Report) Drifted() bool {
	if r.HashChanged || len(r.Undone) > 0 || len(r.UnusedMCP) > 0 {
		return true
	}
	for _, s := range r.Sections() {
		for _, c := range s.Counts {
			if c.Refused > 0 {
				return true
			}
			if agent.IsRuntimeRule(c.Rule) {
				continue
			}
			if !c.Declared && c.Total() > 0 && !r.DeclaredUnknown {
				return true
			}
		}
	}
	return false
}

// ctxEvery is how many lines ComputeCtx reads between checks of its context (R29).
const ctxEvery = 1024

// ComputeCtx reads one run's ledger and reports declared versus observed per rule
// (R13-R16). rt is the contract this run declared, recompiled from the run
// directory's own contract.yaml copy by the caller; a nil or empty table is
// legal and makes every observed rule undeclared with an empty CurrentHash
// (§6 case 23). It streams: memory is O(rules), not O(events) (§6 case 10).
//
// It stops on ctx: it checks it every ctxEvery lines and returns its error as is,
// so a ledger of millions of lines ends on the first signal (R29).
func ComputeCtx(ctx context.Context, r *ledger.Reader, rt *agent.RuleTable) (*Report, error) {
	if r == nil {
		return nil, fmt.Errorf("drift: no reader")
	}
	rep := &Report{Runs: 1}
	b := newBuckets()
	b.declare(rt)
	var (
		gapTally gaps.Tally
		// mcpSeen is R15's "the record could have carried an mcp event", per
		// transport: the run names a producer of that transport in
		// run_start.parsers, or one wrote at least one mcp event of it.
		mcpSeen = map[string]bool{}
		// readsBlind is H10's "the record could not have carried a read":
		// run_start's capability line has record.reads_mmap_chmod false, or
		// the run wrote gap why=unprivileged-tier, which a run_start written
		// before the capability line existed still carries.
		readsBlind bool
		// allowedBlind: run_start's capability line has record.exec_open_connect false (record: off),
		// so the run recorded refusals only and no allowed event.
		allowedBlind bool
		prev         mirror.Key
		lines        int
	)
	for e, err := range r.Iter() {
		if err != nil {
			return nil, fmt.Errorf("drift: %w: %w", ErrRead, err)
		}
		if lines++; lines%ctxEvery == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if rep.Run == "" {
			rep.Run, rep.Agent = e.Run, e.Agent
		}
		gapTally.Add(e)
		rep.Ended = rep.Ended || e.Kind == record.KindRunEnd
		if e.Kind == record.KindRunStart {
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				return nil, fmt.Errorf("drift: decode run_start: %w", err)
			}
			rep.ContractHash = p.ContractHash
			rep.BestEffort = p.BestEffort
			for _, t := range MCPTransports(p.Parsers) {
				mcpSeen[t] = true
			}
			if reads, ok := p.Capabilities[string(backend.CapRecordReads)]; ok && !reads {
				readsBlind = true
			}
			if ex, ok := p.Capabilities[string(backend.CapRecordExecOpenNet)]; ok && !ex {
				allowedBlind = true
			}
			continue
		}
		if e.Kind == record.KindGap && !readsBlind {
			var p record.GapPayload
			if e.DecodePayload(&p) == nil && p.What == gapWhatRecord && p.Why == gapWhyUnprivilegedTier {
				readsBlind = true
			}
		}
		if e.Kind == record.KindMCP {
			// Every line a P0 writer wrote is a stdio server's start; one whose transport cannot be read is
			// read as that.
			var p record.MCPPayload
			if e.DecodePayload(&p) != nil || p.Transport != mcpHTTP {
				p.Transport = mcpStdio
			}
			mcpSeen[p.Transport] = true
		}
		if e.Kind == record.KindSSLRequest {
			// A request the forwarder or the uprobes read names the models[]
			// entry it went to by provider (its endpoint field), and it is
			// that entry's use, though no action verdict rides on it (R14).
			// One whose endpoint cannot be read uses nothing, so the entry
			// is still reported undone rather than assumed used.
			var p struct {
				Endpoint string `json:"endpoint"`
			}
			if e.DecodePayload(&p) == nil && p.Endpoint != "" {
				b.use(SectionNet, modelsRule(p.Endpoint))
			}
			continue
		}
		if e.Kind == record.KindExec && e.Verdict == record.VerdictAllow {
			// An exec a constrained tool's allow entry admitted names it in command_rule (ADR 0048 (8)): the entry
			// is used, beside the image rule the line counts against.
			var p struct {
				CommandRule string `json:"command_rule"`
				CommandList string `json:"command_list"`
			}
			if e.DecodePayload(&p) == nil && p.CommandRule != "" && p.CommandList == "allow" {
				b.use(SectionExec, "exec.allow["+p.CommandRule+"]")
			}
		}
		mirrored := prev.Mirrors(e)
		prev = mirror.Of(e)
		section, ok := sectionOf(e.Kind)
		if !ok {
			// A refused line that mirrors the action line just before it was already counted from
			// the action's verdict; counting it again would count one occurrence twice. One written on its
			// own (a keyring or mount-family refusal) is the only record of that refusal, and counts.
			if e.Kind == record.KindRefused && !mirrored {
				b.count(SectionOther, e.Rule, record.VerdictRefused)
				rep.Actions++
			}
			continue
		}
		if e.Kind == record.KindFS && e.Verdict == record.VerdictAllow && e.Authority == record.AuthorityHuman {
			var p struct {
				AlternateFor string `json:"alternate_for"`
			}
			if e.DecodePayload(&p) == nil && p.AlternateFor != "" {
				b.countAlternate(section, e.Rule)
				rep.Actions++
				continue
			}
		}
		b.count(section, e.Rule, e.Verdict)
		rep.Actions++
	}
	if rt != nil && rt.Hash != ([32]byte{}) {
		rep.CurrentHash = hex.EncodeToString(rt.Hash[:])
	}
	rep.HashChanged = rep.CurrentHash != "" && rep.ContractHash != "" && rep.ContractHash != rep.CurrentHash
	b.fill(rep)
	rep.Undone, rep.GuardsNotExercised = b.splitGuards(rep.Undone)
	rep.Used = b.usedEntries()
	rep.UnusedMCP, rep.UnobservableMCP = splitObservedMCP(rep.UnusedMCP, rt, mcpSeen)
	if readsBlind {
		rep.Undone, rep.UnobservableFS = b.splitReadOnly(rep.Undone)
	}
	if allowedBlind {
		rep.Undone, rep.UnobservableRecord = nil, rep.Undone
	}
	rep.Gaps = gapTally.Counts()
	return rep, nil
}

// The gap a run without read records writes once, right after run_start (SEMANTICS §7); spelled here
// rather than imported, since internal/runtime is the writer and this package only reads the record.
const (
	gapWhatRecord          = "record"
	gapWhyUnprivilegedTier = "unprivileged-tier"
)

// The transports of an mcp line (spec/record/v1), spelled here rather than imported from derive, which is the
// writer.
const (
	mcpStdio = "stdio"
	mcpHTTP  = "http"
)

// MCPTransports reads which servers a run's MCP producers could have recorded, from run_start.parsers["mcp"]
// (R15): a "+"-joined list of producers. "exec" (the supervisor's exec path) records a stdio server's start;
// "mcp/<version>" (derive/mcp reading captured HTTPS exchanges) an HTTP server's connection and calls. Any other
// value other than "" and "0" is a producer a ledger written before 2026-10-19 named, when every producer was the
// exec path's, and reads as stdio. A producer announces itself there, and that is what lets drift read a declared
// server of its transport with no mcp event as unused rather than unobservable.
func MCPTransports(parsers map[string]string) []string {
	v := parsers[string(SectionMCP)]
	if v == "" || v == "0" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, "+") {
		t := mcpStdio
		if strings.HasPrefix(p, "mcp/") {
			t = mcpHTTP
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// splitObservedMCP divides the run's unused servers into those a producer of their transport could have recorded,
// which are unused (R15), and the rest, which are unobservable. A server is HTTP when the table declares it by an
// https url (agent-contract.md R16a), stdio when by command, a name the table does not hold included. One declared
// by a plain http:// url (or a url ParseMCPURL refuses) is covered by no producer: its exchanges pass no TLS
// library, so the HTTP reader never sees them (capture-derive R41), and it is unobservable under every one.
func splitObservedMCP(unused []string, rt *agent.RuleTable, seen map[string]bool) (used, blind []string) {
	transport := map[string]string{}
	if rt != nil && rt.Contract != nil {
		for _, s := range rt.Contract.MCP {
			if s.URL == "" || len(s.Command) > 0 {
				continue
			}
			transport[agent.MCPRule(s.Name)] = ""
			if e, err := agent.ParseMCPURL(s.URL); err == nil && e.HTTPS {
				transport[agent.MCPRule(s.Name)] = mcpHTTP
			}
		}
	}
	for _, name := range unused {
		t, byURL := transport[name]
		if !byURL {
			t = mcpStdio
		}
		if t != "" && seen[t] {
			used = append(used, name)
		} else {
			blind = append(blind, name)
		}
	}
	return used, blind
}

// Aggregate sums per-run reports for one agent (R17): RuleCounts add up by
// (section, rule), Undone and UnusedMCP are read off the sum — declared in
// some run and used in none, so a run with no table adds nothing to them — and the distinct contract hashes
// are listed with their run counts. A server no run used, that is not unused
// in every run because some run could not have observed it, is
// UnobservableMCP for the agent: one blind run is enough to leave the question
// open. A deny_read or watch entry is UnobservableFS for the agent on the same
// terms. Gap tallies add up by what and why.
func Aggregate(reports []*Report) (*Report, error) {
	if len(reports) == 0 {
		return nil, fmt.Errorf("drift: %w: no reports", ErrMixedAgent)
	}
	out := &Report{}
	b := newBuckets()
	hashes := map[string]int{}
	var (
		unobservable, unobservableFS, unobservableRec []string
		runGaps                                       [][]gaps.Count
		usedMarks                                     []UsedEntry
	)
	for i, rep := range reports {
		if rep == nil {
			return nil, fmt.Errorf("drift: report %d is nil", i)
		}
		if i == 0 {
			out.Agent = rep.Agent
		}
		if rep.Agent != out.Agent {
			return nil, fmt.Errorf("drift: %w: %q and %q", ErrMixedAgent, out.Agent, rep.Agent)
		}
		out.Runs += max(rep.Runs, 1)
		out.DeclaredUnknown = out.DeclaredUnknown || rep.DeclaredUnknown
		out.CutOff = out.CutOff || rep.CutOff
		out.Actions += rep.Actions
		if rep.ContractHash != "" {
			hashes[rep.ContractHash] += max(rep.Runs, 1)
		}
		// A run whose own copy recompiles to another hash than it recorded is R16's change for the
		// agent whatever the other runs say: the aggregate took only the first run's CurrentHash, so
		// `drift <run1> --aggregate` hid a change `drift <run2>` reports. The first changed run's
		// CurrentHash is the one shown, so the line names the hash that differs.
		if rep.HashChanged && !out.HashChanged {
			out.HashChanged = true
			out.CurrentHash = rep.CurrentHash
		}
		if out.CurrentHash == "" {
			out.CurrentHash = rep.CurrentHash
		}
		for _, s := range rep.Sections() {
			for _, c := range s.Counts {
				b.add(s.Section, c)
			}
		}
		usedMarks = append(usedMarks, rep.Used...)
		unobservable = append(unobservable, rep.UnobservableMCP...)
		unobservableFS = append(unobservableFS, rep.UnobservableFS...)
		unobservableRec = append(unobservableRec, rep.UnobservableRecord...)
		for _, g := range rep.GuardsNotExercised {
			b.guards[g] = true
		}
		runGaps = append(runGaps, rep.Gaps)
		for _, c := range rep.BestEffort {
			if !slices.Contains(out.BestEffort, c) {
				out.BestEffort = append(out.BestEffort, c)
			}
		}
	}
	slices.Sort(out.BestEffort)
	for h, n := range hashes {
		out.Hashes = append(out.Hashes, HashCount{Hash: h, Runs: n})
	}
	slices.SortFunc(out.Hashes, func(a, b HashCount) int {
		if a.Runs != b.Runs {
			return b.Runs - a.Runs
		}
		return strings.Compare(a.Hash, b.Hash)
	})
	if len(out.Hashes) == 1 {
		out.ContractHash = out.Hashes[0].Hash
	}
	out.HashChanged = out.HashChanged || len(out.Hashes) > 1 ||
		(out.ContractHash != "" && out.CurrentHash != "" && out.ContractHash != out.CurrentHash)
	// Undone and UnusedMCP come from the merged buckets: declared in some run, used in none, and not
	// one some run could not observe (that is UnobservableMCP/FS below). Intersecting the per-run lists
	// let one run with no table (its copy missing or no longer compiling) declare nothing and empty
	// the list for the agent.
	for _, u := range usedMarks {
		b.use(u.Section, u.Rule)
	}
	b.fill(out)
	out.Undone, out.GuardsNotExercised = b.splitGuards(out.Undone)
	out.Used = b.usedEntries()
	out.Undone = without(without(out.Undone, unobservableFS), unobservableRec)
	out.UnusedMCP = without(out.UnusedMCP, unobservable)
	out.UnobservableMCP = unobservedByAll(unobservable, out.MCP, out.UnusedMCP)
	out.UnobservableFS = unobservedByAll(unobservableFS, out.FS, out.Undone)
	out.UnobservableRecord = unobservedByAll(unobservableRec, slices.Concat(out.FS, out.Net, out.Exec), out.Undone)
	out.Gaps = gaps.Merge(runGaps...)
	return out, nil
}

// unobservedByAll keeps the servers some run could not observe that no run
// used and that are not already unused in every run, sorted and without
// duplicates.
func unobservedByAll(unobservable []string, counts []RuleCount, unused []string) []string {
	var out []string
	for _, name := range unobservable {
		if slices.Contains(out, name) || slices.Contains(unused, name) {
			continue
		}
		if c, ok := findRule(counts, name); ok && c.Total() > 0 {
			continue
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// findRule returns one rule's counts from a section.
func findRule(counts []RuleCount, rule string) (RuleCount, bool) {
	for _, c := range counts {
		if c.Rule == rule {
			return c, true
		}
	}
	return RuleCount{}, false
}

// buckets accumulates one RuleCount per (section, rule) and remembers which
// rules the contract declared.
type buckets struct {
	counts   map[Section]map[string]*RuleCount
	declared map[Section][]string
	// aux holds entries the compiler added rather than the contract's author:
	// the built-in deny_read list and the implicit exec grants. They count
	// when the run used them and are left out of the report when it did not,
	// so a report lists what the author wrote, not what the compiler derived.
	aux map[Section]map[string]bool
	// alias maps a second name an event may give a declared entry onto the
	// bucket it belongs to (declare: a models[] entry's host:port name).
	alias map[Section]map[string]string
	// used marks declared entries the run exercised through a line that
	// carries no action verdict (ComputeCtx: an ssl_request to a models[]
	// entry), so they are not reported undone although they count nothing.
	used map[Section]map[string]bool
	// readOnly marks the author's fs.deny_read and fs.watch entries: the
	// entries only a read names, which a run that records no reads cannot see
	// used (Report.UnobservableFS).
	readOnly map[string]bool
	// guards marks the exec.deny and exec.ask entries (Report.GuardsNotExercised).
	guards map[string]bool
}

// splitGuards moves the guards out of the undone entries: a deny or ask entry nothing named was not exercised,
// which is no finding about the contract.
func (b *buckets) splitGuards(undone []string) (rest, guards []string) {
	for _, u := range undone {
		if b.guards[u] {
			guards = append(guards, u)
			continue
		}
		rest = append(rest, u)
	}
	return rest, guards
}

func newBuckets() *buckets {
	return &buckets{
		counts:   map[Section]map[string]*RuleCount{},
		declared: map[Section][]string{},
		aux:      map[Section]map[string]bool{},
		alias:    map[Section]map[string]string{},
		used:     map[Section]map[string]bool{},
		readOnly: map[string]bool{},
		guards:   map[string]bool{},
	}
}

// splitReadOnly separates the undone entries only a read could have used from the rest, both sorted.
func (b *buckets) splitReadOnly(undone []string) (rest, readOnly []string) {
	for _, rule := range undone {
		if b.readOnly[rule] {
			readOnly = append(readOnly, rule)
			continue
		}
		rest = append(rest, rule)
	}
	return rest, readOnly
}

// modelsRule is the bucket a models[] entry is counted under: its provider,
// the name the contract's author gave it and the one the frozen v1 fixture's
// net line carries (models[anthropic]).
func modelsRule(provider string) string { return "models[" + provider + "]" }

// declare records every entry the compiled table carries, so an entry with no
// events still appears (R14, R15). Implicit entries — the run directory, the
// contract file, /sys/fs/cgroup, /sys/fs/bpf (SEMANTICS §2) — are not
// declarations of the contract's author and are left out unless the run
// actually recorded one.
func (b *buckets) declare(rt *agent.RuleTable) {
	if rt == nil {
		return
	}
	for _, r := range rt.FS {
		if r.Kind == agent.FSImplicit {
			continue
		}
		b.entry(SectionFS, r.RuleName(), !r.BuiltIn)
		if r.Kind == agent.FSDenyRead || r.Kind == agent.FSWatch {
			b.readOnly[r.RuleName()] = true
		}
	}
	// A built-in row absent at compile carries no FS rule, yet a read the Landlock ruleset refuses for it is recorded
	// under its name (ADR 0067 D3): it is the compiler's entry, as an existing row is, not an undeclared one.
	for _, a := range rt.AbsentDenyRead {
		b.entry(SectionFS, a.RuleName(), false)
		b.readOnly[a.RuleName()] = true
	}
	// A name entry (ADR 0043 D8) is declared under every name its refusals carry: a declared glob's own entry, the
	// built-in list's label with each scope's spelling; read-only, as a deny_read entry is. A glob that matched no file
	// at compile has no fs entry and is still the author's.
	for i := range rt.NameDeny {
		e := &rt.NameDeny[i]
		for j := range e.Scopes {
			name := e.RuleName(j)
			b.entry(SectionFS, name, !e.BuiltIn)
			b.readOnly[name] = true
		}
	}
	// Approval candidates and listeners are declared entries too, despite
	// being kept outside ordinary grants so compilation cannot admit them.
	for _, r := range rt.FSAsk {
		b.entry(SectionFS, r.RuleName(), true)
	}
	for _, r := range rt.Net {
		// A rule an HTTP MCP server's url derived (NetRule.MCP, agent-contract R16a) is that server's, reported
		// idle under mcp, never as a net entry the author declared and never used.
		b.entry(SectionNet, r.RuleName(), r.MCP == "")
	}
	for _, r := range rt.NetAsk {
		b.entry(SectionNet, r.RuleName(), true)
	}
	for _, r := range rt.Listen {
		b.entry(SectionNet, r.RuleName(), true)
	}
	for _, rule := range rt.HTTP.RuleNames() {
		b.entry(SectionNet, rule, true)
	}
	for _, r := range rt.Exec {
		// Only an exec.allow entry is an exec declaration of the author's: the
		// implicit grants (the agent's own command, an MCP server's binary, a
		// script's interpreter) are derived from other sections and are
		// reported there, never as an unused exec entry.
		//
		// Contains, not equality: one binary that is both the agent's command
		// and an exec.allow entry compiles to a single rule whose Source is
		// the comma-joined "command,exec.allow" (pkg/spec/agent compile_exec).
		// The author did write it in exec.allow, so it is theirs.
		b.entry(SectionExec, r.RuleName(), strings.Contains(r.Source, agent.ExecSourceAllow))
	}
	// Exec command rules (ADR 0048 (8)): an allow entry with words is counted one by one through the exec line's
	// command_rule; a deny or ask entry is a guard, reported apart when nothing named it.
	if ec := rt.ExecCommands; ec != nil {
		for _, en := range ec.Entries {
			b.entry(SectionExec, en.Pattern.Rule(), true)
			if en.Pattern.List != execmatch.ListAllow {
				b.guards[en.Pattern.Rule()] = true
			}
		}
	}
	if rt.Contract == nil {
		return
	}
	for _, m := range rt.Contract.MCP {
		b.entry(SectionMCP, "mcp["+m.Name+"]", true)
	}
	for _, m := range rt.Contract.Models {
		// A model endpoint belongs to the net section, and the record names
		// it two ways. By provider: the frozen v1 fixture's net line
		// (models[anthropic]) and every ssl_request's endpoint field (ComputeCtx).
		// By host:port: the refusal of a direct connection to it under
		// capture: forwarder carries agent.ModelRule, models[<host>:<port>]
		// (SEMANTICS §1). Both are this one declaration, so the second is an
		// alias of the first: counted apart, the refusal read as an action no
		// entry declares and the entry it hit as declared and never used.
		// Two entries that share a host:port share that name too, and a
		// refusal under it is counted against the first declared of them.
		name := modelsRule(m.Provider)
		b.entry(SectionNet, name, true)
		if m.Host == "" || m.Port <= 0 {
			continue // no endpoint, so no refusal can name it
		}
		if b.alias[SectionNet] == nil {
			b.alias[SectionNet] = map[string]string{}
		}
		if alt := agent.ModelRule(m); alt != name && b.alias[SectionNet][alt] == "" {
			b.alias[SectionNet][alt] = name
		}
	}
}

// use marks a declared entry exercised by a line that carries no action
// verdict; a name the contract does not declare is ignored, so the set stays
// O(rules) whatever the record names (§6 case 10).
func (b *buckets) use(s Section, rule string) {
	if c := b.counts[s][rule]; c == nil || !c.Declared {
		return
	}
	if b.used[s] == nil {
		b.used[s] = map[string]bool{}
	}
	b.used[s][rule] = true
}

// usedEntries lists the marks use recorded, in section then rule order.
func (b *buckets) usedEntries() []UsedEntry {
	var out []UsedEntry
	for s, rules := range b.used {
		for rule := range rules {
			out = append(out, UsedEntry{Section: s, Rule: rule})
		}
	}
	slices.SortFunc(out, func(a, b UsedEntry) int {
		if a.Section != b.Section {
			return strings.Compare(string(a.Section), string(b.Section))
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	return out
}

// entry registers a declared rule; own says whether it is the contract
// author's own declaration and may therefore be reported undone.
//
// Two compiled entries may share a name: a rule is named after the entry its
// author declared (agent.RuleName), not after its position in a list, so a
// glob that expanded to several paths, or an entry written twice, is one
// declaration and belongs in one bucket — which is how a reader of the
// contract counts it. Registering the same name twice therefore merges rather
// than splits, and the author's own declaration wins over a compiler-added
// entry of the same name whichever order they arrive in: demoting it to aux
// would drop the bucket from the section table while unused() still reported
// it undone (R14).
func (b *buckets) entry(s Section, rule string, own bool) {
	c := b.get(s, rule)
	c.Declared = true
	if !own {
		if slices.Contains(b.declared[s], rule) {
			return // already the author's own under this name; never demote it
		}
		if b.aux[s] == nil {
			b.aux[s] = map[string]bool{}
		}
		b.aux[s][rule] = true
		return
	}
	delete(b.aux[s], rule)
	if !slices.Contains(b.declared[s], rule) {
		b.declared[s] = append(b.declared[s], rule)
	}
}

// get returns the accumulator for one rule, creating it on first sight.
func (b *buckets) get(s Section, rule string) *RuleCount {
	m := b.counts[s]
	if m == nil {
		m = map[string]*RuleCount{}
		b.counts[s] = m
	}
	c := m[rule]
	if c == nil {
		c = &RuleCount{Section: s, Rule: rule}
		m[rule] = c
	}
	return c
}

// count adds one action event to its bucket; an event with no rule falls into
// the unmatched bucket, which SEMANTICS §2 gives its own name, and one that
// names a declared entry by its second name falls into that entry's (alias).
// A name some entry declares as its own is never redirected.
func (b *buckets) count(s Section, rule string, v record.Verdict) {
	if rule == "" {
		rule = UnmatchedRule
	}
	if to := b.alias[s][rule]; to != "" {
		if c := b.counts[s][rule]; c == nil || !c.Declared {
			rule = to
		}
	}
	c := b.get(s, rule)
	switch v {
	case record.VerdictAllow:
		c.Allow++
	case record.VerdictAsk:
		c.Ask++
	case record.VerdictRefused:
		c.Refused++
	default:
		// observed, and any verdict a later schema adds: counted, never lost,
		// so the buckets still partition the ledger exactly (I4).
		c.Observed++
	}
}

// countAlternate adds one open a person answered with another file to its rule's bucket (RuleCount.Alternate),
// named as count names it.
func (b *buckets) countAlternate(s Section, rule string) {
	if rule == "" {
		rule = UnmatchedRule
	}
	if to := b.alias[s][rule]; to != "" {
		if c := b.counts[s][rule]; c == nil || !c.Declared {
			rule = to
		}
	}
	b.get(s, rule).Alternate++
}

// add merges an already-computed RuleCount, for Aggregate.
func (b *buckets) add(s Section, in RuleCount) {
	c := b.get(s, in.Rule)
	c.Declared = c.Declared || in.Declared
	c.Allow += in.Allow
	c.Ask += in.Ask
	c.Refused += in.Refused
	c.Observed += in.Observed
	c.Alternate += in.Alternate
	if in.Declared && in.Rule != UnmatchedRule && !slices.Contains(b.declared[s], in.Rule) {
		b.declared[s] = append(b.declared[s], in.Rule)
	}
}

// fill writes the accumulated buckets into a report, sorted by rule name, and
// derives Undone and UnusedMCP (R14, R15).
func (b *buckets) fill(rep *Report) {
	rep.FS = b.section(SectionFS)
	rep.Net = b.section(SectionNet)
	rep.Exec = b.section(SectionExec)
	rep.MCP = b.section(SectionMCP)
	rep.Other = b.section(SectionOther)
	rep.Undone = nil
	rep.UnusedMCP = nil
	for _, s := range []Section{SectionFS, SectionNet, SectionExec} {
		rep.Undone = append(rep.Undone, b.unused(s)...)
	}
	slices.Sort(rep.Undone) // one order everywhere
	rep.UnusedMCP = b.unused(SectionMCP)
}

// section returns one section's counts, sorted by rule name. A compiler-added
// entry the run never touched is left out (see buckets.aux).
func (b *buckets) section(s Section) []RuleCount {
	out := make([]RuleCount, 0, len(b.counts[s]))
	for rule, c := range b.counts[s] {
		if c.Total() == 0 && b.aux[s][rule] {
			continue
		}
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b RuleCount) int { return strings.Compare(a.Rule, b.Rule) })
	return out
}

// unused lists the section's own declared entries that no event touched.
func (b *buckets) unused(s Section) []string {
	var out []string
	for _, rule := range b.declared[s] {
		if b.used[s][rule] {
			continue
		}
		if c := b.counts[s][rule]; c == nil || c.Total() == 0 {
			out = append(out, rule)
		}
	}
	slices.Sort(out)
	return out
}

// sectionOf maps an event kind onto the section it counts toward; the second
// result is false for every kind drift does not count (R13).
func sectionOf(k record.Kind) (Section, bool) {
	switch k {
	case record.KindFS:
		return SectionFS, true
	case record.KindNet:
		return SectionNet, true
	case record.KindExec:
		return SectionExec, true
	case record.KindMCP:
		return SectionMCP, true
	}
	return "", false
}

// without keeps the names of list that are not in drop.
func without(list, drop []string) []string {
	var out []string
	for _, n := range list {
		if !slices.Contains(drop, n) {
			out = append(out, n)
		}
	}
	return out
}
