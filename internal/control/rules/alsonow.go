// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// NowOption is one live block "Also apply now" can place on a running run of the changed contract, so the narrowing
// holds in that run at once instead of from its next run . OK false says Why it is not offered.
type NowOption struct {
	Run string
	// Kind and Value are the live block's (internal/liveblock): exec, net, path, read or write.
	Kind, Value string
	// Block is Kind:Value, as the journal and `tego block` spell it.
	Block string
	OK    bool
	Why   string
	// Change is the list change the option is for, as the journal spells it ("fs.write -= ./tmp/").
	Change string
	// Cwd is the folder the change's relative entries were read against (the run's working folder), so a page can
	// say Value as the person wrote it.
	Cwd string
	// Observe is a run that is only watched (tego watch: run_start tier observe): a block placed there is recorded on
	// each matching line and refuses nothing, so the offer says "recorded only (watched run)" (internal/check/livestatus).
	Observe bool
	// FenceLift is a widening that lies inside the fence of a running Adjustable run (ADR 0125 decision 3): it places
	// no block (OK is false), but the run may get it now by a lift or a grant of the fence entry Kind:Value on the
	// Rules page, enforced by Tego's live layer, not the kernel. Why then says so (WhyFenceLift).
	FenceLift bool
}

// WhyFenceLift is the reason of a widening inside a running Adjustable run's fence (NowOption.FenceLift). The saved
// change itself is the next run's, so the words read after a "Next run" chip as every other Why does ("This run keeps
// its rules: …"); a template that checks FenceLift says "Live now" with its own chip and a link to the run's fence.
const WhyFenceLift = "it lies inside the run's fence, so a lift on the Rules page gives it now (Tego's live layer, not the kernel)"

// LiveResult is what placing one live block did.
type LiveResult struct {
	Run, Block string
	OK         bool
	Err        string
	// Serial is the run's overlay serial after the block was placed: the launcher's confirming gap line carrying it,
	// or a later one, says the block is in force (ledgerview.LiveFacts). 0 when it is not known.
	Serial uint64
	// Observe is a watched run, where the block is recorded only.
	Observe bool
	// Lift is a removal an Undo made of a block the change it undid had placed (lift.go), not a placement.
	Lift bool
}

// The reasons a change has no live block, said as the rest of a "Next run: …" line.
const (
	whyWidens     = "it lets the agent do more, so it waits for the next run"
	whyAskAdd     = "an ask cannot be added live: the run asks from its next run"
	whyAskRemove  = "removing a read ask has no live block: this run keeps asking until its next run"
	whyPattern    = "a pattern: a live block names one path"
	whyCommand    = "a command entry: a live block names a whole program, and would refuse its other commands too"
	whyNoHome     = "the home folder is not known here"
	whyUnknownKey = "this list has no live block"
	whyTakenBack  = "a later change took this entry back, so the current rules do not refuse it"
	// whyOldWrite is a write block asked of a run whose launcher predates write blocks (livestatus.Facts.NarrowKinds):
	// it would fail to read the run's live blocks and ignore every later change, so none is placed.
	whyOldWrite = "this run was started by an older tego that has no write blocks; its next run gets the change"
	// whyPlaneWrite is a write block asked of a run whose kernel decision plane answers file changes without asking the
	// supervisor (livestatus.Facts.KernelDecidesChanges): the block would say "in force" and refuse only part of them.
	whyPlaneWrite = "at this run's protection level the kernel decides file changes itself, so a live block cannot refuse them all now; " +
		"its next run gets the change"
)

// blockOf is the live block that applies the list change c to a running run now, or why none does. rest is the
// contract's entries after the change (rule.Entries; nil when they are not known). A live block is offered only where
// it refuses nothing the new contract allows (it may refuse less: a write block leaves reads alone):
//
//   - exec.allow X removed, or exec.deny X added: exec:X (a program; a command entry "git push" has none, since a
//     live block names a whole program and would refuse git pull too), unless another exec.allow entry still allows
//     that program;
//   - net.allow or net.ask X removed: net:X, unless another net.allow or net.ask entry still admits that host;
//   - fs.deny_read X added (a block of a read, or the ask_read → deny_read move of "Never allow"): read:X, a path and
//     everything beneath it for reads only, which the supervisor decides only when the run sees its reads (heldReads);
//   - fs.deny_write X added: write:X, the changes under X;
//   - fs.write X removed: write:X, unless another fs.write or fs.ask entry still covers X, or a part of it;
//   - fs.ask X removed (Never allow on a write ask, or Remove): write:X, as an fs.write removal, under the same
//     condition: once the ask goes, a change under X is outside the contract, so the run may not make it now either.
//
// An addition the contract no longer holds (a later change took it back) has none: rest decides what still narrows.
// Every other change says why it has none: an ask added, a read ask removed, a pattern, a widening. A write block is
// further held to what the run's launcher can enforce (nowOptions: whyOldWrite, whyPlaneWrite), whichever change
// asked for it.
func blockOf(c rule.Change, cwd, home string, rest map[string][]string) (kind liveblock.Kind, value, why string) {
	if !c.Remove && rest != nil && slices.Contains(rule.EditKeys(), c.Key) && !stillListed(c.Key, c.Entry, rest[c.Key], cwd, home) {
		return "", "", whyTakenBack
	}
	switch {
	case !c.Remove && c.Key == "exec.deny", c.Remove && c.Key == "exec.allow":
		if strings.ContainsAny(c.Entry, " \t") {
			return "", "", whyCommand
		}
		v := execValue(c.Entry, cwd)
		k, n, why := norm(liveblock.KindExec, v)
		if why == "" && c.Key == "exec.allow" {
			if other, ok := execStillAllowed(n, rest["exec.allow"], cwd); ok {
				return "", "", "another exec.allow entry (" + other + ") still allows that program"
			}
		}
		return k, n, why
	case c.Remove && (c.Key == "net.allow" || c.Key == "net.ask"):
		k, n, why := norm(liveblock.KindNet, c.Entry)
		if why == "" {
			if other, ok := netStillAdmitted(n, append(slices.Clone(rest["net.allow"]), rest["net.ask"]...)); ok {
				return "", "", "another entry (" + other + ") still admits that destination"
			}
		}
		return k, n, why
	case !c.Remove && c.Key == "fs.deny_read":
		return fsBlock(liveblock.KindRead, c.Entry, cwd, home)
	case !c.Remove && c.Key == "fs.deny_write":
		return fsBlock(liveblock.KindWrite, c.Entry, cwd, home)
	case c.Remove && (c.Key == "fs.write" || c.Key == "fs.ask"):
		k, v, why := fsBlock(liveblock.KindWrite, c.Entry, cwd, home)
		if why != "" {
			return k, v, why
		}
		for _, key := range []string{"fs.write", "fs.ask"} {
			if other, ok := fsStillCovered(v, rest[key], cwd, home); ok {
				return "", "", "another " + key + " entry (" + other + ") still covers it, so a live block would refuse more than the new rules do"
			}
		}
		return k, v, ""
	case !c.Remove && (c.Key == "fs.ask" || c.Key == "fs.ask_read" || c.Key == "net.ask"):
		return "", "", whyAskAdd
	case c.Remove && c.Key == "fs.ask_read":
		return "", "", whyAskRemove
	case c.Remove && (c.Key == "fs.deny_read" || c.Key == "fs.deny_write" || c.Key == "exec.deny"),
		!c.Remove && (c.Key == "fs.write" || c.Key == "exec.allow" || c.Key == "net.allow"):
		return "", "", whyWidens
	}
	return "", "", whyUnknownKey
}

// fenceOf is the fence entry a widening list change c would need lifted or granted on a running Adjustable run (ADR
// 0125 decision 2): fs.read added or fs.deny_read removed is read:X; net.allow added is net:X; exec.allow added, or
// an exec.deny entry that names a whole program removed, is exec:X. source is the fence entry's source the change must
// meet: an addition is new access (record.LiveFenceSourceNew), a removal takes out one of the contract's own refusals
// (record.LiveFenceSourceDeny). A lift of a deny-source entry while the contract keeps that refusal, or a grant of a
// new-source entry the change does not add, is not what the saved change does, so it is not offered as its Live now.
// A pattern, a command entry and every other change have none.
func fenceOf(c rule.Change, cwd, home string) (k liveblock.Kind, v, source string, ok bool) {
	var why string
	source = record.LiveFenceSourceNew
	if c.Remove {
		source = record.LiveFenceSourceDeny
	}
	switch {
	case !c.Remove && c.Key == "fs.read", c.Remove && c.Key == "fs.deny_read":
		k, v, why = fsBlock(liveblock.KindRead, c.Entry, cwd, home)
	case !c.Remove && c.Key == "net.allow":
		if strings.Contains(c.Entry, "*") {
			return "", "", "", false
		}
		k, v, why = norm(liveblock.KindNet, c.Entry)
	case !c.Remove && c.Key == "exec.allow", c.Remove && c.Key == "exec.deny":
		if strings.ContainsAny(c.Entry, " \t") || strings.HasSuffix(c.Entry, "/") {
			return "", "", "", false
		}
		k, v, why = norm(liveblock.KindExec, execValue(c.Entry, cwd))
	default:
		return "", "", "", false
	}
	return k, v, source, why == ""
}

// fenceEntry is the entry of fence a change mapped by fenceOf to kind, value and source lifts or grants. Kind, value
// and source must all match, except that a removed exec.deny entry naming a bare program ("psql") matches the
// deny-source exec entry compile resolved it to ("/usr/bin/psql", pkg/spec/agent): the fence keeps the resolved path,
// and its last element is the name the contract refused.
func fenceEntry(fence []record.LiveFenceEntry, kind, value, source string) (record.LiveFenceEntry, bool) {
	bare := kind == string(liveblock.KindExec) && source == record.LiveFenceSourceDeny && !strings.Contains(value, "/")
	for _, e := range fence {
		if e.Kind != kind || e.Source != source {
			continue
		}
		if e.Value == value || bare && path.Base(e.Value) == value {
			return e, true
		}
	}
	return record.LiveFenceEntry{}, false
}

// stillListed reports whether the list key of the contract now (rest) still holds entry: spelled the same, or, for a
// path list, an entry naming the same path ("./vault" for "./vault/").
func stillListed(key, entry string, rest []string, cwd, home string) bool {
	if slices.Contains(rest, entry) {
		return true
	}
	if !strings.HasPrefix(key, "fs.") {
		return false
	}
	want, why := fsPath(entry, cwd, home)
	if why != "" {
		return false
	}
	return slices.ContainsFunc(rest, func(e string) bool {
		p, why := fsPath(e, cwd, home)
		return why == "" && p == want
	})
}

// execValue is an exec entry as a live block's value: a relative path made absolute under cwd, a directory keeping its
// trailing "/" (every program beneath it, as liveblock keeps it), a bare name as it is.
func execValue(v, cwd string) string {
	if strings.Contains(v, "/") && !path.IsAbs(v) {
		dir := strings.HasSuffix(v, "/")
		v = path.Join(cwd, v)
		if dir {
			v += "/"
		}
	}
	return v
}

// execStillAllowed is another program entry of rest that admits a program the block on v would refuse: the same
// value, the same program name where either is a bare name, a directory holding the other.
func execStillAllowed(v string, rest []string, cwd string) (string, bool) {
	for _, e := range rest {
		prog := e
		if f := strings.Fields(e); len(f) > 1 {
			prog = f[0] // a command entry admits its program for that command
		}
		n, err := liveblock.Normalize(liveblock.KindExec, execValue(prog, cwd))
		if err != nil {
			continue
		}
		bare := !strings.HasPrefix(n, "/") || !strings.HasPrefix(v, "/")
		switch {
		case n == v,
			bare && path.Base(strings.TrimSuffix(n, "/")) == path.Base(strings.TrimSuffix(v, "/")),
			strings.HasSuffix(n, "/") && strings.HasPrefix(v, n),
			strings.HasSuffix(v, "/") && strings.HasPrefix(n, v):
			return e, true
		}
	}
	return "", false
}

// netStillAdmitted is another destination entry of rest that admits a destination the block on v would refuse: the
// same host (by any port, when either names no port) or a host pattern ("*.example.com") matching it.
func netStillAdmitted(v string, rest []string) (string, bool) {
	host, port := splitHostPort(v)
	for _, e := range rest {
		if strings.Contains(e, "*") {
			pat, _ := splitHostPort(strings.ToLower(e))
			if ok, _ := path.Match(pat, host); ok {
				return e, true
			}
			continue
		}
		n, err := liveblock.Normalize(liveblock.KindNet, e)
		if err != nil {
			continue
		}
		h, p := splitHostPort(n)
		if h == host && (p == "" || port == "" || p == port) {
			return e, true
		}
	}
	return "", false
}

// splitHostPort is a normalized destination's host and port ("" for none); a unix name is all host.
func splitHostPort(v string) (host, port string) {
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "@") {
		return v, ""
	}
	if strings.HasPrefix(v, "[") {
		if i := strings.Index(v, "]:"); i > 0 {
			return v[1:i], v[i+2:]
		}
		return strings.Trim(v, "[]"), ""
	}
	if strings.Count(v, ":") == 1 {
		h, p, _ := strings.Cut(v, ":")
		return h, p
	}
	return v, ""
}

// fsBlock is a path entry as a live block of kind: ~ under home, a relative path under cwd; a pattern has none.
func fsBlock(kind liveblock.Kind, entry, cwd, home string) (liveblock.Kind, string, string) {
	p, why := fsPath(entry, cwd, home)
	if why != "" {
		return "", "", why
	}
	return norm(kind, p)
}

// fsPath is a path entry made absolute, or why it cannot be.
func fsPath(entry, cwd, home string) (string, string) {
	if strings.ContainsAny(entry, "*?[") {
		return "", whyPattern
	}
	p := entry
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return "", whyNoHome
		}
		p = path.Join(home, strings.TrimPrefix(p, "~"))
	case !path.IsAbs(p):
		p = path.Join(cwd, p)
	}
	return path.Clean(p), ""
}

// fsStillCovered is an entry of rest that covers v or a part of it: one at or above v (it still allows or asks for v),
// or one beneath it (a write block on v would refuse there too). A pattern entry is compared by its literal folder
// before the first wildcard.
func fsStillCovered(v string, rest []string, cwd, home string) (string, bool) {
	for _, e := range rest {
		lit := e
		if i := strings.IndexAny(lit, "*?["); i >= 0 {
			lit = path.Dir(lit[:i] + "x") // the folder the pattern starts in
		}
		p, why := fsPath(lit, cwd, home)
		if why != "" {
			continue
		}
		if p == v || strings.HasPrefix(v, strings.TrimSuffix(p, "/")+"/") || strings.HasPrefix(p, v+"/") || p == "/" {
			return e, true
		}
	}
	return "", false
}

func norm(k liveblock.Kind, v string) (liveblock.Kind, string, string) {
	n, err := liveblock.Normalize(k, v)
	if err != nil {
		return "", "", "no live block names it: " + err.Error()
	}
	return k, n, ""
}

// nowOptions is every live block the changes map to, on every running run of the contract (runs, newest first), and
// every change with none with its reason, once per run. rest is the contract's entries after the changes. A read
// (or path) block is offered on a run only while that run holds its reads or records every read:
// otherwise the read never reaches the supervisor that enforces the block, and the box would promise what it cannot
// do. On a watched run every offer is marked Observe: the block would be recorded, not enforced. A change that has
// none is left out when another change of the same entry has one ("Never allow" removes the ask_read entry and adds
// the deny_read one: the deny_read's block says it).
//
// A run whose launcher predates read and write blocks (record_minor below record.MinorLiveControl) would fail to read
// an overlay holding one and ignore every later change, so it is offered what that launcher enforces: an added
// fs.deny_read as a path block (refusing changes there too, as before read blocks existed), and no write block. A run
// whose kernel decision plane answers file changes itself is offered no write block either.
func (s *Service) nowOptions(ctx context.Context, runs []string, changes []rule.Change, cwd string, rest map[string][]string) []NowOption {
	var out []NowOption
	for _, run := range runs {
		held, heldWhy := -1, ""
		facts := s.runFacts(run)
		var mine []NowOption
		for _, c := range changes {
			k, v, why := blockOf(c, cwd, s.Home, rest)
			if k == "" && why != whyTakenBack && facts.Adjustable {
				if fk, fv, src, ok := fenceOf(c, cwd, s.Home); ok {
					if e, in := fenceEntry(facts.Fence, string(fk), fv, src); in {
						mine = append(mine, NowOption{Run: run, Kind: e.Kind, Value: e.Value, Why: WhyFenceLift, Change: c.String(),
							Observe: facts.Observe, Cwd: cwd, FenceLift: true})
						continue
					}
				}
			}
			switch {
			case k == liveblock.KindRead && !facts.NarrowKinds():
				k = liveblock.KindPath
			case k == liveblock.KindWrite && !facts.NarrowKinds():
				k, v, why = "", "", whyOldWrite
			case k == liveblock.KindWrite && facts.KernelDecidesChanges:
				k, v, why = "", "", whyPlaneWrite
			}
			o := NowOption{Run: run, Kind: string(k), Value: v, OK: k != "", Why: why, Change: c.String(), Observe: facts.Observe, Cwd: cwd}
			if k != "" {
				o.Block = liveblock.Key(k, v)
			}
			if k == liveblock.KindRead || k == liveblock.KindPath {
				if held < 0 {
					ok, why := s.heldReads(ctx, run)
					held, heldWhy = map[bool]int{true: 1, false: 0}[ok], why
				}
				if held == 0 {
					o.OK, o.Why = false, heldWhy
				}
			}
			if !slices.ContainsFunc(mine, func(x NowOption) bool { return x.Block == o.Block && o.Block != "" }) {
				mine = append(mine, o)
			}
		}
		for _, o := range mine {
			if !o.OK && o.Block == "" && slices.ContainsFunc(mine, func(x NowOption) bool { return x.Block != "" && sameEntry(x.Change, o.Change) }) {
				continue
			}
			out = append(out, o)
		}
	}
	return out
}

// sameEntry reports whether two journal-spelled changes ("fs.ask_read -= ./docs/") name the same entry.
func sameEntry(a, b string) bool {
	entry := func(s string) string {
		for _, op := range []string{" -= ", " += "} {
			if _, e, ok := strings.Cut(s, op); ok {
				return e
			}
		}
		return s
	}
	return entry(a) == entry(b)
}

// runFacts is what run's record says of how it can enforce a live block (runact.StartFacts).
func (s *Service) runFacts(run string) livestatus.Facts {
	if s.facts != nil {
		return s.facts(run)
	}
	if !runID(run) {
		return livestatus.Facts{}
	}
	return runact.StartFacts(filepath.Join(s.Ledger, run))
}

// heldReads is whether the running run's own contract copy, compiled at the run's tier, holds its read opens or
// records every read (agent.RuleTable.ReadsHeldAt, record: full), and why not otherwise.
func (s *Service) heldReads(ctx context.Context, run string) (bool, string) {
	if s.readsHeld != nil {
		return s.readsHeld(run)
	}
	if s.Machine == nil {
		return false, "the machine config is not read here, so it is not known whether this run holds its reads"
	}
	c := rulesview.Load(ctx, s.Ledger, run, rulesview.Options{Machine: s.Machine, Anchor: s.Anchor})
	if c.Compiled == nil {
		return false, "this run's contract does not compile here, so it is not known whether it holds its reads"
	}
	t, err := backend.ParseTier(c.Tier)
	if err == nil && c.Compiled.ReadsHeldAt(t) || c.Compiled.Record == agent.RecordFull {
		return true, ""
	}
	return false, "this run reads files directly (its reads are not held), so a live block cannot refuse a read now; " +
		"the change applies from its next run"
}

// applyNow places the OK options of the runs picked (AlsoNow); a picked run that has none, or is no running run of
// the contract any more, is reported, never a reason to undo the write.
func (s *Service) applyNow(ctx context.Context, opts []NowOption, picked []string) []LiveResult {
	var out []LiveResult
	for _, run := range dedupe(picked) {
		placed := false
		for _, o := range opts {
			if o.Run != run || !o.OK {
				continue
			}
			placed = true
			r := LiveResult{Run: run, Block: o.Block, OK: true, Observe: o.Observe}
			b, err := s.placeBlock(ctx, run, o.Kind, o.Value)
			if err != nil {
				r.OK, r.Err = false, err.Error()
			}
			r.Serial = b.Serial
			out = append(out, r)
		}
		if !placed {
			out = append(out, LiveResult{Run: run, Err: "no live block is offered for this run (it is not running this contract now, " +
				"or the change has none)"})
		}
	}
	return out
}

func (s *Service) placeBlock(ctx context.Context, run, kind, value string) (runact.Blocked, error) {
	if s.block != nil {
		return runact.Blocked{Run: run}, s.block(ctx, run, kind, value)
	}
	return runact.Block(ctx, s.Ledger, run, kind, value, true)
}

// journalLive is the journal's form of the outcomes.
func journalLive(rs []LiveResult) []rulefile.Live {
	out := make([]rulefile.Live, 0, len(rs))
	for _, r := range rs {
		out = append(out, rulefile.Live{Run: r.Run, Block: r.Block, OK: r.OK, Err: r.Err, Lift: r.Lift})
	}
	return out
}

func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x != "" && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// path is the PATH this dashboard compiles with.
func (s *Service) path() string {
	if s.PATH != "" {
		return s.PATH
	}
	return os.Getenv("PATH")
}

// entriesOf is the editable lists' entries of a contract text (rule.Entries), nil when it does not parse.
func entriesOf(text []byte) map[string][]string {
	m, err := rule.Entries(text)
	if err != nil {
		return nil
	}
	return m
}
