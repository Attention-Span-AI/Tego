// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/syslookup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A run's Signal is one pass over its lines (the fold) and a post-pass over what the pass gathered (finish). A live
// 24/7 agent's run gains a few lines a second, and a full pass over 100k lines took 70-150 ms per live update per open
// tab (the r7 perf lane, PF-F1), so the fold is kept per run (signalcache.go) and a new version of the run folds only
// the lines it gained. Everything that depends on the whole run or on the run's state rather than on its lines
// (which groups are background, what is near a secret, whether an open ask is pending or lost, the order) is decided
// by finish, on copies, so a read never changes the fold. computeSignal is the same fold run from the first line,
// and TestSignalFoldEqualsOnePass holds the incremental Signal equal to the one-pass code it replaced.

// lineMark is what says a line is the one a fold took: its seq, time and byte offset in the events file.
type lineMark struct {
	seq uint64
	ts  time.Time
	off int64
}

func markOf(e *Event) lineMark { return lineMark{e.Seq, e.TS, e.off} }

// touchAt is one secret touch's place in the ledger, in ledger order, for the near-a-secret windows.
type touchAt struct {
	seq uint64
	ts  time.Time
}

// probeSet is the destinations of refused net lines that were a route probe (RouteProbe) and the ones that were not;
// a destination is a probe target when every refused net line to it was a probe.
type probeSet struct{ probe, other map[string]bool }

func (p *probeSet) add(e *Event) {
	if e.Kind != "net" || !e.Refused() {
		return
	}
	if p.probe == nil {
		p.probe, p.other = map[string]bool{}, map[string]bool{}
	}
	_, dst := splitNet(e.Target)
	if RouteProbe(e) {
		p.probe[dst] = true
	} else {
		p.other[dst] = true
	}
}

// targets is the probe targets (probeTargets), a fresh map.
func (p *probeSet) targets() map[string]bool {
	out := map[string]bool{}
	for d := range p.probe {
		if !p.other[d] {
			out[d] = true
		}
	}
	return out
}

// signalFold is the pass over a run's first n lines: each secret touched and its counts, each destination, the ask
// and answer lines, the refusal groups, the live blocks and the refused programs, in first-seen order as the one-pass
// code built them. It is for one Sensitive only.
type signalFold struct {
	sens        sensitiveMatch
	n           int
	first, last lineMark // lines 0 and n-1

	secrets  map[string]int
	secretL  []SecretTouch
	touches  []touchAt
	dests    map[string]int
	outbound []Dest
	// destAddrs is what each destination's Addrs holds (group is its place in outbound): a name whose DNS the agent
	// controls can stand for an address per line, and scanning the list for each line took 2 s at 40,000.
	destAddrs map[groupPart]bool
	reached   map[string]bool // hosts the run reached (allowed or observed)
	// liveHosts are the hosts a net live block named at any time in the run, and the addresses one refused (HostOf's form).
	liveHosts map[string]bool
	probes    probeSet
	groups    map[string]int
	groupL    []Group
	// groupTargets and groupPorts are what each group's lists hold: a group on one host can hold 65,535 of each, and
	// scanning a list for each line took 3.8 s at 40,000.
	groupTargets, groupPorts map[groupPart]bool
	asks                     map[string]int
	// approvals' State is "" until an answer line: finish says pending, lost or unanswered from the run's state.
	approvals []Approval
	blocks    map[string]int
	blockL    []BlockHit
	programs  map[string]int
	programL  []ProgramHit
}

func newSignalFold(s Sensitive) *signalFold {
	return &signalFold{sens: compileSensitive(s), secrets: map[string]int{}, dests: map[string]int{},
		destAddrs: map[groupPart]bool{}, reached: map[string]bool{}, liveHosts: map[string]bool{}, groups: map[string]int{},
		groupTargets: map[groupPart]bool{}, groupPorts: map[groupPart]bool{}, asks: map[string]int{}, blocks: map[string]int{}, programs: map[string]int{}}
}

// extends reports whether evs is the lines this fold took and maybe more: the same first line and the same line at
// n-1 (by seq, time and offset; a run's file only grows, and one replaced or cut gives other lines there).
func (f *signalFold) extends(evs []Event) bool {
	return f.n > 0 && len(evs) >= f.n && markOf(&evs[0]) == f.first && markOf(&evs[f.n-1]) == f.last
}

// add folds lines in after the ones already taken.
func (f *signalFold) add(evs []Event) {
	if len(evs) == 0 {
		return
	}
	if f.n == 0 {
		f.first = markOf(&evs[0])
	}
	for i := range evs {
		f.take(&evs[i])
	}
	f.n += len(evs)
	f.last = markOf(&evs[len(evs)-1])
}

// touch counts one touch of path p, the i-th of e's paths (Event.secretPart), when it is a secret to the run: its
// rule guards a secret, it is under a contract entry, or its name says so (IsSecretPath).
func (f *signalFold) touch(e *Event, i int, p, rule string, bump func(*SecretTouch)) {
	entry, under := f.sens.under(p)
	wk := e.secretPart(i, p)
	named := secretRule(rule)
	if !named && !under && !wk {
		return
	}
	i, ok := f.secrets[p]
	if !ok {
		i = len(f.secretL)
		f.secrets[p] = i
		f.secretL = append(f.secretL, SecretTouch{Path: p, First: e.TS, FirstSeq: e.Seq})
	}
	st := &f.secretL[i]
	if named && st.Rule == "" {
		st.Rule = rule
	}
	if under && st.Entry == "" {
		st.Entry = entry
	}
	st.WellKnown = st.WellKnown || wk
	bump(st)
	f.touches = append(f.touches, touchAt{e.Seq, e.TS})
}

// destKey is a destination's key (Dest.Key) and its Logs search text: "host:port" by name when the line names the
// host, else the dst as written. Verdict.Mark keys a line the same way.
func destKey(dst, name string) (key, q string) {
	host, port := hostPort(dst)
	key, q = dst, dst
	if name != "" && name != host {
		key, q = name, name
		if port != "" {
			key = name + ":" + port
		}
	}
	return key, q
}

func (f *signalFold) dest(e *Event, dst, name string) *Dest {
	key, q := destKey(dst, name)
	i, ok := f.dests[key]
	if !ok {
		i = len(f.outbound)
		f.dests[key] = i
		f.outbound = append(f.outbound, Dest{Key: key, Name: name, First: e.TS, FirstSeq: e.Seq, Query: q, groups: map[int]bool{}})
	}
	return &f.outbound[i]
}

// groupPart is one target or port of the group at place group, or one address of the destination at that place.
type groupPart struct {
	group int
	part  string
}

// hold appends part to list, the group's or destination's at place gi, once: seen is what that list holds.
func hold(seen map[groupPart]bool, gi int, list *[]string, part string) {
	if k := (groupPart{gi, part}); !seen[k] {
		seen[k] = true
		*list = append(*list, part)
	}
}

type answerPayload struct {
	After float64 `json:"after_s"`
}

// take folds one line.
func (f *signalFold) take(e *Event) {
	f.probes.add(e)
	switch e.Kind {
	case "fs":
		if e.Refused() || e.Verdict == "ask" {
			return // counted from its refused line, or from its ask line
		}
		for i, p := range paths(e.Target) {
			f.touch(e, i, p, e.Rule, func(st *SecretTouch) {
				if e.Verdict == "observed" {
					st.Observed++
				} else {
					st.Allowed++
				}
				if e.readNothing {
					st.Unread++
				} else {
					st.reads = append(st.reads, touchAt{e.Seq, e.TS})
				}
			})
		}
	case "net":
		if e.Refused() || !outboundOp(e.Op) {
			return
		}
		name, dst := splitNet(e.Target)
		if dst == "" || dst == "unspec" || dst == "netlink" {
			return
		}
		d := f.dest(e, dst, name)
		if d.Key != dst {
			hold(f.destAddrs, f.dests[d.Key], &d.Addrs, dst)
		}
		switch e.Verdict {
		case "allow":
			d.Allowed++
		case "observed":
			d.Observed++
		case "ask":
			d.Asked++
		}
		if strings.HasPrefix(e.Rule, "net[") || e.Rule == syslookup.ResolverRule {
			d.InContract = true
		}
		d.Resolver = d.Resolver || e.Rule == syslookup.ResolverRule
		if e.Verdict == "allow" || e.Verdict == "observed" {
			h, _ := hostPort(dst)
			f.reached[h] = true
		}
	case "ask":
		a := Approval{AskID: e.AskID, Op: e.askOp, Target: e.askTarget, Rule: e.Rule, TS: e.TS, Seq: e.Seq}
		if _, seen := f.asks[e.AskID]; !seen {
			f.asks[e.AskID] = len(f.approvals)
			f.approvals = append(f.approvals, a)
		}
		if a.Target != "" && (a.Op == "read" || a.Op == "open" || a.Op == "write" || strings.HasPrefix(a.Rule, "fs.")) {
			f.touch(e, 0, a.Target, a.Rule, func(st *SecretTouch) { st.Asked++ })
		}
	case "answer":
		i, ok := f.asks[e.AskID]
		if !ok {
			return
		}
		a := &f.approvals[i]
		a.State = "denied"
		if strings.HasSuffix(e.Target, ", approved") {
			a.State = "approved"
		}
		if _, by, ok := strings.Cut(e.Target, " by "); ok {
			a.By = strings.TrimSuffix(strings.TrimSuffix(by, ", approved"), ", not approved")
		}
		var p answerPayload
		if json.Unmarshal([]byte(e.Raw), &p) == nil && p.After > 0 {
			a.After = time.Duration(p.After * float64(time.Second))
		}
	case "refused":
		f.refused(e)
	case "gap":
		if !strings.HasSuffix(e.Target, record.GapLiveBlockAdded) {
			return
		}
		var p record.GapPayload
		if json.Unmarshal([]byte(e.Raw), &p) == nil && p.LiveBlock != nil && p.LiveBlock.Kind == record.LiveKindNet {
			f.liveHost(p.LiveBlock.Value)
		}
	}
}

// liveHost notes the host dst names, if it names one (a unix socket does not), as under a live block.
func (f *signalFold) liveHost(dst string) {
	if h := HostOf(dst); h != "" {
		f.liveHosts[h] = true
	}
}

// blocked is what classify keeps out of "the run also reached this host": every host a net live block of this run named,
// whenever in the run, and the addresses a named one was reached at (a refused connect names no host), all in HostOf's
// form, so a scope id on the agent's connects is no way around a block that holds none. A group folds lines from before
// a block and after it, so a block's time is not read: the group shows, which is the safe way to err.
func (f *signalFold) blocked() map[string]bool {
	if len(f.liveHosts) == 0 {
		return nil
	}
	out := maps.Clone(f.liveHosts)
	for i := range f.outbound {
		if d := &f.outbound[i]; f.liveHosts[strings.ToLower(d.Name)] {
			for _, a := range d.Addrs {
				out[HostOf(a)] = true
			}
		}
	}
	return out
}

// refused folds one refused line into its group, and into its destination, program, secret or live block.
func (f *signalFold) refused(e *Event) {
	g := Group{Event: *e, First: e.TS, Last: e.TS, FirstSeq: e.Seq}
	var port string
	g.Class, g.Subject, port = groupSubject(e)
	k := groupKey(e, g.Subject)
	gi, ok := f.groups[k]
	if !ok {
		gi = len(f.groupL)
		f.groups[k] = gi
		f.groupL = append(f.groupL, g)
	} else {
		og := &f.groupL[gi]
		og.Event, og.Last = *e, e.TS
	}
	og := &f.groupL[gi]
	hold(f.groupTargets, gi, &og.Targets, e.Target)
	if port != "" {
		hold(f.groupPorts, gi, &og.Ports, port)
	}
	og.Count++
	switch g.Class {
	case "net":
		if e.Target != "" && e.Target != "unspec" && e.Target != "netlink" {
			d := f.dest(e, e.Target, "")
			d.Refused++
			d.groups[gi] = true
		}
	case "exec":
		pk := g.Subject + "\x00" + e.Rule
		pi, ok := f.programs[pk]
		if !ok {
			pi = len(f.programL)
			f.programs[pk] = pi
			f.programL = append(f.programL, ProgramHit{Program: g.Subject, Rule: e.Rule})
		}
		f.programL[pi].N++
	case "fs":
		f.touch(e, 0, e.Target, e.Rule, func(st *SecretTouch) { st.Refused++ })
		og.Write = og.Write || writesFile(e)
		if og.to == "" && e.to != "" && RunsLater(e.to) {
			og.to = e.to
		}
		if secretRule(e.Rule) || e.secretPart(0, e.Target) {
			og.Secret = true
		} else if _, ok := f.sens.under(e.Target); ok {
			og.Secret = true
		}
	}
	if v, ok := strings.CutPrefix(e.Rule, "live.block["); ok {
		if g.Class == "net" {
			f.liveHost(ruleDest(e.Rule))
			f.liveHost(e.Target)
		}
		bi, seen := f.blocks[e.Rule]
		if !seen {
			bi = len(f.blockL)
			f.blocks[e.Rule] = bi
			f.blockL = append(f.blockL, BlockHit{Rule: e.Rule, Value: strings.TrimSuffix(v, "]")})
		}
		f.blockL[bi].N++
	}
}

// finish is the Signal of run r from the lines folded so far (r's lines): it copies what the fold gathered and
// decides, on the copies, what needs the whole run or its state. The fold is not changed, and the result shares
// nothing the fold changes later.
func (f *signalFold) finish(r *Run) *RunSignal {
	out := &RunSignal{
		agent:     CommandAgent(r.Command),
		rules:     f.sens.rules,
		Secrets:   slices.Clone(f.secretL),
		Outbound:  slices.Clone(f.outbound),
		Groups:    slices.Clone(f.groupL),
		Approvals: slices.Clone(f.approvals),
		Blocks:    slices.Clone(f.blockL),
		Programs:  slices.Clone(f.programL),
	}
	for i := range out.Groups {
		// A later line appends to the fold's Targets and Ports: clipped, a caller's append cannot write there.
		g := &out.Groups[i]
		g.Targets, g.Ports = slices.Clip(g.Targets), slices.Clip(g.Ports)
	}
	for i := range out.Outbound {
		d := &out.Outbound[i]
		d.Addrs = slices.Clip(d.Addrs)
	}
	// Only a live run's asks can still be answered: a lost run's open ask is never pending (Snapshot.Pending).
	pending := map[string]bool{}
	if r.Live {
		for _, a := range r.Pending {
			pending[a.AskID] = true
		}
	}
	for i := range out.Approvals {
		a := &out.Approvals[i]
		if a.State != "" {
			continue // answered
		}
		switch {
		case pending[a.AskID]:
			a.State = "pending"
		case !r.Ended && !r.Live:
			a.State = "lost"
		default:
			a.State = "unanswered"
		}
	}
	touches := f.touches[:len(f.touches):len(f.touches)]
	near := func(seq uint64, ts time.Time) bool { return nearOne(touches, seq, ts) }
	probes, blocked := f.probes.targets(), f.blocked()
	for i := range out.Groups {
		g := &out.Groups[i]
		// A system lookup (nscd, userdb, the D-Bus buses) or a DNS lookup is what the C library does around any
		// connect: it carries none of the run's data, so it is never "next to a secret", however close it comes.
		g.NearSecret = g.Class == "net" && !g.SystemLookup && !dnsGroup(g) && near(g.FirstSeq, g.First)
		classify(g, f.reached, probes, blocked)
		g.Severity = groupSeverity(g, out.agent, out.rules)
		if out.sev == nil {
			out.sev = map[string]Severity{}
		}
		out.sev[groupKey(&g.Event, g.Subject)] = g.Severity
		if k := g.Class + "\x00" + g.Subject; g.Severity > out.sev[k] {
			out.sev[k] = g.Severity
		}
		if g.Background {
			if out.bg == nil {
				out.bg = map[string]bool{}
			}
			out.bg[groupKey(&g.Event, g.Subject)] = true
		}
		if g.to != "" { // last: the keys above are the subject's
			g.Query, g.Subject = g.Subject, g.Subject+" → "+g.to
		}
	}
	for i := range out.Programs {
		p := &out.Programs[i]
		p.Background = groupBackground(out.Groups, p)
	}
	for i := range out.Outbound {
		d := &out.Outbound[i]
		if lookupDst(d) {
			// A system lookup socket or the resolver is routine whatever its lines say (observed, allowed or refused,
			// once or a hundred times): a real Codex under tego watch asks nscd for every name it resolves, and a
			// verdict that named the nscd socket as where the secrets went would point the reader at the C library.
			d.Background = true
		} else {
			// A destination the contract allows is where the agent is meant to talk: a send to it right after a
			// secret read is not the attack the mark points at.
			d.NearSecret = !d.InContract && near(d.FirstSeq, d.First)
		}
		if !d.Background && d.Refused > 0 && d.Allowed+d.Observed+d.Asked == 0 {
			d.Background = true
			for gi := range d.groups {
				d.Background = d.Background && out.Groups[gi].Background
			}
		}
		// The fold adds to this map on later lines; the result keeps none of it (only this loop reads it).
		d.groups = nil
		if d.Background {
			out.BackgroundDests++
			out.BackgroundDestLines += d.Refused
		}
	}
	for i := range out.Secrets {
		st := &out.Secrets[i]
		st.NearSend, st.ReadNearSend = nearSend(st, out.Outbound)
		st.Severity = secretSeverity(st, out.agent, out.rules)
	}
	// After Outbound, whose destinations name groups by index; before the counts, which count rows.
	out.Groups = mergeBursts(out.Groups)
	for i := range out.Groups {
		out.count(&out.Groups[i])
	}
	sortSignal(out)
	for _, a := range out.Approvals {
		switch a.State {
		case "approved":
			out.Approved++
		case "denied":
			out.Denied++
		case "pending":
			out.PendingN++
		default:
			out.Unanswered++
		}
	}
	return out
}

// nearOne is whether the line at seq and ts lies within the window of one of touches, which are in ledger order.
func nearOne(touches []touchAt, seq uint64, ts time.Time) bool {
	i := sort.Search(len(touches), func(i int) bool { return touches[i].seq+NearSecretLines >= seq })
	for ; i < len(touches) && touches[i].seq <= seq+NearSecretLines; i++ {
		if d := touches[i].ts.Sub(ts); d <= NearSecretWindow && d >= -NearSecretWindow {
			return true
		}
	}
	return false
}

// count adds refusal group g to the run's counts: a routine group and its lines to Background and BackgroundLines,
// any other to its severity, Real and RealLines.
func (s *RunSignal) count(g *Group) {
	switch g.Severity {
	case SevRoutine:
		s.Background++
		s.BackgroundLines += g.Count
		return
	case SevHigh:
		s.High++
	case SevMedium:
		s.Medium++
	case SevLow:
		s.Low++
	}
	s.Real++
	s.RealLines += g.Count
}
