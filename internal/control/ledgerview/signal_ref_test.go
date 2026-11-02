// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/secretpath"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The Signal as one pass computed it before it was made faster, copied unchanged but for the names (and
// secretpath.Is for IsSecretPath, which is now memoized) and for what was added to the Signal since (Dest.Addrs, a
// live-blocked host), so that the
// equivalence test (signal_fold_test.go) checks the incremental fold against the code that decided the demo's
// verdicts, not against itself.

// refBlocked is what the rule on a live-blocked host keeps out of "the run also reached this host", added with that rule.
func refBlocked(liveHosts map[string]bool, outbound []Dest) map[string]bool {
	out := map[string]bool{}
	for h := range liveHosts {
		out[h] = true
	}
	for i := range outbound {
		if liveHosts[strings.ToLower(outbound[i].Name)] {
			for _, a := range outbound[i].Addrs {
				out[HostOf(a)] = true
			}
		}
	}
	return out
}

func refUnder(s Sensitive, p string) (string, bool) {
	for _, e := range s.Entries {
		full := e
		if strings.HasPrefix(full, "~") {
			continue // the run's home is not recorded; a refusal still names the entry in its rule
		}
		if !filepath.IsAbs(full) {
			if s.Cwd == "" {
				continue
			}
			full = filepath.Join(s.Cwd, full)
		}
		full = filepath.Clean(full)
		if strings.ContainsAny(full, "*?[") {
			if ok, _ := filepath.Match(full, p); ok {
				return e, true
			}
			continue
		}
		if p == full || strings.HasPrefix(p, full+"/") {
			return e, true
		}
	}
	return "", false
}

// refProbeTargets is probeTargets as it was: the destinations of r every refused net line to which is a route
// probe: the refused lines (kind refused, which carry no protocol) to one of them are route probes too.
func refProbeTargets(r *Run) map[string]bool {
	probe, other := map[string]bool{}, map[string]bool{}
	evs := r.AllEvents()
	for i := range evs {
		e := &evs[i]
		if e.Kind != "net" || !e.Refused() {
			continue
		}
		_, dst := splitNet(e.Target)
		if RouteProbe(e) {
			probe[dst] = true
		} else {
			other[dst] = true
		}
	}
	for d := range other {
		delete(probe, d)
	}
	return probe
}

// refSignal is computeSignal as it was before the fold (signalfold.go): one pass over every line, kept as the
// reference the incremental Signal must equal.
func refSignal(r *Run, s Sensitive) *RunSignal {
	out := &RunSignal{agent: CommandAgent(r.Command), rules: s.Rules}
	secrets := map[string]int{}
	type at struct {
		seq uint64
		ts  time.Time
	}
	var touches []at // in ledger order
	touch := func(e *Event, p, rule string, bump func(*SecretTouch)) {
		entry, under := refUnder(s, p)
		named := secretRule(rule)
		wk := secretpath.Is(p)
		if !named && !under && !wk {
			return
		}
		i, ok := secrets[p]
		if !ok {
			i = len(out.Secrets)
			secrets[p] = i
			out.Secrets = append(out.Secrets, SecretTouch{Path: p, First: e.TS, FirstSeq: e.Seq})
		}
		st := &out.Secrets[i]
		if named && st.Rule == "" {
			st.Rule = rule
		}
		if under && st.Entry == "" {
			st.Entry = entry
		}
		st.WellKnown = st.WellKnown || wk
		bump(st)
		touches = append(touches, at{e.Seq, e.TS})
	}
	dests := map[string]int{}
	dest := func(e *Event, dst, name string) *Dest {
		host, port := hostPort(dst)
		key, q := dst, dst
		if name != "" && name != host {
			key, q = name, name
			if port != "" {
				key = name + ":" + port
			}
		}
		i, ok := dests[key]
		if !ok {
			i = len(out.Outbound)
			dests[key] = i
			out.Outbound = append(out.Outbound, Dest{Key: key, Name: name, First: e.TS, FirstSeq: e.Seq, Query: q, groups: map[int]bool{}})
		}
		return &out.Outbound[i]
	}
	reached, probes := map[string]bool{}, refProbeTargets(r)
	liveHosts := map[string]bool{} // added with the rule: a net live block's hosts, and the addresses one refused
	groups := map[string]int{}
	// Only a live run's open asks wait on a person; a lost run's were never answered (Snapshot.Pending).
	pending := map[string]bool{}
	if r.Live {
		// Only a live run's asks can still be answered: a lost run's open ask is never pending.
		for _, a := range r.Pending {
			pending[a.AskID] = true
		}
	}
	asks := map[string]int{}
	blocks := map[string]int{}
	programs := map[string]int{}
	type answer struct {
		After float64 `json:"after_s"`
	}
	evs := r.AllEvents()
	for i := range evs {
		e := &evs[i]
		switch e.Kind {
		case "fs":
			if e.Refused() || e.Verdict == "ask" {
				continue // counted from its refused line, or from its ask line
			}
			for _, p := range paths(e.Target) {
				touch(e, p, e.Rule, func(st *SecretTouch) {
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
				continue
			}
			name, dst := splitNet(e.Target)
			if dst == "" || dst == "unspec" || dst == "netlink" {
				continue
			}
			d := dest(e, dst, name)
			if d.Key != dst && !slices.Contains(d.Addrs, dst) {
				d.Addrs = append(d.Addrs, dst)
			}
			switch e.Verdict {
			case "allow":
				d.Allowed++
			case "observed":
				d.Observed++
			case "ask":
				d.Asked++
			}
			if strings.HasPrefix(e.Rule, "net[") || e.Rule == "net.resolver" {
				d.InContract = true
			}
			d.Resolver = d.Resolver || e.Rule == "net.resolver"
			if e.Verdict == "allow" || e.Verdict == "observed" {
				h, _ := hostPort(dst)
				reached[h] = true
			}
		case "ask":
			a := Approval{AskID: e.AskID, Op: e.askOp, Target: e.askTarget, Rule: e.Rule, TS: e.TS, Seq: e.Seq, State: "unanswered"}
			switch {
			case pending[e.AskID]:
				a.State = "pending"
			case !r.Ended && !r.Live:
				a.State = "lost"
			}
			if _, seen := asks[e.AskID]; !seen {
				asks[e.AskID] = len(out.Approvals)
				out.Approvals = append(out.Approvals, a)
			}
			if a.Target != "" && (a.Op == "read" || a.Op == "open" || a.Op == "write" || strings.HasPrefix(a.Rule, "fs.")) {
				touch(e, a.Target, a.Rule, func(st *SecretTouch) { st.Asked++ })
			}
		case "answer":
			i, ok := asks[e.AskID]
			if !ok {
				continue
			}
			a := &out.Approvals[i]
			a.State = "denied"
			if strings.HasSuffix(e.Target, ", approved") {
				a.State = "approved"
			}
			if _, by, ok := strings.Cut(e.Target, " by "); ok {
				a.By = strings.TrimSuffix(strings.TrimSuffix(by, ", approved"), ", not approved")
			}
			var p answer
			if json.Unmarshal([]byte(e.Raw), &p) == nil && p.After > 0 {
				a.After = time.Duration(p.After * float64(time.Second))
			}
		case "refused":
			g := Group{Event: *e, First: e.TS, Last: e.TS, FirstSeq: e.Seq}
			var port string
			g.Class, g.Subject, port = groupSubject(e)
			if port != "" {
				g.Ports = []string{port}
			}
			k := groupKey(e, g.Subject)
			gi, ok := groups[k]
			if !ok {
				gi = len(out.Groups)
				groups[k] = gi
				g.Targets = []string{e.Target}
				out.Groups = append(out.Groups, g)
			} else {
				og := &out.Groups[gi]
				og.Event, og.Last = *e, e.TS
				if !slices.Contains(og.Targets, e.Target) {
					og.Targets = append(og.Targets, e.Target)
				}
				if len(g.Ports) > 0 && !slices.Contains(og.Ports, g.Ports[0]) {
					og.Ports = append(og.Ports, g.Ports[0])
				}
			}
			out.Groups[gi].Count++
			switch g.Class {
			case "net":
				if e.Target != "" && e.Target != "unspec" && e.Target != "netlink" {
					d := dest(e, e.Target, "")
					d.Refused++
					d.groups[gi] = true
				}
			case "exec":
				pk := g.Subject + "\x00" + e.Rule
				pi, ok := programs[pk]
				if !ok {
					pi = len(out.Programs)
					programs[pk] = pi
					out.Programs = append(out.Programs, ProgramHit{Program: g.Subject, Rule: e.Rule})
				}
				out.Programs[pi].N++
			case "fs":
				out.Groups[gi].Write = out.Groups[gi].Write || writesFile(e)
				if og := &out.Groups[gi]; og.to == "" && e.to != "" && RunsLater(e.to) {
					og.to = e.to
				}
				touch(e, e.Target, e.Rule, func(st *SecretTouch) { st.Refused++ })
				if secretRule(e.Rule) || secretpath.Is(e.Target) {
					out.Groups[gi].Secret = true
				} else if _, ok := refUnder(s, e.Target); ok {
					out.Groups[gi].Secret = true
				}
			}
			if v, ok := strings.CutPrefix(e.Rule, "live.block["); ok {
				if g.Class == "net" {
					for _, dst := range []string{ruleDest(e.Rule), e.Target} {
						if h := HostOf(dst); h != "" {
							liveHosts[h] = true
						}
					}
				}
				bi, seen := blocks[e.Rule]
				if !seen {
					bi = len(out.Blocks)
					blocks[e.Rule] = bi
					out.Blocks = append(out.Blocks, BlockHit{Rule: e.Rule, Value: strings.TrimSuffix(v, "]")})
				}
				out.Blocks[bi].N++
			}
		case "gap":
			var p record.GapPayload
			if strings.HasSuffix(e.Target, record.GapLiveBlockAdded) && json.Unmarshal([]byte(e.Raw), &p) == nil &&
				p.LiveBlock != nil && p.LiveBlock.Kind == record.LiveKindNet {
				if h := HostOf(p.LiveBlock.Value); h != "" {
					liveHosts[h] = true
				}
			}
		}
	}
	near := func(seq uint64, ts time.Time) bool {
		i := sort.Search(len(touches), func(i int) bool { return touches[i].seq+NearSecretLines >= seq })
		for ; i < len(touches) && touches[i].seq <= seq+NearSecretLines; i++ {
			if d := touches[i].ts.Sub(ts); d <= NearSecretWindow && d >= -NearSecretWindow {
				return true
			}
		}
		return false
	}
	blocked := refBlocked(liveHosts, out.Outbound)
	for i := range out.Groups {
		g := &out.Groups[i]
		// A system lookup (nscd, userdb, the D-Bus buses) or a DNS lookup is what the C library does around any
		// connect: it carries none of the run's data, so it is never "next to a secret", however close it comes.
		g.NearSecret = g.Class == "net" && !g.SystemLookup && !dnsGroup(g) && near(g.FirstSeq, g.First)
		classify(g, reached, probes, blocked)
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
		if g.to != "" {
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
