// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// evalNet matches a connect against the compiled net entries. P0's verdicts do
// not depend on the tier (R15): the root tiers decide host:port in the kernel
// and the unprivileged tier's supervisor matches the same host:port on a
// duplicate of the socket before connecting it (SEMANTICS §5), so the answer
// is the same and only the place the decision runs differs. Observe mode
// enforces nothing. datagram says the action is an unconnected send decided as
// this connect (evalSend): a unix name's walk is answered as the run answers a
// datagram's (unixLanded), and its spelling as the kernel's programs read it
// (kernelDatagram).
//
// A contract with no net: section restricts nothing (SEMANTICS §1, "no net:
// — deny nothing"), so a destination no entry names is allowed and counted
// as unmatched, in every tier (NetUnrestricted). The other components read
// the same bit: the Landlock builder leaves the net rights unhandled
// (netRestricted), tier 2 attaches no network program, and the supervisor
// leaves such a connect to the kernel. The one exception is a models[]
// endpoint under capture: forwarder, which is refused (GuardedModels,
// evalGuard) and which the supervisor refuses too.
func evalNet(rt *agent.RuleTable, a agent.Action, tier backend.Tier, datagram bool) agent.EvalResult {
	proto := strings.ToLower(a.Proto)
	host := a.Host
	if host == "" && a.Path != "" { // a unix: entry names a path, not a host
		host, proto = a.Path, "unix"
	}
	if host == "" {
		return invalidAction()
	}
	if proto == "" {
		proto = "tcp"
	}
	if proto != agent.ProtoUnix {
		if a.Port < 0 || a.Port > 0xffff {
			return invalidAction()
		}
		// One spelling of the host for every arm, the one ParseEndpoint gives an entry's Host and evalGuard
		// compares: `example.com.` is the name `example.com` (the run decides on the addresses both resolve
		// to), an IP literal in netip's form. matchNet alone compared the row's text, so a trailing-dot row
		// was refused where the run admits the connect.
		host = agent.CanonicalHost(host)
	}
	i, ok := matchNet(rt, host, a.Port, proto)
	if tier == backend.TierObserve {
		if ok {
			return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rt.Net[i].RuleName()}
		}
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
	}
	explicit := ok && rt.Net[i].Verdict == agent.VerdictAllow
	if !explicit || rt.Net[i].Runtime != agent.CaptureGrant {
		if res, guarded := evalGuard(rt, host, a.Port, proto, explicit); guarded {
			return res
		}
	}
	if !ok {
		if rt.NetUnrestricted() {
			if proto == agent.ProtoUnix && rt.HostSocketsRefused() {
				return hostSocketVerdict(rt, a, host, datagram)
			}
			return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
		}
		if proto == agent.ProtoUnix {
			// A connect that reaches a net.ask unix: scope's place is held for a person at run time (supervisor
			// R11c), also inside a write entry, so it is refused under the scope's own rule, as an ask compiles in P0
			// (agent-contract R15), before the write entry around it could certify it: by the scope's declared
			// spelling or the place it resolved to at compile (agent.ResolveUnixPlace, the run's own resolution), and so
			// is a connect whose walk lands there (a.Landed), as the run places the name to ask about it (unixScopeOf).
			for j := range rt.NetAsk {
				if r := &rt.NetAsk[j]; r.Proto == agent.ProtoUnix && (unixMatch(r, host) || unixResolvedMatch(r, host) ||
					!datagram && a.Landed != "" && unixAskPlace(r) == a.Landed) {
					return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: record.ReasonNetNotAllowed}
				}
			}
			if w, ok := unixUnderWrite(rt, host); ok {
				return kernelDatagram(unixLanded(rt, a, w, datagram), a, tier, datagram)
			}
		}
		if unresolvedCandidate(rt, host, a.Port, proto) || emptiedCandidate(rt, host, a.Port, proto) {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnresolvedRule, Reason: record.ReasonNetNotAllowed}
		}
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonNetNotAllowed}
	}
	r := rt.Net[i]
	if r.Verdict != agent.VerdictAllow {
		// ask compiles as refused in P0 (SEMANTICS §3.1, R2).
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: record.ReasonNetNotAllowed}
	}
	if proto == agent.ProtoUnix {
		return kernelDatagram(unixLanded(rt, a, r.RuleName(), datagram), a, tier, datagram)
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: r.RuleName()}
}

// kernelDatagram is res as the run's own kernel programs leave it at tier: where they decide unix names (cgroup's
// sendmsg_unix, the plane's socket_sendmsg), a datagram whose absolute name is not spelled canonically
// (agent.Action.Uncanonical) is refused there, and the supervisor, which admitted the name cleaned, answers that
// refusal itself, rule unmatched, since no row is looked up for such a spelling (supervisor.md R13b, kernelRefusal). A
// refusal of what the name reaches stays the supervisor's own. Tier cgroup below 6.7 outside a plane mode loads no unix
// program and admits it as tier landlock does, which this column, asked of no kernel, does not answer.
func kernelDatagram(res agent.EvalResult, a agent.Action, tier backend.Tier, datagram bool) agent.EvalResult {
	if !datagram || !a.Uncanonical || res.Verdict != agent.VerdictAllow ||
		(tier != backend.TierCgroup && tier != backend.TierBPFLSM) {
		return res
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonNetNotAllowed}
}

// unixLanded is the verdict of a unix pathname whose name the rule named admitted: the run then decides on what its
// own walk of the name meets in the agent's view (supervisor R11, R11a; SEMANTICS §5 as amended 2026-10-16), in the
// relay for a connect and in decideLanded for a datagram, and so does this, on a.Walk and a.Landed:
//   - a name the walk met nothing at (agent.UnixWalkAbsent: ENOENT, ENOTDIR), or failed at otherwise as the agent's
//     own lookup fails (agent.UnixWalkFailed: EACCES): a connect fails in the agent's lookup and its line keeps the
//     name's verdict, named (finishUnix's unixUnresolved); a datagram is refused, unix-absent and path-unreliable
//     respectively (unixLandedRefusal);
//   - a walk the run cannot place in its own view (agent.UnixWalkUnreliable: a magic link, a symlink loop, procfs):
//     refused path-unreliable, connect and datagram alike;
//   - a socket only the walk a component at a time reached (agent.UnixWalkStepwise): a connect is refused
//     path-unreliable (errWalkedOnly), a datagram decided on that socket;
//   - what the walk reached (a.Landed), matched as the supervisor's decideResolved matches it: a unix: entry whose
//     resolved path is it (agent.NetRule.UnixResolved), else a net.ask unix: scope whose place it is, refused
//     unix-ask-scope as the run refuses what reaches a scope's place unasked (R11c), else the nearest filesystem entry
//     at or above it by its resolved path alone when that is a write entry (the implicit admit), else refused
//     unmatched, whatever the name looked
//     like. The implicit admit holds only for a socket a process of the run bound (boundByRun): what compile lands is
//     the tree the agent calls in (agent.UnixLanding), in which a socket is the run's (see unixUnderWrite) and a
//     directory or a file that is no socket (a.NoSocket) is refused unix-foreign, as the run refuses it (design). An
//     admitted socket is named by the entry that admitted it, as the run's line is.
//
// Every refusal here has reason net-not-allowed, as the run's net lines do. A name not landed (a table run with no
// UnixLander, a walk compile could not make) is decided on its spelling alone, named.
func unixLanded(rt *agent.RuleTable, a agent.Action, named string, datagram bool) agent.EvalResult {
	refused := func(rule string) agent.EvalResult {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonNetNotAllowed}
	}
	switch a.Walk {
	case agent.UnixWalkAbsent, agent.UnixWalkFailed:
		switch {
		case !datagram:
			return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: named}
		case a.Walk == agent.UnixWalkAbsent:
			return refused(agent.UnixAbsentRule)
		}
		return refused(agent.PathUnreliableRule)
	case agent.UnixWalkUnreliable:
		return refused(agent.PathUnreliableRule)
	case agent.UnixWalkStepwise:
		if !datagram {
			return refused(agent.PathUnreliableRule)
		}
	case agent.UnixWalkLookup:
	}
	at := a.Landed
	if at == "" {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: named}
	}
	for i := range rt.Net {
		r := &rt.Net[i]
		if r.Proto != agent.ProtoUnix || r.Abstract || r.UnixPath == "" {
			continue
		}
		resolved := r.UnixResolved
		if resolved == "" {
			resolved = cleanPath(r.UnixPath)
		}
		if resolved == at {
			return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: r.RuleName()}
		}
	}
	for i := range rt.NetAsk {
		if r := &rt.NetAsk[i]; r.Proto == agent.ProtoUnix && unixAskPlace(r) == at {
			return refused(agent.UnixAskScopeRule)
		}
	}
	switch w, ok := nearestUnixWrite(rt, at, false); {
	case !ok:
		return refused(agent.UnmatchedRule)
	case a.NoSocket:
		return refused(agent.UnixForeignRule)
	default:
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: w}
	}
}

// hostSocketVerdict is a unix destination no entry names in the unix-only state (ADR 0070, agent.RuleTable.
// HostSocketsRefused): a contract with no net: section that did not set host_sockets: true admits a unix socket only
// when a process of the run bound it, which the run holds its implicit admit to wherever the socket lies (supervisor
// R7b, R11a). A static evaluation knows no binds, so it answers the run's own case where the run can make one: a
// pathname under a write entry, where a process of the run can bind (Landlock grants MAKE_SOCK only there), decided as
// the run decides what its walk reaches (unixLanded), its unmatched and unix-foreign refusals named host-sockets. Every
// other name, an abstract one and a pathname outside every write entry (the daemon sockets of R19 among them), is
// refused host-sockets: no process of the run could have bound it, or, for an abstract name, compile cannot say one
// did. The root tiers' kernel programs decide no unix name for such a contract (ADR 0070 (5)), so nothing here
// is the kernel's (kernelDatagram is not asked).
func hostSocketVerdict(rt *agent.RuleTable, a agent.Action, host string, datagram bool) agent.EvalResult {
	refused := agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.HostSocketsRule, Reason: record.ReasonNetNotAllowed}
	w, ok := unixUnderWrite(rt, host)
	if !ok {
		return refused
	}
	res := unixLanded(rt, a, w, datagram)
	if res.Verdict == agent.VerdictRefused && (res.Rule == agent.UnmatchedRule || res.Rule == agent.UnixForeignRule) {
		return refused
	}
	return res
}

// matchNet finds the entry that decides host:port on proto. A host entry
// matches by name or by any address it resolved to, a cidr entry an address
// inside the prefix, a unix entry the socket path or the abstract name byte
// for byte (SEMANTICS §5). Among the entries covering the destination a
// refusing one decides, whatever the declaration order, and otherwise the
// first declared: the rule tier 2's rows are composed by (enforce/cgroup
// BuildRuleMaps), so the kernel's exact-before-longest-prefix lookup gives
// the same verdict and the same entry.
func matchNet(rt *agent.RuleTable, host string, port int, proto string) (int, bool) {
	addr, addrErr := netip.ParseAddr(host)
	isAddr := addrErr == nil
	first, refusing := -1, -1
	for i := range rt.Net {
		if !netCovers(&rt.Net[i], host, addr, isAddr, port, proto) {
			continue
		}
		if first < 0 {
			first = i
		}
		if rt.Net[i].Verdict != agent.VerdictAllow {
			refusing = i
			break
		}
	}
	if refusing >= 0 {
		return refusing, true
	}
	return first, first >= 0
}

// netCovers reports whether one entry covers host:port on proto (matchNet).
func netCovers(r *agent.NetRule, host string, addr netip.Addr, isAddr bool, port int, proto string) bool {
	if r.Proto == "unix" || proto == "unix" {
		return r.Proto == "unix" && proto == "unix" && unixMatch(r, host)
	}
	if !protoMatches(r.Proto, proto) || !netPortAdmits(r.Port, port, proto) {
		return false
	}
	switch {
	case r.CIDR != nil:
		return isAddr && r.CIDR.Contains(addr.Unmap())
	case r.Host != "" && strings.EqualFold(r.Host, host):
		// An entry whose every resolved address R18 dropped admits nothing (agent-contract R18): the run
		// connects to the addresses, and the supervisor refuses each. Matching it by name would certify a
		// connect the run refuses.
		return !emptiedByR18(r)
	case isAddr:
		for _, ip := range r.IPs {
			if ip.Unmap() == addr.Unmap() {
				return true
			}
		}
	}
	return false
}

// emptiedByR18 reports whether a host entry was left with no address because every one it resolved to is
// in a class R18 refuses.
func emptiedByR18(r *agent.NetRule) bool {
	return r.FiltersResolved() && len(r.IPs) == 0 && len(r.Denied) > 0
}

// emptiedCandidate reports whether a host entry R18 emptied names host (a name, not an address) on port
// and proto: the name row is refused as `unresolved`, E18's reading of an entry with no addresses.
func emptiedCandidate(rt *agent.RuleTable, host string, port int, proto string) bool {
	for i := range rt.Net {
		r := &rt.Net[i]
		if emptiedByR18(r) && netPortAdmits(r.Port, port, proto) && protoMatches(r.Proto, proto) && strings.EqualFold(r.Host, host) {
			return true
		}
	}
	return false
}

// protoMatches compares an entry's protocol with the one a connect uses: a
// host or cidr entry compiles to ProtoInet, which covers both TCP connects
// and UDP destinations (SEMANTICS §5, compile_net.go).
func protoMatches(rule, action string) bool {
	return agent.ProtocolMatches(rule, action)
}

// netPortAdmits applies the runtime's port rule to the evaluator's int field.
// Validate before narrowing so an invalid public query cannot wrap into a grant.
func netPortAdmits(declared, observed int, proto string) bool {
	return observed >= 0 && observed <= 0xffff && PortAdmits(declared, uint16(observed), proto)
}

// unixMatch compares a unix entry with the socket a connect names: an abstract
// name by bytes after the target's one leading "@", a pathname entry by its cleaned path
// (SEMANTICS §5). The entry's UnixPath already has its "@" removed (ParseEndpoint), so
// `unix:@@foo` names the abstract name "@foo" and is compared as it is, the bytes the
// cgroup key and the supervisor compare; trimming an "@" from it too matched "foo".
func unixMatch(r *agent.NetRule, target string) bool {
	target = strings.TrimPrefix(target, "unix:")
	if r.Abstract {
		name, ok := strings.CutPrefix(target, "@")
		return ok && name == r.UnixPath
	}
	return cleanPath(r.UnixPath) == cleanPath(target)
}

// unixAskPlace is a pathname net.ask unix: scope's place, where the run asks a connect about it (supervisor R11c,
// unixAskAt): the place it resolved to at compile (NetRule.UnixResolved), else its declared path cleaned; "" for an
// abstract name, which no walk lands at.
func unixAskPlace(r *agent.NetRule) string {
	switch {
	case r.Abstract || r.UnixPath == "":
		return ""
	case r.UnixResolved != "":
		return cleanPath(r.UnixResolved)
	}
	return cleanPath(r.UnixPath)
}

// unixResolvedMatch reports whether a pathname unix entry's resolved spelling (agent.NetRule.UnixResolved) is target.
func unixResolvedMatch(r *agent.NetRule, target string) bool {
	return !r.Abstract && r.UnixResolved != "" && cleanPath(r.UnixResolved) == cleanPath(strings.TrimPrefix(target, "unix:"))
}

// unixUnderWrite reports whether a pathname unix socket no unix: entry names lies under a declared fs.write
// entry, and names that entry: such a socket is allowed implicitly when a process of the run bound it (SEMANTICS
// §5, supervisor R11a), which a static evaluation cannot know, so this answers the run's own case, as tier 2's unix
// program allows it; the run refuses a socket there it did not bind (unix-foreign). The nearest write or deny_read entry
// decides, by its resolved or declared spelling, as decideUnix matches (NewAdvisoryTables' Both); a watch
// entry grants nothing. An abstract name or a relative path lies under no entry.
//
// It scans rt.FS once, allocating nothing, rather than asking NearestIn: building NewAdvisoryTables for one
// lookup sorted and indexed every entry (tens of thousands with the .env scan) on every unix row evaluated.
// The scan picks what NearestIn(Both) picks: the longest enclosing spelling, and among equal ones the first in
// Both's order, which is table order with an entry's resolved spelling before its declared one.
func unixUnderWrite(rt *agent.RuleTable, target string) (string, bool) {
	p := strings.TrimPrefix(target, "unix:")
	if strings.HasPrefix(p, "@") || !strings.HasPrefix(p, "/") {
		return "", false
	}
	return nearestUnixWrite(rt, cleanPath(p), true)
}

// nearestUnixWrite names the filesystem entry nearest the clean absolute path p when that entry is a write entry,
// matching each entry by its resolved spelling and, with declared set, by its declared one too: what NearestIn picks
// over NewAdvisoryTables' Both (declared) or Resolved, the tables the supervisor's name decision (decideUnix) and its
// landed one (decideResolved) ask.
func nearestUnixWrite(rt *agent.RuleTable, p string, declared bool) (string, bool) {
	var near *agent.FSRule
	nearLen := -1
	for i := range rt.FS {
		r := &rt.FS[i]
		if r.Path == "" || r.Kind == agent.FSWatch {
			continue // no rights of its own, as NewAdvisoryTables leaves it out
		}
		resolved := r.Resolved
		if resolved == "" {
			resolved = r.Path
		}
		spellings := [2]string{resolved, r.Path}
		n := 1
		if declared {
			n = 2
		}
		for _, s := range spellings[:n] {
			if k := TrimDir(s); len(k) > nearLen && advisoryEncloses(k, p) {
				near, nearLen = r, len(k)
			}
		}
	}
	if near != nil && near.Kind == agent.FSWrite {
		return near.RuleName(), true
	}
	return "", false
}

// advisoryEncloses reports whether the advisory key k (TrimDir'd) encloses the clean absolute path p, as
// NearestWhere's walk asks: p itself, p continuing k with a "/", or the root.
func advisoryEncloses(k, p string) bool {
	return k == p || k == "/" || (len(p) > len(k) && p[len(k)] == '/' && strings.HasPrefix(p, k))
}

// unresolvedCandidate reports whether a literal address could only have been
// decided by a host entry carrying no addresses — the offline compile of
// E18/E19. `compile --test` renders that as "could not resolve", distinct
// from a verdict mismatch (§6 E19).
func unresolvedCandidate(rt *agent.RuleTable, host string, port int, proto string) bool {
	return len(UnresolvedHosts(rt, host, port, proto)) > 0
}

// UnresolvedHosts returns the declared hosts of the host entries that carry no addresses and could have
// admitted a connect to the literal address host on port and proto: the names `compile --test` reports as
// the ones that failed to resolve (§6 E19). Nil when host is not a literal address.
func UnresolvedHosts(rt *agent.RuleTable, host string, port int, proto string) []string {
	if _, err := netip.ParseAddr(host); err != nil {
		return nil
	}
	var out []string
	for i := range rt.Net {
		r := &rt.Net[i]
		if r.Static || r.Host == "" || len(r.IPs) > 0 || !netPortAdmits(r.Port, port, proto) {
			continue
		}
		if protoMatches(r.Proto, proto) {
			out = append(out, r.Host)
		}
	}
	return out
}

// evalGuard refuses known model identities even when net.allow names them. An unallowed destination on a
// remote named model's port is refused independently of DNS. Explicit allowances may admit an unknown
// address, but the runtime still refuses one its model lookup or fresh local-address enumeration identifies
// as the model. This pure evaluator cannot discover DNS aliases or the host's assigned interfaces; an
// unallowed literal on a local/literal model's port remains conservatively unresolved.
//
// The port reservation (models.port) applies only under a net: section (SEMANTICS §1, amended 2026-10-05).
// A contract with no net: section denies nothing but the model itself, so there another name on the model's
// port is allowed and a literal is refused unresolved, the answer E18/E19 give a literal only an unresolved
// entry could match: from 2026-10-01 it refused every HTTPS host of such a contract.
func evalGuard(rt *agent.RuleTable, host string, port int, proto string, explicit bool) (agent.EvalResult, bool) {
	if proto == agent.ProtoUnix {
		// A unix path names no models[] endpoint. Every other protocol is guarded, raw and icmp included,
		// because the run guards every IP socket (the supervisor's decideGuarded): answering allow here for a
		// raw datagram to the endpoint would be the allow for an address the run refuses that this function
		// must never give.
		return agent.EvalResult{}, false
	}
	guarded := rt.GuardedModels()
	if len(guarded) == 0 {
		return agent.EvalResult{}, false
	}
	h := agent.CanonicalHost(host)
	addr, literal := guardAddr(h)
	unresolved := false
	var guardedPort *agent.ModelEndpoint
	for _, m := range guarded {
		if m.Port != port {
			continue
		}
		if h == m.Host {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.ModelRule(m), Reason: record.ReasonNetNotAllowed}, true
		}
		mAddr, mLiteral := guardAddr(m.Host)
		switch {
		case literal && mLiteral && agent.GuardAddrMatches(addr, mAddr):
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.ModelRule(m), Reason: record.ReasonNetNotAllowed}, true
		case !mLiteral && !explicit && !rt.NetUnrestricted():
			if guardedPort == nil {
				guardedPort = &m
			}
		case literal && !explicit:
			// This pure function cannot classify the host's assigned interface addresses.
			unresolved = true
		}
	}
	if guardedPort != nil {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.ModelPortRule(*guardedPort), Reason: record.ReasonNetNotAllowed}, true
	}
	if unresolved {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnresolvedRule, Reason: record.ReasonNetNotAllowed}, true
	}
	return agent.EvalResult{}, false
}

// guardAddr is the address a models[] host or a destination names without a lookup: a literal as written,
// and a localhost name as the loopback address (LocalhostName). ok is false for any other name.
func guardAddr(h string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(h); err == nil {
		return a, true
	}
	if agent.LocalhostName(h) {
		return netip.IPv6Loopback(), true
	}
	return netip.Addr{}, false
}
