// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Net rule protocols. A host:port or cidr:port entry decides both TCP
// connects and UDP destinations, so it compiles to ProtoInet. tcp:// and
// udp:// select one transport; unix: entries compile to ProtoUnix.
const (
	ProtoInet = "inet"
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoUnix = "unix"
)

// net compiles net.allow: literal addresses, CIDRs and unix sockets are
// Static; host names resolve through a bounded pool (§9) and an unresolvable
// one is an error, or a warning when Offline (E18). The TTL is floored (E19).
func (k *compiler) net() {
	k.rt.NetAssurance = NetAssuranceBestEffort
	// Carried whatever the contract says, so a table's refusals of refreshed addresses (R18) read the
	// same machine ranges its compile did.
	k.rt.DeniedResolved = append([]netip.Prefix(nil), k.m.DeniedResolved.Value...)
	k.warnMCPRelay()
	if k.c.Net == nil {
		return
	}
	if k.c.Net.Assurance != "" {
		k.rt.NetAssurance = k.c.Net.Assurance
	}
	if k.rt.NetAssurance == NetAssuranceKernel {
		for _, t := range k.rt.Reach {
			if t == backend.TierLandlock || t == backend.TierObserve {
				k.ds.warnf(k.pos("net.assurance"), CodeUnenforced, "net.assurance: kernel refuses launch at tier %s: it lacks complete kernel destination admission", t).
					fix("use tier: cgroup or bpflsm with complete destination hooks, or net.assurance: best-effort").only(t)
			}
		}
	}
	k.rt.Net = k.netRules(k.c.Net.Allow, "net.allow", VerdictAllow)
	if len(k.c.Net.Ask) <= 256 {
		k.rt.NetAsk = k.netRules(k.c.Net.Ask, "net.ask", VerdictAsk)
	}
	// After the author's own entries, so where one of them also covers a server's endpoint it is the first
	// declared and names the connection (matchNet).
	k.rt.Net = append(k.rt.Net, k.mcpNetRules()...)
}

// mcpNetRules derives the net rule each HTTP MCP server's URL needs (R16a, FEATURES I5): a TCP connect to its host
// and port (both HTTP transports are TCP; HTTP/3 is not admitted), compiled and resolved as a net.allow entry is,
// named for the server. An endpoint net.allow already lists derives nothing, with a redundant-rule warning, as an
// mcp command listed in exec.allow does (R16). Nor does one a net.ask entry would decide a connect of (askingEntry),
// so connecting to it still asks: a derived allow would be matched first and the ask never reached. Only called
// under a net: section: without one every destination is admitted already (SEMANTICS §1).
func (k *compiler) mcpNetRules() []NetRule {
	var entries, keys, names []string
	for i, s := range k.c.MCP {
		// A relayed server's only route is Tego's relay (ADR 0126 §4): its URL derives no rule, so the agent cannot
		// reach the server around the relay.
		if s.URL == "" || len(s.Command) > 0 || s.Relayed() {
			continue
		}
		e, err := ParseMCPURL(s.URL)
		if err != nil {
			continue // validateMCPURLs reported it
		}
		key := "mcp." + strconv.Itoa(i) + ".url"
		if r := coveringEndpoint(k.rt.Net, e); r != nil {
			k.ds.warnf(k.pos(key), CodeRedundantRule, "net.allow %q already admits %s, the url of mcp %q, which derives that rule itself", r.Raw, e, s.Name).
				fix("remove %q from net.allow", r.Raw)
			continue
		}
		entries, keys, names = append(entries, ProtoTCP+"://"+e.String()), append(keys, key), append(names, s.Name)
	}
	rules := k.netRulesAt(entries, keys, VerdictAllow)
	out := rules[:0]
	j := 0
	for _, r := range rules {
		for entries[j] != r.Raw { // netRulesAt leaves out an entry it refused
			j++
		}
		r.MCP = names[j]
		if a := askingEntry(k.rt.NetAsk, r); a != nil {
			k.warnAsked(r, a)
			continue
		}
		// Only now, for a rule the run holds: R18's warning says what the rule's kept addresses admit, which is
		// false of one that is not derived, and warnAsked names that one's addresses itself.
		k.warnResolved(&r, keys[j])
		out = append(out, r)
	}
	return out
}

// warnMCPRelay says what a relayed server (mcp[].tools, ADR 0126 §4) needs that the contract does not give: an
// exec.allow list must admit the tego binary the agent's MCP client starts as the stdio shim, and a url server is
// kept to its relay only under a net: section (without one every destination is admitted, the server's included).
func (k *compiler) warnMCPRelay() {
	for i, s := range k.c.MCP {
		if !s.Relayed() {
			continue
		}
		key := "mcp." + strconv.Itoa(i) + ".tools"
		if len(s.Command) > 0 && k.c.Exec != nil && len(k.c.Exec.Allow) > 0 {
			k.ds.warnf(k.pos(key), CodeExecRule, "mcp %q is behind Tego's relay: its MCP client starts the server as `tego mcp relay`, which exec.allow must admit", s.Name).
				fix("add the tego binary (its absolute path) to exec.allow")
		}
		if s.URL != "" && k.c.Net == nil {
			k.ds.warnf(k.pos(key), CodeUnenforced, "mcp %q is behind Tego's relay, but with no net: section every destination is admitted, its url %s included, so the agent can reach it around the relay", s.Name, s.URL).
				fix("add a net: section (net: {allow: []} admits nothing beyond the run's own)")
		}
	}
}

// coveringEndpoint is the entry of rules that names e exactly: its host in CanonicalHost's spelling and its port, on
// TCP. A wider entry (a CIDR, another port) is not one: the server's own rule still names its connections.
func coveringEndpoint(rules []NetRule, e MCPEndpoint) *NetRule {
	for i := range rules {
		r := &rules[i]
		if (r.Proto == ProtoInet || r.Proto == ProtoTCP) && r.Port == e.Port && r.Host != "" && CanonicalHost(r.Host) == e.Host {
			return r
		}
	}
	return nil
}

// warnAsked says that the server r's url derives no rule because the net.ask entry a decides a connect to it
// (askingEntry), and names every address compile resolved the url to, kept or dropped under R18, that no ask entry
// asks for: with no rule derived, a connect to one is neither asked nor admitted by the server's url (R16a). A
// dropped one is named with its class, since listing the url's name in net.ask would not have it asked either.
// This is the only warning about the url's addresses: R18's is left out for a rule that is not derived.
func (k *compiler) warnAsked(r NetRule, a *NetRule) {
	resolved := slices.Concat(r.IPs, r.Denied)
	slices.SortFunc(resolved, netip.Addr.Compare)
	var unasked []string
	var keptUnasked bool
	var droppedUnasked netip.Addr
	for _, ip := range resolved {
		if slices.ContainsFunc(k.rt.NetAsk, func(e NetRule) bool { return asks(e, r, ip) }) {
			continue
		}
		if class, denied := k.rt.ResolvedDenied(r, ip); denied {
			unasked = append(unasked, ip.String()+" ("+class+", which a host name never admits)")
			if !droppedUnasked.IsValid() {
				droppedUnasked = ip
			}
			continue
		}
		unasked, keptUnasked = append(unasked, ip.String()), true
	}
	if len(unasked) == 0 {
		k.ds.warnf(r.Pos, CodeRedundantRule, "mcp %q url %s is decided by net.ask %q: connecting to it asks first, and no allow is derived for it", r.MCP, r.Raw, a.Raw).
			fix("keep it in net.ask to be asked, or narrow the net.ask entry to let the server's url admit it")
		return
	}
	var fixes []string
	if keptUnasked {
		fixes = append(fixes, "list "+r.Raw+" in net.ask to have every address of the server asked")
	}
	if droppedUnasked.IsValid() {
		fixes = append(fixes, "declare the address itself (for example "+net.JoinHostPort(droppedUnasked.String(), strconv.Itoa(r.Port))+") in net.ask to have it asked")
	}
	k.ds.warnf(r.Pos, CodeRedundantRule, "mcp %q url %s is decided by net.ask %q: no allow is derived for it, so a connect to an address an ask entry holds asks first, and one to an address it resolved to that no ask entry holds is refused unless another net.allow entry admits it: %s",
		r.MCP, r.Raw, a.Raw, strings.Join(unasked, ", ")).
		fix("%s, or narrow the net.ask entry to let the server's url admit it", strings.Join(fixes, ", or "))
}

// askingEntry is the first of asks that would decide a TCP connect r admits, or refuses by name: on r's port, and
// naming r's host (asksName: whatever its own lookup kept, it asks for what a later answer brings that name, which
// a derived r would admit first), or holding one of the addresses compile resolved r to (asks), kept or dropped
// under R18. A dropped
// one counts because the run refuses it by r's name (net.denied_resolved[...], supervisor R7) before any ask is
// reached, so a derived r would turn an asked connect into a refusal. The addresses compared are compile's: one a
// later answer brings to either name is not (R16a says so).
func askingEntry(as []NetRule, r NetRule) *NetRule {
	resolved := slices.Concat(r.IPs, r.Denied)
	for i := range as {
		a := &as[i]
		if asksName(*a, r) || slices.ContainsFunc(resolved, func(ip netip.Addr) bool { return asks(*a, r, ip) }) {
			return a
		}
	}
	return nil
}

// asksName reports whether the net.ask entry a names r's host on r's port, for TCP.
func asksName(a, r NetRule) bool {
	return a.Host != "" && asksPort(a, r) && CanonicalHost(a.Host) == CanonicalHost(r.Host)
}

func asksPort(a, r NetRule) bool {
	return (a.Proto == ProtoInet || a.Proto == ProtoTCP) && a.Port == r.Port
}

// asks reports whether the net.ask entry a asks for a TCP connect to ip on r's port: a holds ip in its CIDR or
// among the addresses it kept, whether or not it names r's host. The run's ask lookup is built from an entry's kept
// addresses (dns.NewSet), so an address R18 dropped from a's own name, or one a's own lookup of r's name did not
// answer, is never asked at compile's addresses.
func asks(a, r NetRule, ip netip.Addr) bool {
	return asksPort(a, r) && (a.CIDR != nil && a.CIDR.Contains(ip) || slices.Contains(a.IPs, ip))
}

func (k *compiler) netRules(entries []string, key string, verdict Verdict) []NetRule {
	keys := make([]string, len(entries))
	for i := range entries {
		keys[i] = key + "." + strconv.Itoa(i)
	}
	rules := k.netRulesAt(entries, keys, verdict)
	for i := range rules {
		k.warnResolved(&rules[i], key)
	}
	return rules
}

// listKey is the list a key's entry belongs to, as a diagnostic names it: net.allow for net.allow.3.
func listKey(key string) string {
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		if _, err := strconv.Atoi(key[i+1:]); err == nil {
			return key[:i]
		}
	}
	return key
}

// netRulesAt compiles entries, keys[i] naming where entry i was declared.
func (k *compiler) netRulesAt(entries, keys []string, verdict Verdict) []NetRule {
	rules := make([]NetRule, 0, len(entries))
	hosts := map[string][]int{}
	for i, raw := range entries {
		pos := k.pos(keys[i])
		e, err := ParseEndpoint(raw)
		if err != nil {
			k.ds.errorf(pos, CodeSchema, "%s %q: %v", listKey(keys[i]), raw, err)
			continue
		}
		r := NetRule{Raw: raw, Proto: e.Proto, Port: e.Port, Verdict: verdict, Pos: pos, Static: true}
		switch e.Kind {
		case EndpointUnix:
			r.Proto, r.UnixPath, r.Abstract = ProtoUnix, e.UnixPath, e.Abstract
			if !e.Abstract {
				r.UnixPath = k.abs(e.UnixPath)
				r.UnixResolved = resolveDeepest(r.UnixPath)
			}
		case EndpointCIDR:
			cidr := e.CIDR
			r.CIDR = &cidr
		default:
			r.Host = e.Host
			if e.IP.IsValid() {
				r.IPs = []netip.Addr{e.IP}
			} else {
				r.Static = false
				hosts[e.Host] = append(hosts[e.Host], len(rules))
			}
		}
		if r.Proto == ProtoInet && r.Port == 0 {
			// A port-0 entry is an ICMP destination (SEMANTICS §5), and with it the run's filter admits ping
			// sockets (ADR 0018). No kernel hook governs where a ping socket sends: the supervisor decides each
			// addressed send, as it does an unconnected UDP datagram, which is best effort (R14's row).
			k.ds.warnf(pos, CodeUnenforced, "net.allow %q is an ICMP destination: ping sockets are admitted, and where one sends is decided by the supervisor alone, best effort, with no kernel rule behind it", raw).
				fix("keep it only if the agent needs ping; name a port for anything else")
		}
		rules = append(rules, r)
	}
	k.resolveHosts(rules, hosts)
	return rules
}

type lookupResult struct {
	ips []netip.Addr
	err error
}

// resolveHosts looks every distinct host up at most dnsParallel at a time,
// each under its own timeout, and waits for all of them before returning:
// no goroutine outlives the call (§9).
func (k *compiler) resolveHosts(rules []NetRule, hosts map[string][]int) {
	if len(hosts) == 0 {
		return
	}
	names := make([]string, 0, len(hosts))
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)
	results := make([]lookupResult, len(names))
	sem := make(chan struct{}, k.o.dnsParallel)
	var wg sync.WaitGroup
schedule:
	for i, h := range names {
		if k.o.ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-k.o.ctx.Done():
			break schedule
		}
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(k.o.ctx, k.o.dnsTimeout)
			defer cancel()
			ips, err := k.o.resolver.LookupNetIP(ctx, "ip", host)
			results[i] = lookupResult{ips: ips, err: err}
		}(i, h)
	}
	wg.Wait()
	if k.o.ctx.Err() != nil {
		return // cancellation is returned by Compile, not reported as an unresolvable host
	}
	now := k.o.now()
	for i, h := range names {
		res := results[i]
		if res.err == nil && len(res.ips) == 0 {
			res.err = errNoAddresses
		}
		for _, ri := range hosts[h] {
			r := &rules[ri]
			r.ResolvedAt, r.TTL = now, k.o.ttl
			if res.err != nil {
				if k.o.offline {
					k.ds.warnf(r.Pos, CodeHostUnresolvable, "host %s not resolved (offline): %v; the launcher resolves it at run start", h, res.err)
				} else {
					k.ds.errorf(r.Pos, CodeHostUnresolvable, "host %s cannot be resolved: %v", h, res.err).
						fix("check the name, or run tego compile --offline to defer resolution to run start")
				}
				continue
			}
			r.IPs = unmapped(res.ips)
			k.dropResolved(r)
		}
	}
}

// dropResolved drops from a host entry's resolved addresses every one it may not admit by name (R18,
// ResolvedDenied). The dropped addresses stay on the rule (Denied) for the supervisor to name a refusal by; an
// entry left with none admits nothing until a refresh brings an address it may admit. An entry whose kept answer
// is public only (publicAddr) is marked PublicAnswer, which refuses a private address a later answer brings in;
// nothing at compile is dropped for it. The caller warns (warnResolved) once it knows the rule is one the run holds.
func (k *compiler) dropResolved(r *NetRule) {
	if !r.FiltersResolved() {
		return
	}
	kept := r.IPs[:0:0]
	for _, a := range r.IPs {
		if _, denied := k.rt.ResolvedDenied(*r, a); denied {
			r.Denied = append(r.Denied, a)
			continue
		}
		kept = append(kept, a)
	}
	r.PublicAnswer = len(kept) > 0 && !slices.ContainsFunc(kept, func(a netip.Addr) bool { return !publicAddr(a) })
	if len(r.Denied) > 0 {
		r.IPs = kept
	}
}

// warnResolved warns about the addresses dropResolved dropped from r, naming each with its class and list, the one
// the entry came from (net.allow, net.ask, an mcp url), so the author sees what the name resolved to and how to
// admit it on purpose. Its last clause says what r's kept addresses admit, so it is only for a rule the run holds:
// an mcp url that derives no rule (askingEntry) names its addresses in warnAsked instead.
func (k *compiler) warnResolved(r *NetRule, list string) {
	if len(r.Denied) == 0 {
		return
	}
	dropped := make([]string, 0, len(r.Denied))
	for _, a := range r.Denied {
		class, _ := k.rt.ResolvedDenied(*r, a)
		dropped = append(dropped, a.String()+" ("+class+")")
	}
	what := "the others still admit"
	if len(r.IPs) == 0 {
		what = "the entry admits nothing until the name resolves elsewhere"
	}
	k.ds.warnf(r.Pos, CodeResolvedDenied, "%s %s: host %s resolved to %s, which a host name never admits; dropped, %s",
		list, r.Raw, r.Host, strings.Join(dropped, ", "), what).
		fix("declare the address itself (for example %s) to allow it on purpose", net.JoinHostPort(r.Denied[0].String(), strconv.Itoa(r.Port)))
}

var errNoAddresses = noAddressesError{}

type noAddressesError struct{}

func (noAddressesError) Error() string { return "no addresses" }

// unmapped copies addresses with IPv4-in-IPv6 unwrapped and duplicates removed, sorted.
func unmapped(in []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]bool, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}
