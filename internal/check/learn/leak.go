// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/secretpath"
	"github.com/attention-span-ai/tego/internal/check/syslookup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The leak rule is the dashboard's "secret read, then send" verdict (internal/control/ledgerview: Signal and
// RunVerdict) read from the same lines, below the control layer, so `tego learn` never proposes where a run's secrets
// went (QA PW-1). The two share the closeness rule (secretpath.NearSeconds, NearLines) and the classifiers
// (secretpath, syslookup); TestLeakRuleAgreesWithTheVerdict, in internal/control/rulesview, holds them equal.
//
// A destination counts only when a particular successful send and a particular
// successful secret read lie within both proximity bounds. Refused sends and
// refused reads cannot supply either half. Repeated contacts are checked at their
// own sequence and timestamp. The page also knows contract sensitive entries and
// may borrow a reliably paired run's contract, which the standalone learner does not.
//
// Port 53 off this machine is judged here as on the page: only the engine's rule makes it a resolver, any server can
// listen there, and tego allows the machine's resolvers on its own (SEMANTICS §2), so leaving a real one out of
// net.allow costs nothing. The warning is its own (Leak.Resolver).
//
// What the rule cannot see: a secret renamed or linked to a name that says nothing and read there.
//
// The fold keeps only the contacts the last NearLines lines can still match.
// Distinct secrets, destinations and associations are each capped by maxDistinct;
// one confirmed witness per destination preserves warnings after association truncation.
// Repeated reads and sends never retain a record per historical contact.

// nearWindow is secretpath.NearSeconds as a duration.
const nearWindow = secretpath.NearSeconds * time.Second

// Leak is one destination the leak rule says a run's secrets may have gone to.
type Leak struct {
	// Dest is the destination as the record names it: "address:port", "name:port" when the line names a host, or a
	// unix socket.
	Dest string
	// Entries are the net.allow entries the proposal left out for it.
	Entries []string
	// ByName is true when the record holds the destination only by host name: no address to compare with an entry.
	ByName bool
	// Local is true for a unix socket. It is reported and never withheld, as the dashboard withholds addresses only:
	// a socket is a place on this machine, whose listener may be the agent's own (Codex's control socket sits next to
	// its auth.json at every start).
	Local bool
	// Resolver is true for an address on port 53 off this machine that the engine did not name a resolver: it may still
	// be the machine's, which needs no entry.
	Resolver bool
}

// leakLine is where a line sits in the record.
type leakLine struct {
	seq uint64
	ts  time.Time
}

// near is the closeness rule: within NearLines lines and nearWindow of each other.
func (a leakLine) near(b leakLine) bool {
	if a.seq+secretpath.NearLines < b.seq || b.seq+secretpath.NearLines < a.seq {
		return false
	}
	d := a.ts.Sub(b.ts)
	return d <= nearWindow && d >= -nearWindow
}

// seenSecret is one secret path the run touched.
type seenSecret struct {
	path  string
	first leakLine
	near  map[*seenDest]bool // destinations with a particular successful read/send pair
}

// seenTouch is one touch of a secret in the last NearLines lines.
type seenTouch struct {
	leakLine
	secret *seenSecret // nil for a path past maxDistinct
	read   bool        // it went through and can have read the file (leakAddFS)
}

// seenDest is one destination the run sent to or tried to.
type seenDest struct {
	key       string
	first     leakLine
	got       bool        // a line for it was allowed or observed
	contract  bool        // a line for it carried a net[...] entry, or the resolver's rule
	nearTouch bool        // a successful contact lies next to a successful secret read
	witness   *seenSecret // one confirmed read, retained even when the association list fills
}

// sendAddr ties a destination's key to one address it was reached at.
type sendAddr struct {
	key  string
	addr netKey
}

type seenSend struct {
	leakLine
	dest *seenDest
}

// leakRule folds a run's lines for the rule above.
type leakRule struct {
	secrets     map[string]*seenSecret
	dests       map[string]*seenDest
	sends       map[sendAddr]bool
	touches     []seenTouch // every touch in the last NearLines lines
	recentSends []seenSend  // successful contacts in the last NearLines lines
	links       int         // bounded associations, plus at most one witness per destination
	truncated   bool
}

func newLeakRule() *leakRule {
	return &leakRule{secrets: map[string]*seenSecret{}, dests: map[string]*seenDest{}, sends: map[sendAddr]bool{}}
}

// prune forgets what a line at seq can no longer be near. Lines arrive in order, so each list is oldest first.
func (r *leakRule) prune(seq uint64) {
	r.touches = dropBefore(r.touches, seq, func(t seenTouch) uint64 { return t.seq })
	r.recentSends = dropBefore(r.recentSends, seq, func(d seenSend) uint64 { return d.seq })
}

func dropBefore[T any](s []T, seq uint64, at func(T) uint64) []T {
	i := 0
	for i < len(s) && at(s[i])+secretpath.NearLines < seq {
		i++
	}
	return s[i:]
}

// touch takes one touch of path p, when it is a secret to the run: its name says so, or the line's rule guards it. read
// says the touch went through and can have read the file.
func (r *leakRule) touch(e *record.Event, p, rule string, read bool) {
	if p == "" || !(secretpath.GuardRule(rule) || secretpath.Is(p)) {
		return
	}
	at := leakLine{e.Seq, e.TS}
	r.prune(e.Seq)
	s := r.secrets[p]
	if s == nil && len(r.secrets) >= maxDistinct {
		r.truncated = true
	} else if s == nil {
		s = &seenSecret{path: p, first: at, near: map[*seenDest]bool{}}
		r.secrets[p] = s
	}
	t := seenTouch{leakLine: at, secret: s, read: read}
	for _, send := range r.recentSends {
		if at.near(send.leakLine) {
			t.nextTo(r, send.dest)
		}
	}
	r.touches = append(r.touches, t)
}

// nextTo keeps an association only after both particular operations succeeded.
// Its global budget prevents repeated contacts from growing a quadratic map.
func (t seenTouch) nextTo(r *leakRule, d *seenDest) {
	if !t.read {
		return
	}
	d.nearTouch = true
	if d.witness == nil {
		d.witness = t.secret
	}
	if t.secret != nil && !t.secret.near[d] {
		if r.links >= maxDistinct {
			r.truncated = true
			return
		}
		t.secret.near[d] = true
		r.links++
	}
}

// send takes one outbound line to dst, named host when the line names one: a connect that got through or was held
// (got tells them apart) or a refused one, whose proto is empty.
func (r *leakRule) send(e *record.Event, proto, dst, host, rule string, got bool) {
	if dst == "" || dst == "unspec" || dst == "netlink" || dst == "family(16)" {
		return
	}
	key := leakKey(dst, host)
	at := leakLine{e.Seq, e.TS}
	r.prune(e.Seq)
	d := r.dests[key]
	if d == nil {
		if len(r.dests) >= maxDistinct {
			r.truncated = true
			return
		}
		d = &seenDest{key: key, first: at}
		r.dests[key] = d
	}
	if got {
		r.recentSends = append(r.recentSends, seenSend{at, d})
		for _, t := range r.touches {
			if at.near(t.leakLine) {
				t.nextTo(r, d)
			}
		}
	}
	d.got = d.got || got
	d.contract = d.contract || strings.HasPrefix(rule, "net[") || rule == "net.resolver"
	if proto == "" {
		return
	}
	k := sendAddr{key, netKey{proto, dst}}
	if !r.sends[k] {
		if len(r.sends) >= maxDistinct {
			r.truncated = true
			return
		}
		r.sends[k] = true
	}
}

// leakKey is a destination's key as the dashboard keys it: "name:port" when the line names a host that is not the
// address itself, else dst as written.
func leakKey(dst, name string) string {
	if strings.HasPrefix(dst, "unix:") || name == "" {
		return dst
	}
	i := strings.LastIndexByte(dst, ':')
	if i <= 0 {
		return dst
	}
	host, port := dst[:i], dst[i+1:]
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return dst // a bare IPv6 address with no port
	}
	if name == host {
		return dst
	}
	return name + ":" + port
}

// routine is whether a destination is no send at all: a system lookup socket, or port 53 on this machine, which
// classify leaves out of net.allow as the resolver (SEMANTICS §2). Port 53 elsewhere is judged like any other place.
// A resolver the run has needs no rule here: its lines carry the engine's rule, which marks it as on the contract.
func routine(key string) bool { return syslookup.Routine(key, "") }

// onPort53 is whether dst is an address on port 53. A name has no address to withhold, so its warning is ByName's.
func onPort53(dst string) bool {
	ap, err := netip.ParseAddrPort(dst)
	return err == nil && ap.Port() == 53
}

// judge is the rule's answer once the record is read: the leaks in the order the run reached them and the secrets
// that went with them, in the order the run first touched them.
func (r *leakRule) judge() ([]*Leak, []string) {
	off := func(d *seenDest) bool { return !d.contract && !routine(d.key) }
	var secrets []*seenSecret
	seen := map[*seenSecret]bool{}
	for _, s := range r.secrets {
		for d := range s.near {
			if off(d) {
				secrets = append(secrets, s)
				seen[s] = true
				break
			}
		}
	}
	var dests []*seenDest
	for _, d := range r.dests {
		if d.got && d.nearTouch && off(d) {
			dests = append(dests, d)
			if d.witness != nil && !seen[d.witness] {
				seen[d.witness] = true
				secrets = append(secrets, d.witness)
			}
		}
	}
	if len(dests) == 0 {
		return nil, nil
	}
	slices.SortFunc(secrets, func(a, b *seenSecret) int { return compareLine(a.first, b.first, a.path, b.path) })
	slices.SortFunc(dests, func(a, b *seenDest) int { return compareLine(a.first, b.first, a.key, b.key) })
	leaks := make([]*Leak, 0, len(dests))
	for _, d := range dests {
		leaks = append(leaks, &Leak{Dest: d.key})
	}
	names := make([]string, 0, len(secrets))
	for _, s := range secrets {
		names = append(names, s.path)
	}
	return leaks, names
}

func compareLine(a, b leakLine, an, bn string) int {
	switch {
	case a.seq < b.seq:
		return -1
	case a.seq > b.seq:
		return 1
	}
	return strings.Compare(an, bn)
}

// held maps each address a leak was reached at to its leak, and marks a leak the record holds only by host name.
func (r *leakRule) held(leaks []*Leak) map[netKey]*Leak {
	byKey := make(map[string]*Leak, len(leaks))
	for _, lk := range leaks {
		byKey[lk.Dest] = lk
		lk.ByName = !hasAddress(lk.Dest)
		lk.Local = strings.HasPrefix(lk.Dest, "unix:")
		lk.Resolver = onPort53(lk.Dest)
	}
	out := map[netKey]*Leak{}
	for s := range r.sends {
		lk := byKey[s.key]
		if lk == nil {
			continue
		}
		out[s.addr] = lk
		if addressed(s.addr) {
			lk.ByName = false
		}
	}
	return out
}

// addressed is whether a line's destination is one a net.allow entry can name exactly.
func addressed(k netKey) bool { return k.proto == "unix" || k.proto == "raw" || hasAddress(k.dst) }

func hasAddress(dst string) bool {
	if strings.HasPrefix(dst, "unix:") || strings.HasPrefix(dst, "family(") {
		return true
	}
	_, err := netip.ParseAddrPort(dst)
	return err == nil
}

// leakAddNet feeds a net line to the rule: every outbound line, also the forwarder's http_request ones, which the
// dashboard reads as sends too.
func (l *Learner) leakAddNet(e *record.Event, p *record.NetPayload) {
	if p.Op == "bind" || p.Op == "listen" || p.Op == "accept" || e.Verdict == record.VerdictRefused {
		return // a refused connect is counted from its refused line
	}
	got := e.Verdict != record.VerdictAsk
	l.leak.send(e, p.Proto, p.Dst, p.Host, e.Rule, got)
}

// leakAddFS feeds a file line to the rule. A refused or held line is counted from its refused or ask line.
func (l *Learner) leakAddFS(e *record.Event, p *record.FSPayload) {
	if notDone(e) {
		return
	}
	l.leak.touch(e, p.Path, e.Rule, secretpath.ReadOpen(p.Op, p.Flags, p.Errno, p.Created))
	l.leak.touch(e, p.Path2, e.Rule, false)
}

// askedFields are the fields of an ask line the rule reads.
type askedFields struct {
	Op      string `json:"op"`
	Target  string `json:"target"`
	Target2 string `json:"target2"`
	AskRule string `json:"ask_rule"`
}

// leakAddAsk feeds an ask line: a secret someone was asked about is a touch, whatever the answer was.
func (l *Learner) leakAddAsk(e *record.Event) error {
	var p askedFields
	if err := e.DecodePayload(&p); err != nil {
		return fmt.Errorf("learn: ask at seq %d: %w", e.Seq, err)
	}
	rule := e.Rule
	if rule == "" {
		rule = p.AskRule
	}
	if p.Op != "read" && p.Op != "open" && p.Op != "write" && !strings.HasPrefix(rule, "fs.") {
		return nil
	}
	target := p.Target
	if p.Target2 != "" {
		target += " -> " + p.Target2
	}
	l.leak.touch(e, target, rule, false)
	return nil
}

// leakAddRefused feeds a refused line: a refused connect is a send that did not get through, and any other refusal
// but a program's names a path, a touch that did not get through.
func (l *Learner) leakAddRefused(e *record.Event) error {
	var p record.RefusedPayload
	if err := e.DecodePayload(&p); err != nil {
		return fmt.Errorf("learn: refused at seq %d: %w", e.Seq, err)
	}
	switch p.Op {
	case "net":
		l.leak.send(e, "", p.Target, "", e.Rule, false)
	case "exec":
	default:
		l.leak.touch(e, p.Target, e.Rule, false)
	}
	return nil
}

// leakEntryWhy is the "observed, not allowed" reason of a net.allow entry the rule left out.
const leakEntryWhy = "an open of a secret for reading came next to this send, so a secret may have gone there; add it by hand only if you know it is the agent's own service"

// withhold takes a leak's entry out of the proposal: entry is what classify would have allowed. It reports whether
// the entry was the leak's to take: a unix socket's is not (Leak.Local).
func (p *Proposal) withhold(held map[netKey]*Leak, k netKey, entry string, n int) bool {
	lk := held[k]
	if lk == nil || lk.Local || entry == "" {
		return false
	}
	lk.Entries = append(lk.Entries, entry)
	p.Left = append(p.Left, Excluded{Section: "net", What: record.Printable(entry), Why: leakEntryWhy, Count: n})
	return true
}

// maxLeakNames is how many secrets or destinations one warning names; the file's comments name every destination.
const maxLeakNames = 4

// listNames joins names, each made safe to print, up to maxLeakNames.
func listNames(names []string) string {
	shown := make([]string, 0, min(len(names), maxLeakNames))
	for _, n := range names[:min(len(names), maxLeakNames)] {
		shown = append(shown, record.Printable(n))
	}
	s := strings.Join(shown, ", ")
	if len(names) > maxLeakNames {
		s += fmt.Sprintf(" and %d more", len(names)-maxLeakNames)
	}
	return s
}

// Warnings are what a person must know before using the proposal, one sentence each, the most serious first: the
// destinations left out as a leak, the ones the leak rule cannot match to an entry, and what the proposal leaves
// open. The file's header carries them, and tego learn says them on stderr.
func (p *Proposal) Warnings() []string {
	var out []string
	var withheld, byName, local, resolver, other []string
	for _, lk := range p.Leaks {
		switch {
		case lk.ByName:
			byName = append(byName, lk.Dest)
		case lk.Local:
			local = append(local, lk.Dest)
		case lk.Resolver:
			resolver = append(resolver, lk.Dest)
		case len(lk.Entries) > 0:
			withheld = append(withheld, lk.Dest)
		default:
			other = append(other, lk.Dest)
		}
	}
	// "or tried to": a watched line carries no return, so the record cannot say the open worked.
	names := listNames(p.LeakSecrets)
	if len(p.LeakSecrets) == 0 {
		names = "secret files whose names were omitted"
	}
	opened := "this run opened " + names + " for reading, or tried to,"
	if len(withheld) > 0 {
		out = append(out, fmt.Sprintf("%s next to a send to %s, which is how a leak looks in the record: the proposal leaves that out; add an address back only if you know it is the agent's own service",
			opened, listNames(withheld)))
	}
	if len(other) > 0 {
		out = append(out, fmt.Sprintf("%s next to a send to %s: the proposal does not allow it, and it may be where the secret went", opened, listNames(other)))
	}
	if len(resolver) > 0 {
		out = append(out, fmt.Sprintf("%s next to a connect to %s: the engine did not name it a resolver, and the port alone says nothing, so the proposal leaves that out; if it is the machine's resolver nothing is lost, as tego allows that one itself",
			opened, listNames(resolver)))
	}
	if len(local) > 0 {
		out = append(out, fmt.Sprintf("%s next to a connect to the local socket %s: a socket is not withheld, so if the proposal lists it, check what listens there", opened, listNames(local)))
	}
	if len(byName) > 0 {
		out = append(out, fmt.Sprintf("%s next to a send to %s, recorded only by host name: the record keeps no address for it, so the proposal cannot tell whether an address it allows is the same place; check every net.allow entry",
			opened, listNames(byName)))
	}
	out = append(out, "this proposal leaves env and reads open: with no env section every variable of the launcher's environment reaches the agent, secrets included, and the agent can read any file the built-in fs.deny_read list does not name; a secret it can read can leave through any address allowed here")
	return out
}
