// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/secretpath"
)

// Signal over noise: a run's lines read for what a person needs first (the secrets it touched, where it sent
// data, what it asked, what a live block stopped, which programs were refused), and its refusals grouped so that
// an agent's own background traffic (Codex's Cloudflare probes on port 65535, a /dev/tty the held reads cannot
// hold) folds into one counted row instead of burying the few refusals that matter. Nothing is dropped: every
// refused line is in exactly one group, and every group keeps its count.

// NearSecretWindow and NearSecretLines are how close to a secret touch a destination's first contact must be to
// be marked "near a secret": secretpath's rule, which tego learn's leak rule uses too.
const (
	NearSecretWindow = secretpath.NearSeconds * time.Second
	NearSecretLines  = secretpath.NearLines
)

// defaultRules are the rule keys a decision carries when no entry of the contract named the action.
var defaultRules = map[string]bool{"unmatched": true, "host-sockets": true, "held-unsupported": true}

// Sensitive is what makes a path a secret for one run: the fs.deny_read and fs.ask_read entries of its contract
// (relative entries resolve against the run's working directory), on top of IsSecretPath. An fs.ask entry is a
// folder whose changes ask a person first, not a secret: the web layer leaves those out. Rules are the person's own
// severity rules, which a Signal's severities read.
type Sensitive struct {
	Entries []string
	Cwd     string
	Rules   []SevRule
}

// under is the first entry p is under, as written (compileSensitive says how an entry is read).
func (s Sensitive) under(p string) (string, bool) {
	m := compileSensitive(s)
	return m.under(p)
}

// SecretTouch is one sensitive path the run touched and how each touch went.
type SecretTouch struct {
	Path string
	// Rule is the contract entry that names the path ("" when only IsSecretPath or an entry match found it);
	// Entry is the contract entry the path is under, as written.
	Rule, Entry                       string
	Refused, Asked, Allowed, Observed int
	First                             time.Time
	FirstSeq                          uint64
	WellKnown                         bool
	// NearSend: an outbound destination that is not background was first contacted within NearSecretWindow and
	// NearSecretLines of this path's first touch or of a read of it (a read right before a send). These sort first.
	NearSend bool
	// ReadNearSend: NearSend by a read: an open of this path for reading (secretpath.ReadOpen) that went through, any
	// of them and not only the first. This is what the run's verdict calls exposed.
	ReadNearSend bool
	// Unread counts the Allowed and Observed lines that cannot have read the file: a write-only open, a create, an
	// unlink, a failed open.
	Unread   int
	Severity Severity
	// reads are the places of the opens that can have read it, oldest first.
	reads []touchAt
}

// Dest is one outbound destination (host:port, by name when the line names the host) and how its connects went.
type Dest struct {
	Key, Name                         string
	Allowed, Observed, Refused, Asked int
	// InContract: a line for it carried a net[...] entry (or the always-allowed resolver), so the contract allows it.
	InContract bool
	// Resolver: a line for it carried net.resolver, the engine's word that it is a resolver the run has.
	Resolver bool
	// NearSecret: its first contact was within NearSecretWindow and NearSecretLines of a secret touch.
	NearSecret bool
	// Background: it is a system lookup socket or a resolver (lookupDst), whatever its lines say, or every line
	// for it is a refusal in a background group. The dashboard calls these routine.
	Background bool
	First      time.Time
	FirstSeq   uint64
	// Query is the Logs search text that finds its lines.
	Query  string
	groups map[int]bool
}

// Approval is one ask and what became of it.
type Approval struct {
	AskID, Op, Target, Rule string
	TS                      time.Time
	Seq                     uint64
	// State is pending (the run is live and no answer line came yet), approved, denied, unanswered (the run ended
	// with no answer line) or lost (the run was lost before an answer: nobody can answer it now).
	State string
	By    string
	After time.Duration
}

// BlockHit is a live block that refused actions in this run.
type BlockHit struct {
	Rule, Value string
	N           int
}

// ProgramHit is a program the run was refused, by basename and rule.
type ProgramHit struct {
	Program, Rule string
	N             int
	Background    bool
}

// Group is the refused lines of one run with the same rule, reason, operation and subject: the destination host
// (any port) for a connect, the program's basename for an exec, the path otherwise. A burst of refused connects to
// one host, one destination or one range reads as one Group (burst.go).
type Group struct {
	// Event is the group's newest line, for its rule label and reason.
	Event
	// Label is the rule in words (set by the web layer).
	Label   string
	Subject string
	Class   string // net, exec or fs
	// Targets are the distinct refused targets (host:port, program path or path), oldest first; Ports the ports.
	Targets     []string
	Ports       []string
	Count       int
	First, Last time.Time
	FirstSeq    uint64
	Secret      bool
	NearSecret  bool
	Background  bool
	// Write: a line of it would have changed a file.
	Write bool
	// to is the file that runs code later a line of it would have replaced by a rename or a link (refused), "" for none.
	// It is what makes such a group High, and its row says it: Subject is then "from → to", and Query from.
	to string
	// Why says why a background group is background.
	Why      string
	Severity Severity
	// Hosts is how many addresses a burst's row holds (mergeBursts), 0 for a group of one host. Its Subject is then the
	// range or the destination the rule names. Query is the text that finds a row's lines when its Subject does not.
	Hosts int
	Query string
}

// LogsText is the Logs search that finds a group's lines.
func (g Group) LogsText() string {
	if g.Query != "" {
		return g.Query
	}
	return g.Subject
}

// RunSignal is a run's highlights and its grouped refusals.
type RunSignal struct {
	Secrets   []SecretTouch
	Outbound  []Dest // next to a secret first, then refused by count, then the rest (not in the contract first), then background
	Approvals []Approval
	Blocks    []BlockHit
	Programs  []ProgramHit
	// Groups are the refusal groups: the ones that matter first (secrets, contract entries, near a secret, then
	// newest), then the background ones, largest first.
	Groups []Group
	// Real and Background count the groups; RealLines and BackgroundLines the refused lines in each.
	Real, Background, RealLines, BackgroundLines int
	// BackgroundDests and BackgroundDestLines count the outbound destinations folded into background.
	BackgroundDests, BackgroundDestLines   int
	Approved, Denied, PendingN, Unanswered int
	// High, Medium and Low count the refusal groups at each severity (routine ones are Background): blocked actions
	// only, so the run page and Detections show the same numbers.
	High, Medium, Low int
	// AllowedFrom is set on a watched run's Signal read against an enforced run's allow list (Against): that run's
	// ID. Its InContract destinations are the ones that run's contract allows.
	AllowedFrom string
	// bg holds the key of every background group (groupKey), for IsBackground; sev every group's severity; agent is the
	// coding agent the run started (CommandAgent) and rules the person's severity rules this signal was read with.
	bg    map[string]bool
	sev   map[string]Severity
	agent string
	rules []SevRule
}

// SeverityOf is the severity of a refused line of the run this signal was read from (SevRoutine for a background
// one). A refused action and its mirror word the action differently (op, reason), so a line whose own key names no
// group takes the highest severity of its class and subject, and a line no group holds is read on its own.
func (s *RunSignal) SeverityOf(e *Event) Severity {
	class, subject, _ := groupSubject(e)
	if v, ok := s.sev[groupKey(e, subject)]; ok {
		return v
	}
	// A refused connect: its mirror's own group, by the key that group has. A row's Severity is the highest it holds,
	// and the scan below is a substring match over every target of the run, for each line that asks.
	if e.Kind == "net" {
		_, dst := splitNet(e.Target)
		sub, _ := netSubject(dst)
		if v, ok := s.sev[e.Rule+"\x00"+e.Reason+"\x00net\x00"+sub]; ok {
			return v
		}
	}
	// Any other refused action: the group its mirror is in has the same rule and reason, and the mirror's target is in
	// the action's ("104.18.32.47:443" in "chatgpt.com (104.18.32.47:443)") or is the program's path (an exec's target
	// is its command line).
	for i := range s.Groups {
		g := &s.Groups[i]
		if g.Rule != e.Rule || g.Reason != e.Reason {
			continue
		}
		for _, t := range g.Targets {
			if t != "" && (strings.Contains(e.Target, t) || t == e.path) {
				return g.Severity
			}
		}
	}
	if v, ok := s.sev[class+"\x00"+subject]; ok {
		return v
	}
	// A refused line no refusal group holds (no mirror line was written for it): its severity from the line itself.
	g := Group{Event: *e, Class: class, Subject: subject}
	if e.Kind == "net" || e.Kind == "exec" {
		g.Class = e.Kind
	}
	g.Secret = IsSecretPath(subject) || secretRule(e.Rule)
	g.Write = writesFile(e)
	return groupSeverity(&g, s.agent, s.rules)
}

// splitNet splits a net line's Target ("chatgpt.com (1.2.3.4:443)" or "1.2.3.4:443") into the host name and dst.
func splitNet(t string) (name, dst string) {
	if i := strings.LastIndex(t, " ("); i > 0 && strings.HasSuffix(t, ")") {
		return t[:i], t[i+2 : len(t)-1]
	}
	return "", t
}

// hostPort splits a dst into host and port; a unix socket or netlink is all host.
func hostPort(dst string) (string, string) {
	if strings.HasPrefix(dst, "unix:") {
		return dst, ""
	}
	i := strings.LastIndexByte(dst, ':')
	if i <= 0 {
		return dst, ""
	}
	h := dst[:i]
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return dst, "" // a bare IPv6 address with no port
	}
	return h, dst[i+1:]
}

// loopback reports whether a host is this machine, where each port is a different service: reaching one port says
// nothing about another.
func loopback(host string) bool {
	h := strings.Trim(host, "[]")
	return strings.HasPrefix(h, "127.") || h == "::1" || h == "localhost" || strings.HasPrefix(h, "unix:")
}

// routeProbePort is the port musl's getaddrinfo connects a UDP socket to, for each address a lookup returns, to sort
// them by the route the kernel would take (RFC 6724); no service listens there and nothing is sent.
const routeProbePort = "65535"

// RouteProbe reports whether a net line is a route probe: UDP to port 65535 of a remote host. Only UDP: a TCP
// connect to that port is a real attempt, and the port alone would fold an attacker's beacon there as background.
// The supervisor refuses a probe a contract does not name (a connected UDP socket's later sends are decided at that
// connect and nowhere else), so this is a display class only; docs/DASHBOARD.md.
func RouteProbe(e *Event) bool {
	if e.Kind != "net" || e.Proto != "udp" {
		return false
	}
	_, dst := splitNet(e.Target)
	h, port := hostPort(dst)
	return port == routeProbePort && !loopback(h)
}

// probeTargets is the destinations of r every refused net line to which is a route probe: the refused lines (kind
// refused, which carry no protocol) to one of them are route probes too.
func probeTargets(r *Run) map[string]bool {
	var ps probeSet
	evs := r.AllEvents()
	for i := range evs {
		ps.add(&evs[i])
	}
	return ps.targets()
}

func outboundOp(op string) bool { return op != "bind" && op != "listen" && op != "accept" }

// paths is the file paths an fs line names (a rename names two).
func paths(target string) []string {
	if a, b, ok := strings.Cut(target, " → "); ok {
		return []string{a, b}
	}
	return []string{target}
}

// groupSubject is what a refused line's group is about: the destination host (any port) for a connect, the program's
// basename for an exec, the path otherwise; and for a connect its port.
func groupSubject(e *Event) (class, subject, port string) {
	switch e.Op {
	case "net":
		subject, port = netSubject(e.Target)
		return "net", subject, port
	case "exec":
		return "exec", path.Base(e.Target), ""
	}
	return "fs", e.Target, ""
}

// netSubject is what the group of a refused connect to dst is about, and its port.
func netSubject(dst string) (subject, port string) {
	h, port := hostPort(dst)
	if loopback(h) || port == routeProbePort {
		// Each local port is a different service: one group per port, which a row of the host then holds (burst.go). A
		// route probe (port 65535) is a group of its own, so a host's probe folds as background while a real connect to
		// it does not.
		return dst, port
	}
	return h, port
}

// groupKey is the identity of the group a refused line is in: its rule, reason, operation and subject.
func groupKey(e *Event, subject string) string {
	return e.Rule + "\x00" + e.Reason + "\x00" + e.Op + "\x00" + subject
}

// IsBackground reports whether a refused line of the run this signal was read from is in a background group.
func (s *RunSignal) IsBackground(e *Event) bool {
	_, subject, _ := groupSubject(e)
	return s.bg[groupKey(e, subject)]
}

// computeSignal reads one run's lines for its highlights and grouped refusals (Signal, uncached): the fold
// (signalfold.go) over every line, then its post-pass.
func computeSignal(r *Run, s Sensitive) *RunSignal {
	f := newSignalFold(s)
	f.add(r.AllEvents())
	return f.finish(r)
}

// groupBackground reports whether every refusal group of a program (any reason) is background.
func groupBackground(gs []Group, p *ProgramHit) bool {
	for i := range gs {
		if gs[i].Class == "exec" && gs[i].Subject == p.Program && gs[i].Rule == p.Rule && !gs[i].Background {
			return false
		}
	}
	return true
}

// classify decides whether a refusal group is background. The stated rule: a group is background when the
// contract's default decided it (no entry names it: rule unmatched, host-sockets or held-unsupported), it touches
// no secret, its first refusal is not near a secret touch (NearSecretWindow, NearSecretLines), and one of these holds:
//   - it is a system lookup socket (nscd, systemd's userdb or resolved, the D-Bus system and session buses);
//   - it is a DNS lookup: a refused connect to port 53 on this machine (dnsGroup);
//   - it is a connect to a remote host this run also reached (allowed or observed) on some port: the agent is
//     already talking to that host, so the refused port sends nothing to anyone new (loopback is never folded
//     this way: each local port is a different service);
//   - it is a route probe: every refused line to it is UDP to port 65535 of a remote host (RouteProbe), the UDP
//     connect musl's getaddrinfo makes to sort a lookup's addresses, which sends nothing (Compare leaves these
//     out the same way); a TCP connect to that port is not one;
//   - it is a terminal or standard device (stdDevice).
//
// How often a group repeats is never one of them: severity is read from place and operation, and an attacker's tenth
// try is no less an attempt than its first.
func classify(g *Group, reached, probes map[string]bool) {
	if !defaultRules[g.Rule] || g.Secret || g.NearSecret {
		return
	}
	switch {
	case g.SystemLookup:
		g.Background, g.Why = true, "a system lookup socket"
	case dnsGroup(g):
		g.Background, g.Why = true, "a DNS lookup"
	case g.Class == "net" && !loopback(g.Subject) && reached[g.Subject]:
		g.Background, g.Why = true, "the run also reached this host"
	case g.Class == "net" && probes[g.Subject]:
		g.Background, g.Why = true, "a route probe to port 65535"
	case g.Class == "fs" && stdDevice(g.Subject):
		g.Background, g.Why = true, "a terminal or standard device"
	}
}

// stdDevices are the devices every program opens for its terminal and its standard streams: they hold nothing of the
// person's, and an agent that opens one is talking to its own screen (a /dev/tty the held reads cannot hold).
var stdDevices = []string{"/dev/tty", "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/ptmx",
	"/dev/stdin", "/dev/stdout", "/dev/stderr"}

func stdDevice(p string) bool {
	return slices.Contains(stdDevices, p) || strings.HasPrefix(p, "/dev/pts/")
}

// dnsGroup reports whether a group's refused connects are name lookups: to port 53 on this machine (ResolverDst; a group
// on loopback keeps its port in its subject). A resolver the run has is allowed and never refused, so a refusal on port
// 53 of any other address is what any other refused connect is: the port says nothing about what was sent.
func dnsGroup(g *Group) bool { return g.Class == "net" && ResolverDst(g.Subject) }

func sortSignal(out *RunSignal) {
	rank := func(g *Group) int {
		switch {
		case g.Background:
			return 4
		case g.Secret:
			return 0
		case !defaultRules[g.Rule]:
			return 1
		case g.NearSecret:
			return 2
		}
		return 3
	}
	sort.SliceStable(out.Groups, func(i, j int) bool {
		a, b := &out.Groups[i], &out.Groups[j]
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		if a.Background {
			return a.Count > b.Count
		}
		return a.Last.After(b.Last)
	})
	// Outbound order: next to a secret (never one the contract allows), then the other refusals, then what is
	// neither refused nor in the contract, then the contract's and DNS, then background.
	drank := func(d *Dest) int {
		switch {
		case d.Background:
			return 4
		case d.NearSecret:
			return 0
		case d.Refused > 0:
			return 1
		case d.InContract, ResolverDst(d.Key):
			return 3
		}
		return 2
	}
	sort.SliceStable(out.Outbound, func(i, j int) bool {
		a, b := &out.Outbound[i], &out.Outbound[j]
		if ra, rb := drank(a), drank(b); ra != rb {
			return ra < rb
		}
		if a.Refused != b.Refused {
			return a.Refused > b.Refused
		}
		return a.First.Before(b.First)
	})
	sort.SliceStable(out.Secrets, func(i, j int) bool { return out.Secrets[i].NearSend && !out.Secrets[j].NearSend })
	sort.SliceStable(out.Programs, func(i, j int) bool {
		a, b := &out.Programs[i], &out.Programs[j]
		if a.Background != b.Background {
			return !a.Background
		}
		return a.N > b.N
	})
}

// OutHead is the first n outbound destinations that are not background; OutTail the rest of them.
func (s *RunSignal) OutHead(n int) []Dest { h, _ := s.front(n); return h }

// OutTail is the destinations after OutHead(n) that are not background.
func (s *RunSignal) OutTail(n int) []Dest { _, t := s.front(n); return t }

func (s *RunSignal) front(n int) (head, tail []Dest) {
	end := len(s.Outbound)
	for end > 0 && s.Outbound[end-1].Background {
		end--
	}
	fr := s.Outbound[:end]
	if len(fr) <= n {
		return fr, nil
	}
	return fr[:n], fr[n:]
}

// ProgHead is the first n refused programs; ProgTail the rest.
func (s *RunSignal) ProgHead(n int) []ProgramHit { return s.Programs[:min(n, len(s.Programs))] }

// ProgTail is the refused programs after ProgHead(n).
func (s *RunSignal) ProgTail(n int) []ProgramHit { return s.Programs[min(n, len(s.Programs)):] }
