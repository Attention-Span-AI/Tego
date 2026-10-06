// SPDX-License-Identifier: Apache-2.0

// Package gate evaluates bounded, deterministic policy escalations. It does
// no filesystem, resolver or process access, and never lowers an input floor.
package gate

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/policy/thishost"
)

const (
	MaxRules = 256
	MaxText  = 4096
	MaxScore = 100
	MaxArgs  = 128
)

type Kind uint8

const (
	FSRead Kind = iota + 1
	FSWrite
	Exec
	Net
)

type Predicate uint8

const (
	WriteOutsideWorktree Predicate = iota + 1
	ReadMatches
	ExecMatches
	NetUndeclared
	NetTo
)

type Verdict uint8

const (
	Allow Verdict = iota
	Ask
	Refused
)

type Rule struct {
	Predicate Predicate
	Argument  string
	Score     int
}

// Text is the closed predicate spelling used in effective-policy output.
func (r Rule) Text() string {
	switch r.Predicate {
	case WriteOutsideWorktree:
		return "fs.write outside worktree"
	case NetUndeclared:
		return "net to undeclared host"
	case ReadMatches:
		return "fs.read matches " + strconv.Quote(r.Argument)
	case ExecMatches:
		return "exec matches " + strconv.Quote(r.Argument)
	case NetTo:
		return "net to " + r.Argument
	}
	return ""
}

type compiledRule struct {
	Rule
	host string
	port uint16
	// addr is a `net to` rule's host when that is an address, and local says it is a name reserved for loopback
	// (namesThisHost).
	addr    netip.Addr
	local   bool
	name    string
	pattern string
	// cmd is an exec rule's argument read as a command pattern with the shared matcher (ADR 0048 (5)), nil when its
	// command word holds a glob or the pattern grammar refuses it: the legacy glob reading alone then applies.
	cmd *execmatch.Pattern
	// read is a read rule's pattern read as the clean paths it matches (readPattern).
	read readPattern
}

// Policy owns its copied rules. Fields cannot be edited after compilation.
type Policy struct {
	rules       []compiledRule
	allow, ask  int
	kinds, asks uint8
	// escalates holds the kinds whose rules can sum to allow or above (MayEscalate).
	escalates uint8
	// asksRW and escalatesRW are MayAsk and MayEscalate over the read and the write rules together: the reach of an
	// FSWrite action that also reads (Action.Reads), which both kinds score.
	asksRW, escalatesRW bool
	// cmds indexes the exec rules' command patterns by tool, so an exec normalizes once per tool, not once per rule.
	cmds *execmatch.Index
	// held is the contract's `completion: held` (ADR 0041 Stage B): an open of an escalating fs kind is held and
	// completed in the run by the open deputy instead of continued on its copied name.
	held bool
}

// Completion values of a gate (ADR 0041 Stage B): copied, the default, decides on copied syscall facts and continues
// what it does not refuse; held completes every open of an escalating fs kind on the object it scored.
const (
	CompletionCopied = "copied"
	CompletionHeld   = "held"
)

// HeldCompletion reports whether the contract chose `completion: held`.
func (p *Policy) HeldCompletion() bool { return p != nil && p.held }

// WithHeldCompletion is p with `completion: held`.
func (p *Policy) WithHeldCompletion() *Policy {
	if p == nil {
		return nil
	}
	cp := *p
	cp.held = true
	return &cp
}

// Action contains facts already copied and validated by the caller. Complete
// must be false after truncation or an unreliable target/argument lookup.
type Action struct {
	Kind     Kind
	Complete bool
	// Reads says an FSWrite action also reads the file at Path (a read-write open; the source of a rename or hard
	// link, which leaves its name): the read predicates score it too, every matching rule of either kind once, the
	// scores summed as one action's are. It widens no other kind. A move's end that leaves its name is scored as the
	// directory it may be too: every file beneath it is renamed (holdsMatch).
	Reads bool
	Path  string
	// Dest is the other end of a rename or hard link (an FSWrite action): one call, one line and one verdict, so one
	// action over both ends, every rule that matches an end it scores counted once (ADR 0007, 2026-10-20). The write
	// predicates score both ends; the read ones score Path when Reads and Dest when
	// DestReads (the destination of a RENAME_EXCHANGE, which leaves its name too). Complete covers both ends.
	Dest      string
	DestReads bool

	// PathNotDir and DestNotDir say the move's end is known to be no directory (its final name, not followed, is
	// another type or no object): no path lies beneath it, so a read rule matches it by its own name only. The zero
	// value is unknown, read as a directory (holdsMatch).
	PathNotDir, DestNotDir bool

	Worktree   string
	Executable string
	Invocation string // copied requested executable pathname, when available
	Args       []string
	Host       string
	Hosts      []string // complete bounded aliases of the copied destination
	Port       uint16
	Declared   bool
	// ThisHost is what the running host can tell of its addresses, for a Net action; nil knows what an address says by
	// itself, which is all a `compile --test` row has (namesThisHost).
	ThisHost thishost.Addrs
	commands []string
	invs     []execmatch.Invocation
	// here says a Net action's destination reaches this host (Evaluate).
	here bool
}

type Decision struct {
	Verdict Verdict
	Score   int
	Rule    string // first contributing declaration, or gate.unreadable
}

func predicateKind(p Predicate) Kind {
	switch p {
	case WriteOutsideWorktree:
		return FSWrite
	case ReadMatches:
		return FSRead
	case ExecMatches:
		return Exec
	case NetUndeclared, NetTo:
		return Net
	}
	return 0
}

func kindBit(k Kind) uint8 {
	if k < FSRead || k > Net {
		return 0
	}
	return 1 << (k - 1)
}

// New validates and copies the bounded rule program. The scores of the rules an action matches sum, saturated at
// 100 (ADR 0007: the sum is never lower than the highest rule), across both fs kinds for
// a write that reads (Action.Reads). The thresholds read
// as written: a score below allow allows, allow to ask (both inclusive) asks, above ask refuses.
// allow is at least 1, so an unmatched action (score 0) is always allowed.
func New(rules []Rule, allow, ask int) (*Policy, error) {
	if len(rules) > MaxRules || allow < 1 || allow >= ask || ask > MaxScore {
		return nil, fmt.Errorf("gate: at most %d rules and 1 <= allow < ask <= %d required (below allow allows, allow to ask asks, above ask refuses)", MaxRules, MaxScore)
	}
	p := &Policy{allow: allow, ask: ask, rules: make([]compiledRule, 0, len(rules))}
	for i, r := range rules {
		kind := predicateKind(r.Predicate)
		if kind == 0 || r.Score < 0 || r.Score > MaxScore || len(r.Argument) > MaxText || !utf8.ValidString(r.Argument) || strings.ContainsRune(r.Argument, 0) {
			return nil, fmt.Errorf("gate.rules[%d]: invalid predicate, argument or score", i)
		}
		c := compiledRule{Rule: r, name: "gate.rules[" + strconv.Itoa(i) + "]"}
		switch r.Predicate {
		case WriteOutsideWorktree, NetUndeclared:
			if r.Argument != "" {
				return nil, fmt.Errorf("%s: predicate takes no argument", c.name)
			}
		case ReadMatches, ExecMatches:
			if r.Argument == "" || strings.Contains(r.Argument, "**") {
				return nil, fmt.Errorf("%s: nonempty ordinary glob/literal required; recursive ** is unavailable", c.name)
			}
			if _, _, _, err := parseGlob(r.Argument); err != nil {
				return nil, fmt.Errorf("%s: invalid pattern: %w", c.name, err)
			}
			// Evaluate starts every command string with a basename (R2), so a first word holding a '/'
			// can never match an executable: "/usr/bin/curl *" was accepted and silently never fired.
			if first, rest, spaced := strings.Cut(r.Argument, " "); r.Predicate == ExecMatches && strings.Contains(first, "/") {
				fix := filepath.Base(first)
				if spaced {
					fix += " " + rest
				}
				return nil, fmt.Errorf("%s: an exec pattern's first word is matched against the executable's basename and cannot hold '/'; write %q", c.name, fix)
			}
			// Exec globs operate on a command string, where '/' is ordinary
			// text. NUL is excluded from original input, so it safely projects
			// slash away from filepath.Match's path separator semantics.
			c.pattern = strings.ReplaceAll(r.Argument, "/", "\x00")
			if r.Predicate == ReadMatches {
				var err error
				if c.read, err = newReadPattern(r.Argument); err != nil {
					return nil, fmt.Errorf("%s: fs.read pattern %q: %w", c.name, r.Argument, err)
				}
			}
			if r.Predicate == ExecMatches {
				// The command reading (ADR 0048 (5)), unioned with the glob: a pattern whose command word holds a
				// glob, or that the grammar refuses, keeps the glob reading alone.
				if cmd, err := execmatch.Parse(r.Argument, execmatch.ListDeny, rows.Builtin()); err == nil {
					c.cmd = cmd
				}
			}
		case NetTo:
			host, port, err := net.SplitHostPort(r.Argument)
			n, pe := strconv.ParseUint(port, 10, 16)
			if err != nil || pe != nil || n == 0 || host == "" || strings.ContainsAny(host, "/*?@%\\ \t\r\n") {
				return nil, fmt.Errorf("%s: literal host:port required", c.name)
			}
			c.host, c.port = canonicalHost(host), uint16(n)
			c.local = thishost.Name(c.host)
			if addr, err := netip.ParseAddr(c.host); err == nil {
				c.addr = addr
			}
		}
		p.rules = append(p.rules, c)
		p.kinds |= kindBit(kind)
	}
	var cmds []*execmatch.Pattern
	for _, r := range p.rules {
		if r.cmd != nil {
			cmds = append(cmds, r.cmd)
		}
	}
	if len(cmds) > 0 {
		p.cmds = execmatch.NewIndex(rows.Builtin(), cmds, execmatch.IndexOptions{})
	}
	// A bounded subset-sum identifies kinds which may need approval. This is
	// conservative about predicate overlap, and allocates no state at runtime.
	for kind := FSRead; kind <= Net; kind++ {
		possible := p.sums(func(r Rule) bool { return predicateKind(r.Predicate) == kind })
		if asks(possible, allow, ask) {
			p.asks |= kindBit(kind)
		}
		if escalates(possible, allow) {
			p.escalates |= kindBit(kind)
		}
	}
	rw := p.sums(func(r Rule) bool { k := predicateKind(r.Predicate); return k == FSRead || k == FSWrite })
	p.asksRW, p.escalatesRW = asks(rw, allow, ask), escalates(rw, allow)
	return p, nil
}

// asks reports whether a reachable sum lies in the ask band, allow to ask inclusive.
func asks(possible [MaxScore + 1]bool, allow, ask int) bool {
	for score := allow; score <= ask; score++ {
		if possible[score] {
			return true
		}
	}
	return false
}

// sums is the bounded subset-sum of the scores of the rules keep selects: possible[s] says some subset of them
// sums, saturated at MaxScore, to s.
func (p *Policy) sums(keep func(Rule) bool) [MaxScore + 1]bool {
	var possible [MaxScore + 1]bool
	possible[0] = true
	for _, r := range p.rules {
		if !keep(r.Rule) {
			continue
		}
		for score := MaxScore; score >= 0; score-- {
			if possible[score] {
				possible[min(MaxScore, score+r.Score)] = true
			}
		}
	}
	return possible
}

// escalates reports whether a reachable sum lies at or above allow.
func escalates(possible [MaxScore + 1]bool, allow int) bool {
	for score := allow; score <= MaxScore; score++ {
		if possible[score] {
			return true
		}
	}
	return false
}

// canonicalHost is the spelling a host compares in. An IPv6 scope id goes with the mapped form: it picks a link, it
// names no other destination, and a rule cannot carry one (New refuses a zone), so `[::1%1]:P` scored nothing against
// `net to [::1]:P` and reached the address the rule names.
func canonicalHost(host string) string {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().WithZone("").String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// reachesThisHost reports whether a destination, an address or a name as Action.Host gives it, reaches this host.
func reachesThisHost(host string, h thishost.Addrs) bool {
	if a, err := netip.ParseAddr(canonicalHost(host)); err == nil {
		return thishost.Reaches(a, h)
	}
	return thishost.Name(host)
}

// namesThisHost reports whether a `net to` rule's host names this host. A rule on this host is on the destination, not
// on one spelling of it, as a live block is (liveblock.Set.MatchInet): a server bound to all interfaces answers on every
// loopback address and each of the host's own, so a rule on 127.0.0.1:P scored nothing for 127.0.0.2:P, [::1]:P or the
// host's LAN address on P, and a sibling rule on [::1]:Q nothing for 127.0.0.1:Q. A datagram to a group or a broadcast
// address reaches such a server too, and a rule on one of those names no host. It costs at most another local server on
// the rule's port, or a group send on it. Whether a rule's literal is one of the host's own only the running host can
// tell, so `compile --test` answers that row by the literal alone (gate.md R3).
func (r *compiledRule) namesThisHost(h thishost.Addrs) bool {
	return r.local || r.addr.IsValid() && thishost.Names(r.addr, h)
}

// CheckWorktree refuses a relative `fs.read matches` pattern that no path from worktree can match, since it needs
// more leading ".." components than worktree has names. New cannot ask it, as the
// worktree is the run's; the compile that captures the run's worktree does, so such a rule is refused there rather
// than accepted to never fire.
func (p *Policy) CheckWorktree(worktree string) error {
	if p == nil {
		return nil
	}
	for _, r := range p.rules {
		if r.Predicate != ReadMatches {
			continue
		}
		if err := r.read.beyond(r.Argument, worktree); err != nil {
			return fmt.Errorf("%s: fs.read pattern %q: %w", r.name, r.Argument, err)
		}
	}
	return nil
}

// Rules returns an independent copy for effective-policy display.
func (p *Policy) Rules() []Rule {
	if p == nil {
		return nil
	}
	out := make([]Rule, len(p.rules))
	for i, r := range p.rules {
		out[i] = r.Rule
	}
	return out
}
func (p *Policy) Thresholds() (allow, ask int) {
	if p == nil {
		return 0, 0
	}
	return p.allow, p.ask
}

// CommandReading is rule i's command reading as compile prints it (ADR 0048 (5): an existing rule now also matches
// what the shared matcher reads, `rm -fr` for `rm -rf`), "" when the rule has none.
func (p *Policy) CommandReading(i int) string {
	if p == nil || i < 0 || i >= len(p.rules) || p.rules[i].cmd == nil {
		return ""
	}
	return p.rules[i].cmd.Reading()
}

// HostEndpoints returns a copy of the literal endpoints required by NetTo.
func (p *Policy) HostEndpoints() []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, r := range p.rules {
		if r.Predicate == NetTo {
			out = append(out, r.Argument)
		}
	}
	return out
}

func (p *Policy) Has(kind Kind) bool    { return p != nil && p.kinds&kindBit(kind) != 0 }
func (p *Policy) MayAsk(kind Kind) bool { return p != nil && p.asks&kindBit(kind) != 0 }

// MayEscalate reports whether the kind's rules can raise a complete action's verdict out of the allow band, to ask or
// refused (ADR 0041 D1): a kind that cannot carries no supervisor decision but the gate.unreadable refusal of
// an incomplete action. Like MayAsk it is conservative about predicate overlap.
func (p *Policy) MayEscalate(kind Kind) bool { return p != nil && p.escalates&kindBit(kind) != 0 }

// MayAskReadWrite is MayAsk for an FSWrite action that also reads (Action.Reads), which the read and the write rules
// score together: true when either kind's rules, or some of both summed, can reach the ask band.
func (p *Policy) MayAskReadWrite() bool { return p != nil && p.asksRW }

// MayEscalateReadWrite is MayEscalate for an FSWrite action that also reads (Action.Reads): true when either kind's
// rules, or some of both summed, can score it to allow or above.
func (p *Policy) MayEscalateReadWrite() bool { return p != nil && p.escalatesRW }

// ScoresBeneath reports whether a read rule is a path pattern, which can match a path beneath a moved directory
// (holdsMatch): only then does a move's end need its file type (Action.PathNotDir, DestNotDir).
func (p *Policy) ScoresBeneath() bool {
	if p == nil {
		return false
	}
	for i := range p.rules {
		if p.rules[i].Predicate == ReadMatches && p.rules[i].read.path {
			return true
		}
	}
	return false
}

// MayEscalateBy is MayEscalate over one predicate's rules alone: what an action only that predicate can match
// (a unix destination, which `net to host:port` never matches) may be raised by.
func (p *Policy) MayEscalateBy(pred Predicate) bool {
	return p != nil && escalates(p.sums(func(r Rule) bool { return r.Predicate == pred }), p.allow)
}

// Evaluate preserves a refused floor without evaluating predicates. Missing
// relevant facts refuse; copied facts never substitute a positive decision
// when a live lookup failed. A rule score cannot remove an existing ask.
func (p *Policy) Evaluate(floor Verdict, a Action) Decision {
	d := Decision{Verdict: floor}
	if a.Kind != FSWrite {
		a.Reads, a.Dest, a.DestReads = false, "", false
	}
	a.DestReads = a.DestReads && a.Dest != ""
	if floor == Refused || !p.Has(a.Kind) && !((a.Reads || a.DestReads) && p.Has(FSRead)) {
		return d
	}
	if !a.Complete {
		return Decision{Verdict: Refused, Score: MaxScore, Rule: "gate.unreadable"}
	}
	if a.Kind == Net {
		if len(a.Hosts) > MaxRules {
			return Decision{Verdict: Refused, Score: MaxScore, Rule: "gate.unreadable"}
		}
		a.here = reachesThisHost(a.Host, a.ThisHost)
	}
	if a.Kind == Exec {
		if len(a.Args) > MaxArgs || a.Executable == "" || len(a.Executable) > MaxText || strings.ContainsRune(a.Executable, 0) || !utf8.ValidString(a.Executable) {
			return Decision{Verdict: Refused, Score: MaxScore, Rule: "gate.unreadable"}
		}
		total := len(filepath.Base(a.Executable))
		for _, arg := range a.Args {
			if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) || len(arg) > MaxText {
				return Decision{Verdict: Refused, Score: MaxScore, Rule: "gate.unreadable"}
			}
			total += len(arg) + 1
			if total > MaxText {
				return Decision{Verdict: Refused, Score: MaxScore, Rule: "gate.unreadable"}
			}
		}
		names := []string{filepath.Base(a.Executable)}
		if a.Invocation != "" {
			if len(a.Invocation) > MaxText || !utf8.ValidString(a.Invocation) || strings.ContainsRune(a.Invocation, 0) {
				return Decision{Verdict: Refused, Score: MaxScore, Rule: "gate.unreadable"}
			}
			names = append(names, filepath.Base(a.Invocation))
		}
		if len(a.Args) > 0 && a.Args[0] != "" {
			names = append(names, filepath.Base(a.Args[0]))
		}
		for _, name := range names {
			command := name
			if len(a.Args) > 1 {
				command += " " + strings.Join(a.Args[1:], " ")
			}
			a.commands = append(a.commands, strings.ReplaceAll(command, "/", "\x00"))
		}
		// The command reading's interpretations (ADR 0048 (5)): names and argv only, so by name, dashed forms,
		// multicall and interpreter dispatch; the gate is handed no identity and no #! form.
		if p.cmds != nil {
			f := execmatch.Facts{Requested: a.Invocation, Image: a.Executable, Argv: a.Args, ArgvComplete: true}
			if len(a.Args) > 0 {
				f.Argv0 = a.Args[0]
			}
			a.invs = p.cmds.Interpretations(&f)
		}
	}
	for _, r := range p.rules {
		if !scores(r, a) {
			continue
		}
		if d.Rule == "" {
			d.Rule = r.name
		}
		d.Score = min(MaxScore, d.Score+r.Score)
	}
	if d.Score > p.ask {
		d.Verdict = Refused
	} else if d.Score >= p.allow && floor == Allow {
		d.Verdict = Ask
	}
	return d
}

// scores says whether rule r matches an end of a that r's kind scores: Path, and for a move Dest too (Action.Dest).
// A read rule matches a move's end that leaves its name also when a path it matches may lie beneath that end, unless
// the end is known to be no directory (Action.PathNotDir, DestNotDir).
func scores(r compiledRule, a Action) bool {
	k := predicateKind(r.Predicate)
	if k == a.Kind && a.Dest == "" {
		return matches(r, a)
	}
	if (k != a.Kind && k != FSRead) || a.Kind != FSWrite {
		return false
	}
	write, move := k == FSWrite, a.Dest != ""
	if (write || a.Reads) && (matches(r, a) || !write && move && !a.PathNotDir && holdsMatch(&r, a.Path, a.Worktree)) {
		return true
	}
	if !move || (!write && !a.DestReads) {
		return false
	}
	a.Path = a.Dest
	return matches(r, a) || !write && !a.DestNotDir && holdsMatch(&r, a.Path, a.Worktree)
}

func matches(r compiledRule, a Action) bool {
	switch r.Predicate {
	case WriteOutsideWorktree:
		if !filepath.IsAbs(a.Path) || !filepath.IsAbs(a.Worktree) {
			return true
		}
		rel, err := filepath.Rel(a.Worktree, a.Path)
		return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
	case ReadMatches:
		if !r.read.path {
			ok, _ := filepath.Match(r.Argument, filepath.Base(a.Path))
			return ok
		}
		name, ok := r.read.target(a.Path, a.Worktree)
		if !ok {
			return false
		}
		return r.read.match(name)
	case ExecMatches:
		// The command reading first (ADR 0048 (5)): any interpretation of the pattern's tool that it matches. An
		// interpretation overflow (the ViaOverflow sentinel: a dispatch past the depth bound, or more readings than the
		// count holds) means a reading the matcher dropped may reach the pattern's tool, so the action is scored as
		// matching every command pattern, the worst case of what was not read, as Decide refuses it.
		if r.cmd != nil {
			for i := range a.invs {
				if a.invs[i].Via == execmatch.ViaOverflow {
					return true
				}
				if a.invs[i].Tool == r.cmd.Tool && r.cmd.Match(&a.invs[i]) != execmatch.MatchNone {
					return true
				}
			}
		}
		// Match each copied name conservatively. argv[0] may add an escalation,
		// but cannot remove a match on the requested or resolved executable.
		for _, command := range a.commands {
			if !strings.ContainsAny(r.Argument, "*?[") {
				if command == r.pattern || strings.HasPrefix(command, r.pattern+" ") {
					return true
				}
			} else {
				ok, _ := filepath.Match(r.pattern, command)
				if ok {
					return true
				}
			}
		}
		return false
	case NetUndeclared:
		return !a.Declared
	case NetTo:
		if a.Port != r.port {
			return false
		}
		if canonicalHost(a.Host) == r.host {
			return true
		}
		for _, host := range a.Hosts {
			if canonicalHost(host) == r.host {
				return true
			}
		}
		return a.here && r.namesThisHost(a.ThisHost)
	}
	return false
}
