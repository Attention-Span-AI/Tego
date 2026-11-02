// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"path"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// facts is what a compiled table says about enforcement at one tier; nil for a view built from text.
type facts struct {
	rt      *agent.RuleTable
	tier    backend.Tier
	best    map[string]bool
	observe bool
	held    bool       // the run holds its reads (ReadsHeldAt), so a shadowed deny_read is refused all the same
	exec    *execNames // what a run's lines call each program entry
}

func newFacts(rt *agent.RuleTable, tier backend.Tier, planeMode string) *facts {
	if tier == "" {
		tier = rt.Tier
	}
	f := &facts{rt: rt, tier: tier, best: map[string]bool{}, observe: tier == backend.TierObserve, exec: newExecNames(rt)}
	for _, c := range rt.BestEffortCellsAt(tier, planeMode) {
		f.best[c] = true
	}
	f.held = rt.ReadsHeldAt(tier)
	return f
}

// keys is the ledger rule key a declared entry's lines carry and the further keys its hits come under. A compiled
// table names an exec.allow entry's lines after the rule of the file it resolved to, and its tool's helper images
// after theirs (execNames); every other entry, and every entry of a view built from text, is named by its text
// (ruleKey).
func (f *facts) keys(key string, it item) (string, []string) {
	if f != nil && key == kExecAllow {
		return f.exec.allowKeys(it)
	}
	return ruleKey(key, it.entry), nil
}

// repeats reports whether an exec.allow entry stands for the command's own rule, so that a row for the command
// would only say that entry again: in a compiled table, an entry that resolved to the command's rule (cmd, its
// index); in a view built from text, or for an entry the table cannot place, one whose text gives the command's key.
// An entry with words never does: the command is granted with any words (ADR 0048 (1)), which such an entry does not
// say.
func (f *facts) repeats(items []item, cmd int, key string) bool {
	for _, it := range items {
		if withWords(it.entry) {
			continue
		}
		if f != nil && cmd >= 0 {
			if i, ok := f.exec.ofAllow(it); ok {
				if i == cmd {
					return true
				}
				continue
			}
		}
		if ruleKey(kExecAllow, it.entry) == key {
			return true
		}
	}
	return false
}

// home is the directory ~ stands for, "" without a table.
func (f *facts) home() string {
	if f == nil {
		return ""
	}
	return f.rt.Home
}

// claim is how a rule is enforced: ok is the full claim, text says it. With no facts there is no claim.
type claim struct {
	ok   bool
	text string
}

func (f *facts) at(c claim) (bool, string) {
	if f == nil {
		return false, ""
	}
	if f.observe {
		return false, textObserve
	}
	return c.ok, c.text
}

// kernel is the claim of a rule the kernel decides at the run's tier.
var kernel = claim{true, textKernel}

// connect is the claim of a net rule: at tier landlock tego decides each connection, above it the kernel does.
func (f *facts) connect() claim {
	if f != nil && f.tier == backend.TierLandlock {
		return claim{true, textTegoConnect}
	}
	return kernel
}

// denyRead is the claim of a deny_read entry: unenforced when a write entry shadows it at tier landlock, unless the
// run holds its reads (ADR 0069), which refuses it all the same.
func (f *facts) denyRead(raw string) claim {
	if f == nil {
		return claim{}
	}
	for i := range f.rt.FS {
		r := &f.rt.FS[i]
		if r.Kind == agent.FSDenyRead && !r.AskRead && r.Raw == raw && r.Unenforced && f.tier == backend.TierLandlock {
			if f.held {
				return claim{true, textTegoRead}
			}
			return claim{false, textShadowed}
		}
	}
	return kernel
}

// builtInDenyRead is the built-in secret list's ledger rule keys and its claim.
func (f *facts) builtInDenyRead() (keys []string, c claim) {
	c = kernel
	if f == nil {
		return nil, c
	}
	seen := map[string]bool{}
	for i := range f.rt.FS {
		r := &f.rt.FS[i]
		if r.Kind != agent.FSDenyRead || !r.BuiltIn {
			continue
		}
		if k := r.RuleName(); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
		if r.Unenforced && f.tier == backend.TierLandlock {
			if f.held {
				c = claim{true, textTegoRead}
			} else {
				c = claim{false, textShadowed}
			}
		}
	}
	return keys, c
}

// builtInDenyWrite reports whether the table holds built-in deny_write targets, their rule keys and their claim.
func (f *facts) builtInDenyWrite() (present bool, keys []string, c claim) {
	if f == nil {
		return false, nil, claim{}
	}
	seen := map[string]bool{}
	for i := range f.rt.DenyWrite {
		r := &f.rt.DenyWrite[i]
		if r.IsDeclaredDenyWrite() {
			continue
		}
		present = true
		if k := r.RuleName(); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if f.best[agent.BestEffortDenyWrite] {
		return present, keys, claim{false, textBestEffort}
	}
	return present, keys, kernel
}

// build turns what a contract declares into the view, with the table's facts when there are some.
func build(d decl, f *facts) View {
	v := newView()
	v.Agent = d.name
	v.ContractPath = d.file
	home := f.home()

	src := func(p agent.Pos) Source {
		if p.File == "" || p.File == d.file {
			return Source{File: d.file, Line: p.Line, Origin: OriginContract}
		}
		return Source{File: p.File, Line: p.Line, Origin: OriginProfile}
	}
	add := func(group string, r Rule) {
		r.Group = group
		if r.Source.Origin == "" {
			r.Source.Origin = OriginBuiltIn
		}
		r.Editable = r.Source.Origin == OriginContract && editableKeys[r.Key]
		r.State = stateOf(r.Enforced, r.EnforcedText)
		r.ByKernel = r.State == StateEnforced && r.EnforcedText == textKernel
		g := v.Group(group)
		g.Rules = append(g.Rules, r)
	}
	entry := func(group, key string, it item, sentence, target string, eff Effect, c claim) {
		ok, text := f.at(c)
		rk, covers := f.keys(key, it)
		add(group, Rule{
			Key: key, Entry: it.entry, RuleKey: rk, Covers: covers, Sentence: sentence,
			Target: target, Effect: eff, Enforced: ok, EnforcedText: text, Source: src(it.pos),
		})
	}

	// Can read: every file but the never-read ones; watched files are read and recorded one by one.
	for _, it := range d.lists[kFSWatch] {
		s, t := pathSentence("Can read", it.entry, home)
		entry(GroupRead, kFSWatch, it, s+"; every read is recorded", t, EffectAllow, claim{true, ""})
	}
	v.Group(GroupRead).Default = "Can read any other file on this computer, except the ones under Never reads and Always on."

	// Can change.
	for _, it := range d.lists[kFSWrite] {
		s, t := pathSentence("Can change", it.entry, home)
		entry(GroupChange, kFSWrite, it, s, t, EffectAllow, kernel)
	}
	if f != nil {
		for i := range f.rt.FS {
			r := &f.rt.FS[i]
			if r.Runtime == "" {
				continue
			}
			ok, text := f.at(kernel)
			add(GroupChange, Rule{
				Key: "runtime." + r.Runtime, RuleKey: r.RuleName(), Sentence: runtimeSentence(r.Runtime),
				Target: short(r.Path, home), Effect: EffectAllow, Enforced: ok, EnforcedText: text,
				Source: Source{Origin: OriginTego},
			})
		}
	}
	if len(d.lists[kFSWrite]) == 0 {
		v.Group(GroupChange).Default = "Cannot change any file."
	} else {
		v.Group(GroupChange).Default = "Cannot change anything else."
	}

	// Asks you first, and the never-read entries an ask_read becomes above tier landlock.
	askReadAsks := f == nil || f.tier == backend.TierLandlock || f.observe
	for _, it := range d.lists[kFSAskRead] {
		if askReadAsks {
			s, t := pathSentence("Asks you before it reads", it.entry, home)
			entry(GroupAsk, kFSAskRead, it, s, t, EffectAsk, claim{true, textHeld})
			continue
		}
		s, t := pathSentence("Can never read", it.entry, home)
		entry(GroupNeverRead, kFSAskRead, it, s, t, EffectDeny, claim{true, textAskReadTier})
	}
	for _, it := range d.lists[kFSAsk] {
		s, t := pathSentence("Asks you before it changes", it.entry, home)
		entry(GroupAsk, kFSAsk, it, s, t, EffectAsk, claim{true, textHeld})
	}
	for _, it := range d.lists[kNetAsk] {
		entry(GroupAsk, kNetAsk, it, "Asks you before it connects to "+netTarget(it.entry), it.entry, EffectAsk, claim{true, textHeld})
	}

	// Never reads.
	for _, it := range d.lists[kFSDenyRead] {
		s, t := pathSentence("Can never read", it.entry, home)
		entry(GroupNeverRead, kFSDenyRead, it, s, t, EffectDeny, f.denyRead(it.entry))
	}

	// Never changes.
	userDW := claim{true, textKernel}
	if f != nil && f.best[agent.BestEffortUserDenyWrite] {
		userDW = claim{false, textBestEffort}
	}
	for _, it := range d.lists[kFSDenyWrite] {
		s, t := pathSentence("Can never change", it.entry, home)
		entry(GroupNeverChange, kFSDenyWrite, it, s, t, EffectDeny, userDW)
	}

	buildPrograms(&v, d, f, add, entry)
	buildNetwork(&v, d, f, add, src, entry)
	buildGate(&v, d, f, add, src)
	buildEnv(&v, d, f, entry)

	// The questions' last line, once the gate's are listed too: they wait as long.
	if g := v.Group(GroupAsk); len(g.Rules) > 0 {
		wait := "a few minutes"
		if d.askTimeout != "" {
			wait = human(d.askTimeout)
		} else if f != nil && f.rt.AskConfig != nil && f.rt.AskConfig.Timeout > 0 {
			wait = human(f.rt.AskConfig.Timeout.String())
		}
		g.Default = "If you do not answer within " + wait + ", the answer is no."
		if d.askAlways {
			g.Default = "If you do not answer within " + wait + ", the answer is no for the rest of the run."
		}
	}

	buildLimits(d, f, add, src)
	if len(d.limits) == 0 {
		v.Group(GroupLimits).Default = "No limits of its own: this computer's defaults apply."
	}

	buildAlwaysOn(&v, d, f, add, src)

	if len(d.extends) > 0 {
		if f != nil {
			v.Notes = append(v.Notes, "Includes the rules of "+strings.Join(d.extends, ", ")+"; their entries are marked as from a profile.")
		} else {
			v.Notes = append(v.Notes, "Builds on "+strings.Join(d.extends, ", ")+", whose rules are not shown here.")
		}
	}
	if d.mcp > 0 {
		v.Notes = append(v.Notes, "Its MCP servers' own rules are not listed here.")
	}
	return v
}

// buildPrograms fills the programs group.
func buildPrograms(v *View, d decl, f *facts, add func(string, Rule), entry func(string, string, item, string, string, Effect, claim)) {
	home := f.home()
	g := v.Group(GroupPrograms)
	if len(d.command) > 0 {
		name := path.Base(d.command[0])
		ok, text := f.at(kernel)
		// A run names the command's rule as the command is written (agent.ExecRule.RuleName of its Raw): /bin/sh is
		// exec[/bin/sh], ./agent.sh exec[./agent.sh]. A compiled table's file names replace it below.
		r := Rule{
			Key: "command", Entry: d.command[0], RuleKey: "exec[" + d.command[0] + "]", Sentence: "Can run " + name + ", the command it starts with",
			Target: name, Effect: EffectAllow, Enforced: ok, EnforcedText: text,
			Source: Source{File: d.file, Line: d.cmdPos.Line, Origin: OriginContract},
		}
		cmd := -1
		if f != nil {
			if cmd = commandRule(f.rt); cmd >= 0 {
				if k, c, ok := f.exec.keys(cmd); ok {
					r.RuleKey, r.Covers = k, c
				}
			}
		}
		if !f.repeats(d.lists[kExecAllow], cmd, r.RuleKey) {
			add(GroupPrograms, r)
		}
	}
	if f != nil && f.rt.RunCommandGrant != "" {
		name := path.Base(f.rt.RunCommandGrant)
		ok, text := f.at(kernel)
		r := Rule{
			Key: "run-command", Entry: f.rt.RunCommandGrant, RuleKey: "exec[" + name + "]",
			Sentence: "Can run " + name + ", the command this run was started with", Target: name,
			Effect: EffectAllow, Enforced: ok, EnforcedText: text, Source: Source{Origin: OriginCommandLine},
		}
		for i := range f.rt.Exec {
			if f.rt.Exec[i].Path != f.rt.RunCommandGrant {
				continue
			}
			if k, c, ok := f.exec.keys(i); ok {
				r.RuleKey, r.Covers = k, c
			}
		}
		add(GroupPrograms, r)
	}
	words := claim{true, textKernel}
	if f != nil && f.best[agent.BestEffortExecRules] {
		words = claim{false, textTegoCommands}
	}
	for _, it := range d.lists[kExecAllow] {
		s, t := programSentence("Can run", it.entry, home)
		c := kernel
		if withWords(it.entry) { // as compile reads it: a quoted path with a space is one word, a tab splits words
			c = words
		}
		entry(GroupPrograms, kExecAllow, it, s, t, EffectAllow, c)
	}
	// exec.deny and exec.ask entries are command rules: tego decides them on its copy of the command's words, so
	// they are best effort wherever exec.allow's words are (ADR 0048 (6)).
	for _, it := range d.lists[kExecDeny] {
		s, t := programSentence("Can never run", it.entry, home)
		entry(GroupPrograms, kExecDeny, it, s, t, EffectDeny, words)
	}
	// exec.ask is reserved: every match is refused at every tier until ADR 0044 gives it a way to ask, so it is a
	// refusal here and never a question in "Asks you first" (no approval card, no timeout).
	reserved := claim{words.ok, textExecAskReserved}
	if !words.ok {
		reserved.text = textExecAskReservedBest
	}
	for _, it := range d.lists[kExecAsk] {
		s, t := programSentence("Can never run", it.entry, home)
		entry(GroupPrograms, kExecAsk, it, s+" (asking first is not supported yet)", t, EffectDeny, reserved)
	}
	switch {
	case !d.hasExec:
		g.Default, g.Open = "Can run any program.", true
	case d.execAllowKey:
		g.Default = "Cannot run any other program."
	default:
		g.Default, g.Open = "Can run any other program.", true
	}
}

// buildNetwork fills the network group.
func buildNetwork(v *View, d decl, f *facts, add func(string, Rule), src func(agent.Pos) Source,
	entry func(string, string, item, string, string, Effect, claim)) {
	for _, it := range d.lists[kModels] {
		entry(GroupNetwork, kModels, it, "Can reach its model service at "+netTarget(it.entry), it.entry, EffectAllow, f.connect())
	}
	for _, it := range d.lists[kNetAllow] {
		verb := "Can connect to "
		if strings.HasPrefix(it.entry, "unix:") {
			verb = "Can use "
		}
		entry(GroupNetwork, kNetAllow, it, verb+netTarget(it.entry), it.entry, EffectAllow, f.connect())
	}
	for _, it := range d.lists[kNetListen] {
		entry(GroupNetwork, kNetListen, it, "Can accept connections on "+netTarget(it.entry), it.entry, EffectAllow, f.connect())
	}
	// net.http: the requests tego's model proxy sends on to a model service, decided on each request it holds.
	for i, h := range d.http {
		r := Rule{Key: kNetHTTP, Entry: h.host, Sentence: httpSentence(h), Target: h.host, Effect: EffectAllow, Source: src(h.pos)}
		if len(h.allow) == 0 {
			r.Effect = EffectNote // it grants nothing, so it allows and claims nothing
		} else {
			r.Enforced, r.EnforcedText = f.at(claim{true, textTegoRequest})
		}
		if f != nil || len(d.extends) == 0 { // read as text, a profile's entries would come first
			r.RuleKey = kNetHTTP + "[" + strconv.Itoa(i) + "]"
		}
		add(GroupNetwork, r)
	}
	// net.ingress: the sources a listener accepts, which the run's kernel programs admit packet by packet. No ledger
	// line names an ingress rule: a packet they refuse only adds to a counter (run_end's network refusals, "ingress"),
	// and one they admit is not recorded, so the rows carry no rule key and count no hits.
	for _, in := range d.ingress {
		r := Rule{Key: kNetIngress, Entry: in.from + " -> " + in.to, Target: in.to, Effect: EffectAllow, Source: src(in.pos),
			Sentence: "Can accept connections on " + netTarget(in.to) + " from " + fromPhrase(in.from)}
		r.Enforced, r.EnforcedText = f.at(kernel)
		add(GroupNetwork, r)
	}
	g := v.Group(GroupNetwork)
	switch {
	case d.hasNet && len(g.Rules) == 0:
		g.Default = "Cannot connect anywhere."
	case d.hasNet:
		g.Default = "Cannot connect anywhere else."
	case d.hostSockets:
		g.Default, g.Open = "Can connect anywhere, other programs' local sockets included.", true
	default:
		g.Default, g.Open = "Can connect to any address. Other programs' local sockets stay closed (see Always on).", true
	}
	if len(d.http) > 0 {
		g.Default += " Every other request to its model services is refused."
	}
	if d.ingressKey {
		g.Default += " Nothing else can connect to its listeners."
	}
	// At tier landlock tego decides each datagram on the address it copied and lets the agent's own call send one it
	// does not refuse (supervisor R13b): a sibling thread can change the address between the two, so the refusal of
	// every other destination is best effort for datagrams. Under a net: section that holds for every run of the tier,
	// whatever its entries admit (racesDatagrams).
	if d.hasNet && f.racesDatagrams() {
		ok, text := f.at(claim{false, textDatagram})
		add(GroupNetwork, Rule{Key: "built-in.datagrams", Sentence: "Cannot send datagrams anywhere it may not connect",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	}
}

// racesDatagrams reports whether a run under a net: section can race a datagram past tego's decision: at tier
// landlock, every run, whatever its entries admit. The socket allowlist admits a UDP and a local datagram socket under
// every net: section (enforce-landlock's socket(2) arm), and a sendmsg that names no address is continued undecided
// (supervisor R13b, sendUnaddressed; relayed only on an IP socket under the models[] guard or a net gate), so a sibling
// that writes an address in before the kernel copies the header sends where nothing decided. An addressed datagram
// is continued once admitted, too: by an entry, the machine's resolver (net.dns mode system), the DNS broker's socket
// the runtime grants at launch (mode broker), or a socket the run bound beneath a write entry (supervisor R11a), the
// last two in no compiled table. Landlock refuses a raced datagram itself only from ABI 10 for a UDP port no entry
// declares, from ABI 9 for a pathname socket outside the run's places and from ABI 6 for an abstract name bound
// outside the run, which this view, given no kernel, does not count on. Not in an observe run, which refuses
// nothing, nor read as text, which names no tier.
//
// Not at tiers cgroup and bpflsm, whose cgroup sendmsg programs, which every such run attaches, decide a UDP datagram
// on the kernel's own copy. A local socket's datagram is not wholly theirs: below Landlock ABI 9 one to a relative
// name, which their unix programs leave to tier 1, or to a name that leads elsewhere stays the supervisor's best
// effort there, and so does every one on a kernel those programs do not load on (before 6.7) where no decision plane
// decides it (enforce-cgroup-observe §5). This view does not list that residual yet: which runs it holds for turns on
// the run's attached hooks (run_start.net_guarantees) and Landlock ABI, which Of is not given.
func (f *facts) racesDatagrams() bool {
	return f != nil && f.tier == backend.TierLandlock
}

// httpSentence says a net.http entry: "Can send POST requests to api.example.com under /v1/messages". An entry whose
// allow list is empty grants nothing (httppolicy.Compile).
func httpSentence(h httpRule) string {
	what := "requests"
	if len(h.methods) > 0 {
		what = strings.Join(h.methods, ", ") + " requests"
	}
	if len(h.allow) == 0 {
		return "Can send no " + what + " to " + h.host + " by this entry (its allow list is empty)"
	}
	for _, p := range h.allow {
		if strings.TrimSuffix(p, "/") == "" {
			return "Can send " + what + " to " + h.host + " at any path"
		}
	}
	return "Can send " + what + " to " + h.host + " under " + strings.Join(h.allow, ", ")
}

// gateCells are the best-effort cells (ADR 0041 D1) of a gate predicate's decisions: where the run lists one, the
// rule's score rests on copied syscall facts a program built to race tego could change.
var gateCells = map[gate.Predicate][]string{
	gate.ReadMatches:          {agent.BestEffortGateFSReadOpen, agent.BestEffortGateFSReadMove, agent.BestEffortGateFSReadOPath},
	gate.WriteOutsideWorktree: {agent.BestEffortGateFSWriteOpen, agent.BestEffortGateFSWriteMutation},
	gate.ExecMatches:          {agent.BestEffortGateExec},
	gate.NetUndeclared:        {agent.BestEffortGateNetUnixDatagram, agent.BestEffortGateNetUnixConnect},
}

// buildGate lists the gate's scored rules (agent-contract R22a), with the rule keys its lines carry (gate.rules[i]).
// Scores only add up, so each rule is listed where its score alone puts an action it matches: above the ask threshold
// among the refusals of its kind; from the allow threshold among the questions, save a command, which tego cannot hold
// to ask about and refuses; below it as what it adds, among the questions, save a command's, which can only bring a
// refusal nearer and is listed among the programs. A question is held until you answer and a refusal scored before
// the action happens, each best effort where the run lists a best-effort cell of its kind (gateCells). A note says how
// the scores add up.
func buildGate(v *View, d decl, f *facts, add func(string, Rule), src func(agent.Pos) Source) {
	if d.gateBad {
		v.Notes = append(v.Notes, "Its gate: section does not read as a gate, so its risk scores are not listed.")
	}
	rules := d.gate.Rules()
	if len(rules) == 0 {
		return
	}
	allow, ask := d.gate.Thresholds()
	home := f.home()
	for i, gr := range rules {
		base, third, group, target := gateWords(gr, home)
		score := strconv.Itoa(gr.Score)
		r := Rule{Key: "gate.rules", Entry: gr.Text(), Target: target}
		switch {
		case gr.Score > ask:
			r.Effect, r.Sentence = EffectDeny, "Can never "+base+" (risk score "+score+")"
		case gr.Score >= allow && gr.Predicate == gate.ExecMatches:
			group, r.Effect = GroupPrograms, EffectDeny
			r.Sentence = "Can never " + base + " (risk score " + score + ": asking first is not supported yet)"
		case gr.Score >= allow:
			group, r.Effect, r.Sentence = GroupAsk, EffectAsk, "Asks you before it "+third+" (risk score "+score+")"
		case gr.Predicate == gate.ExecMatches: // tego never asks before a program runs (gate.md R4)
			group, r.Effect, r.Sentence = GroupPrograms, EffectNote, "Adds "+score+" to the risk score when it "+third
		default:
			group, r.Effect, r.Sentence = GroupAsk, EffectNote, "Adds "+score+" to the risk score when it "+third
		}
		if r.Effect != EffectNote {
			best := false
			for _, cell := range gateCells[gr.Predicate] {
				best = best || (f != nil && f.best[cell])
			}
			var c claim
			switch {
			case r.Effect == EffectAsk && best:
				c = claim{false, textHeldBest}
			case r.Effect == EffectAsk:
				c = claim{true, textHeld}
			case best:
				c = claim{false, textBestEffort}
			default:
				c = claim{true, textGate}
			}
			r.Enforced, r.EnforcedText = f.at(c)
		}
		if f != nil || len(d.extends) == 0 { // read as text, a profile's rules would come first
			r.RuleKey = "gate.rules[" + strconv.Itoa(i) + "]"
		}
		var p agent.Pos
		if i < len(d.gatePos) {
			p = d.gatePos[i]
		}
		r.Source = src(p)
		add(group, r)
	}
	v.Notes = append(v.Notes, "Its gate adds up the risk scores of the rules an action matches: from "+strconv.Itoa(allow)+
		" it asks you first, above "+strconv.Itoa(ask)+" it is refused, and what tego cannot hold to ask about (a program, "+
		"a file deleted or moved, a datagram) is refused instead.")
}

// gateWords says a gate predicate as an action, base for "Can never …" and third for "Asks you before it …", with the
// group of its refusals and its target.
func gateWords(r gate.Rule, home string) (base, third, group, target string) {
	switch r.Predicate {
	case gate.WriteOutsideWorktree:
		return "change a file outside its worktree", "changes a file outside its worktree", GroupNeverChange, ""
	case gate.ReadMatches:
		p := short(r.Argument, home)
		return "read a file matching " + p, "reads a file matching " + p, GroupNeverRead, p
	case gate.ExecMatches:
		return "run a command matching " + r.Argument, "runs a command matching " + r.Argument, GroupPrograms, r.Argument
	case gate.NetUndeclared:
		return "connect to a host its rules do not name", "connects to a host its rules do not name", GroupNetwork, ""
	case gate.NetTo:
		return "connect to " + netTarget(r.Argument), "connects to " + netTarget(r.Argument), GroupNetwork, r.Argument
	}
	return "do what " + r.Text() + " names", "does what " + r.Text() + " names", GroupAsk, ""
}

// fromPhrase says an ingress source: a literal address as written, a prefix as the addresses in it.
func fromPhrase(from string) string {
	if strings.Contains(from, "/") {
		return "addresses in " + from
	}
	return from
}

// buildEnv fills the env group with names only: no value of env.set reaches the view.
func buildEnv(v *View, d decl, f *facts, entry func(string, string, item, string, string, Effect, claim)) {
	removed := map[string]bool{}
	if f != nil && f.rt.Env != nil {
		kept := map[string]bool{}
		for _, n := range f.rt.Env {
			kept[n] = true
		}
		for _, it := range d.lists[kEnvPass] {
			if !kept[it.entry] {
				removed[it.entry] = true
			}
		}
	}
	for _, it := range d.lists[kEnvPass] {
		if removed[it.entry] {
			entry(GroupEnv, kEnvPass, it, "Does not get "+it.entry+" from your shell: tego sets it for the run", it.entry, EffectDeny, claim{true, textEnvRemoved})
			continue
		}
		entry(GroupEnv, kEnvPass, it, "Gets "+it.entry+" from your shell", it.entry, EffectAllow, claim{true, textEnvRemoved})
	}
	for _, it := range d.lists[kEnvSet] {
		entry(GroupEnv, kEnvSet, it, "Gets "+it.entry+", set in its rules", it.entry, EffectAllow, claim{true, ""})
	}
	for _, it := range d.lists[kEnvDeny] {
		entry(GroupEnv, kEnvDeny, it, "Never gets "+it.entry, it.entry, EffectDeny, claim{true, textEnvRemoved})
	}
	g := v.Group(GroupEnv)
	if d.envPassKey {
		g.Default = "Every other variable in your shell, secrets included, is removed before it starts."
	} else {
		g.Default, g.Open = "Gets every variable in your shell, secrets included.", true
	}
}

// buildLimits fills the limits group. Read as text, each limit is as written. Compiled, each is what the table holds,
// the contract's value clamped to this computer's ceilings (agent-contract R11): a limit a ceiling lowers says the
// lower value and the one its rules ask for, and a limit only a ceiling sets is listed after the contract's, from the
// machine config. Limits make no enforcement claim.
func buildLimits(d decl, f *facts, add func(string, Rule), src func(agent.Pos) Source) {
	declared := map[string]bool{}
	for _, l := range d.limits {
		declared[l.key] = true
		s := limitSentence(l.key, l.value)
		if v, ok := f.limit(l.key); ok && v != l.value {
			s = limitSentence(l.key, v) + ", this computer's limit; its rules ask for " + limitAmount(l.key, l.value)
		}
		add(GroupLimits, Rule{Key: "limits." + l.key, Entry: l.value, Sentence: s, Effect: EffectLimit, Source: src(l.pos)})
	}
	for _, k := range limitKeys {
		if v, ok := f.limit(k); ok && !declared[k] {
			add(GroupLimits, Rule{Key: "limits." + k, Entry: v, Sentence: limitSentence(k, v), Effect: EffectLimit,
				Source: Source{Origin: OriginMachine}})
		}
	}
}

// limit is the run's budget on limits key k as the table holds it, spelled as the contract spells it ("2h", "4GiB");
// ok is false without a table or when neither the contract nor a ceiling bounds it.
func (f *facts) limit(k string) (v string, ok bool) {
	if f == nil {
		return "", false
	}
	l := f.rt.Limits
	switch k {
	case "wall":
		return agent.Duration(l.Wall).String(), l.Bounded(agent.BudgetWall)
	case "tokens":
		return strconv.FormatInt(l.Tokens, 10), l.Bounded(agent.BudgetTokens)
	case "cost_usd":
		return strconv.FormatFloat(l.CostUSD, 'f', -1, 64), l.Bounded(agent.BudgetCostUSD)
	case "memory":
		return agent.ByteSize(l.MemoryB).String(), l.Bounded(agent.BudgetMemory)
	case "memory_high":
		return agent.ByteSize(l.MemoryHigh).String(), l.Bounded(agent.BudgetMemoryHigh)
	case "pids":
		return strconv.Itoa(l.Pids), l.Bounded(agent.BudgetPids)
	case "cpu":
		return l.CPU, l.Bounded(agent.BudgetCPU)
	case "cpu_weight":
		return strconv.Itoa(l.CPUWeight), l.Bounded(agent.BudgetCPUWeight)
	case "stall_after":
		return agent.Duration(l.StallAfter).String(), l.Bounded(agent.BudgetStallAfter)
	case "repeats":
		return strconv.Itoa(l.Repeats), l.Bounded(agent.BudgetRepeats)
	}
	return "", false
}

// buildAlwaysOn fills the always-on group: the protections no contract line writes.
func buildAlwaysOn(v *View, d decl, f *facts, add func(string, Rule), src func(agent.Pos) Source) {
	at := func(c claim) (bool, string) { return f.at(c) }
	if d.denyReadOff {
		add(GroupAlwaysOn, Rule{
			Key: kFSDenyRead, Sentence: "The usual secret files are NOT protected: this file turns that list off (deny_read: [])",
			Effect: EffectAllow, Source: src(d.denyReadPos),
		})
	} else {
		keys, c := f.builtInDenyRead()
		ok, text := at(c)
		r := Rule{
			Key: "built-in.deny_read", Sentence: "Can never read the usual secret files: SSH and cloud keys, browser profiles, .env files and similar",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text,
		}
		if len(keys) > 0 {
			r.RuleKey, r.Covers = keys[0], keys[1:]
		}
		add(GroupAlwaysOn, r)
	}
	// The built-in deny_write set holds only the files of its kinds a compile finds beneath the write entries (R20): a
	// compiled view lists it when compile found some, and a view read as text, which cannot look, says that condition.
	if present, keys, c := f.builtInDenyWrite(); present || (f == nil && len(d.lists[kFSWrite]) > 0) {
		ok, text := at(c)
		r := Rule{
			Key: "built-in.deny_write", Sentence: "Can never change files that would run code outside the agent: git hooks, shell startup files and agent settings",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text,
		}
		if f == nil {
			r.Sentence += ", where a run finds any in the folders it can change"
		}
		if len(keys) > 0 {
			r.RuleKey, r.Covers = keys[0], keys[1:]
		}
		add(GroupAlwaysOn, r)
	}
	ok, text := at(kernel)
	add(GroupAlwaysOn, Rule{Key: "built-in.own-records", Sentence: "Can never read or change tego's records of its runs", Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	add(GroupAlwaysOn, Rule{Key: "built-in.contract", Sentence: "Cannot change its own rules file", Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	if !d.hasNet {
		if d.hostSockets {
			add(GroupAlwaysOn, Rule{Key: "host_sockets", Sentence: "Can reach other programs on this computer through their local sockets (host_sockets: true)", Effect: EffectAllow})
		} else {
			c := kernel
			if f != nil && (f.best[agent.BestEffortHostSocketsDatagram] || f.best[agent.BestEffortHostSocketsRoot]) {
				c = claim{false, textBestEffort}
			}
			ok, text := at(c)
			add(GroupAlwaysOn, Rule{
				Key: "built-in.host-sockets", RuleKey: "host-sockets",
				Sentence: "Cannot reach other programs on this computer through their local sockets (Docker, ssh-agent, the desktop bus)",
				Effect:   EffectDeny, Enforced: ok, EnforcedText: text,
			})
		}
	}
	// Every contract, and no key turns it off: a route socket's read reaches the kernel by calls no filter sees, so a key
	// could not keep the promise (ADR 0128). It is the one thing here a run gets rather than is kept from.
	add(GroupAlwaysOn, Rule{Key: "built-in.route-read", RuleKey: "route-query",
		Sentence: "Can read this computer's network setup: interface names and addresses, routes, and the nearby machines it has talked to",
		Effect:   EffectAllow})
	if d.setuid {
		add(GroupAlwaysOn, Rule{Key: "setuid", Sentence: "Can gain root through sudo or other setuid programs (setuid: true)", Effect: EffectAllow})
	} else {
		add(GroupAlwaysOn, Rule{Key: "built-in.no-setuid", Sentence: "Cannot gain root through sudo or other setuid programs", Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	}
	switch d.record {
	case "off":
		add(GroupAlwaysOn, Rule{Key: "record", Sentence: "Keeps no record of what it does beyond the run's start and end", Effect: EffectNote})
	case "full":
		add(GroupAlwaysOn, Rule{Key: "record", Sentence: "Writes every action to a record that cannot be changed unnoticed", Effect: EffectNote})
	default:
		add(GroupAlwaysOn, Rule{Key: "record", Sentence: "Writes every refusal and question to a record that cannot be changed unnoticed, and a summary of the rest", Effect: EffectNote})
	}
	// Record and the opt-outs above make no enforcement claim.
	g := v.Group(GroupAlwaysOn)
	for i := range g.Rules {
		if g.Rules[i].Effect == EffectNote || g.Rules[i].Effect == EffectAllow {
			g.Rules[i].Enforced, g.Rules[i].EnforcedText, g.Rules[i].State, g.Rules[i].ByKernel = false, "", StateNone, false
		}
	}
}

// runtimeSentence says a grant the runtime made for this run.
func runtimeSentence(kind string) string {
	switch kind {
	case agent.CodexHomeGrant:
		return "Can change the Codex home folder tego made for this run"
	case agent.HarnessStateGrant:
		return "Can change the folder tego made for the agent's hooks"
	}
	return "Can change a folder tego made for this run"
}

// ruleKey is the ledger rule key a declared entry's events carry, read from its text (agent.FSRule.RuleName and the
// others name a declared entry by its text): fs.write[./tmp/], fs.ask_read[...], exec[git], net[tcp://chatgpt.com:443],
// exec.deny[git push] (execmatch Pattern.Rule). An exec.allow entry is named by its program: an allowed exec carries
// its program's rule, so "git status" is exec[git] (the entry is in the line's command_rule), and a quoted path is
// named without its quotes. In a compiled table an exec.allow entry takes the name of the rule it resolved to
// instead (execNames), which may be another entry's spelling.
func ruleKey(key, entry string) string {
	switch key {
	case kFSWrite, kFSAsk, kFSDenyRead, kFSAskRead, kFSDenyWrite, kFSWatch:
		return key + "[" + entry + "]"
	case kExecAllow:
		return "exec[" + programWord(entry) + "]"
	case kExecDeny, kExecAsk:
		return key + "[" + entry + "]"
	case kNetAllow, kNetAsk:
		return "net[" + entry + "]"
	}
	return ""
}

// defaultKinds are the ledger line kinds whose unmatched lines a group's default decides (Group.DefaultKind): every
// exec no rule names is the programs default's, every connect, datagram, bind and listen the network default's.
var defaultKinds = map[string]string{GroupPrograms: string(record.KindExec), GroupNetwork: string(record.KindNet)}

// newView is a view with every group, in order, and its copy.
func newView() View {
	v := View{Groups: make([]Group, 0, len(GroupOrder))}
	for _, id := range GroupOrder {
		c := groupCopy[id]
		v.Groups = append(v.Groups, Group{ID: id, Title: c[0], Lede: c[1], DefaultKind: defaultKinds[id]})
	}
	return v
}
