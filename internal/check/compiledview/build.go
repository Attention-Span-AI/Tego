// SPDX-License-Identifier: Apache-2.0

package compiledview

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
	Tier    backend.Tier
	best    map[string]bool
	observe bool
	plane   bool
	held    bool       // the run holds its reads (ReadsHeldAt), so a shadowed deny_read is refused all the same
	exec    *execNames // what a run's lines call each program entry
}

func newFacts(rt *agent.RuleTable, tier backend.Tier, planeMode string) *facts {
	if tier == "" {
		tier = rt.Tier
	}
	f := &facts{rt: rt, Tier: tier, best: map[string]bool{}, observe: tier == backend.TierObserve, exec: NewExecNames(rt)}
	for _, c := range rt.BestEffortCellsAt(tier, planeMode) {
		f.best[c] = true
	}
	f.plane = (tier == backend.TierCgroup || tier == backend.TierBPFLSM) && (planeMode == record.DecisionPlaneLSM || planeMode == record.DecisionPlaneFmodRet)
	f.held = rt.ReadsHeldAt(tier)
	return f
}

// keys is the ledger rule key a declared entry's lines carry and the further keys its hits come under. A compiled
// table names an exec.allow entry's lines after the rule of the file it resolved to, and its tool's helper images
// after theirs (execNames); every other entry, and every entry of a view built from text, is named by its text
// (ruleKey).
func (f *facts) keys(key string, it Item) (string, []string) {
	if f != nil && key == kExecAllow {
		return f.exec.allowKeys(it)
	}
	return RuleKey(key, it.Entry), nil
}

// repeats reports whether an exec.allow entry stands for the command's own rule, so that a row for the command
// would only say that entry again: in a compiled table, an entry that resolved to the command's rule (cmd, its
// index); in a view built from text, or for an entry the table cannot place, one whose text gives the command's key.
// An entry with words never does: the command is granted with any words (ADR 0048 (1)), which such an entry does not
// say.
func (f *facts) repeats(items []Item, cmd int, key string) bool {
	for _, it := range items {
		if withWords(it.Entry) {
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
		if RuleKey(kExecAllow, it.Entry) == key {
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
		return false, TextObserve
	}
	return c.ok, c.text
}

// kernel is the claim of a rule the kernel decides at the run's tier.
var kernel = claim{true, TextKernel}

// connect is the claim of a net rule: at tier landlock tego decides each connection, above it the kernel does.
func (f *facts) connect() claim {
	if f != nil && f.Tier == backend.TierLandlock {
		return claim{true, TextTegoConnect}
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
		if r.Kind == agent.FSDenyRead && !r.AskRead && r.Raw == raw && r.Unenforced && f.Tier == backend.TierLandlock {
			if f.held {
				return claim{true, TextTegoRead}
			}
			return claim{false, TextShadowed}
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
		if r.Kind != agent.FSDenyRead || !r.BuiltIn || r.BuiltinRule != "" {
			continue
		}
		if k := r.RuleName(); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
		if r.Unenforced && f.Tier == backend.TierLandlock {
			if f.held {
				c = claim{true, TextTegoRead}
			} else {
				c = claim{false, TextShadowed}
			}
		}
	}
	return keys, c
}

// hasStandardDevices reports whether the table holds a row for a standard data device (agent.FSRule.StdDevice).
func (f *facts) hasStandardDevices() bool {
	if f == nil {
		return false
	}
	for i := range f.rt.FS {
		if f.rt.FS[i].IsStandardDevice() {
			return true
		}
	}
	return false
}

// builtInDenyWrite reports whether the table holds built-in deny_write targets, their rule keys and their claim.
func (f *facts) builtInDenyWrite() (present bool, keys []string, c claim) {
	if f == nil {
		return false, nil, claim{}
	}
	seen := map[string]bool{}
	for i := range f.rt.DenyWrite {
		r := &f.rt.DenyWrite[i]
		if r.IsDeclaredDenyWrite() || r.BuiltinRule != "" {
			continue
		}
		present = true
		if k := r.RuleName(); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if f.best[agent.BestEffortDenyWrite] {
		return present, keys, claim{false, TextBestEffort}
	}
	return present, keys, kernel
}

// build turns what a contract declares into the view, with the table's facts when there are some.
func build(d Declaration, f *facts) View {
	v := New()
	v.Agent = d.Name
	v.ContractPath = d.File
	home := f.home()

	src := func(p agent.Pos) Source {
		if p.File == "" || p.File == d.File {
			return Source{File: d.File, Line: p.Line, Origin: OriginContract}
		}
		return Source{File: p.File, Line: p.Line, Origin: OriginProfile}
	}
	add := func(group string, r Rule) {
		r.Group = group
		if r.Source.Origin == "" {
			r.Source.Origin = OriginBuiltIn
		}
		r.Editable = r.Source.Origin == OriginContract && Editable(r.Key)
		r.State = StateOf(r.Enforced, r.EnforcedText)
		r.ByKernel = r.State == StateEnforced && r.EnforcedText == TextKernel
		g := v.Group(group)
		g.Rules = append(g.Rules, r)
	}
	entry := func(group, key string, it Item, sentence, target string, eff Effect, c claim) {
		ok, text := f.at(c)
		rk, covers := f.keys(key, it)
		r := Rule{
			Key: key, Entry: it.Entry, RuleKey: rk, Covers: covers, Sentence: sentence,
			Target: target, Effect: eff, Enforced: ok, EnforcedText: text, Source: src(it.Pos),
		}
		if key == kExecAllow && withWords(it.Entry) {
			r.Invocation = it.Entry // its lines name it in command_rule; the program's rule is every exec's
		}
		add(group, r)
	}

	// Can read: every file but the never-read ones; watched files are read and recorded one by one.
	for _, it := range d.Lists[kFSWatch] {
		s, t := PathSentence("Can read", it.Entry, home)
		entry(GroupRead, kFSWatch, it, s+"; every read is recorded", t, EffectAllow, claim{true, ""})
	}
	v.Group(GroupRead).Default = "Can read any other file on this computer, except the ones under Never reads and Always on."

	// Can change.
	for _, it := range d.Lists[kFSWrite] {
		s, t := PathSentence("Can change", it.Entry, home)
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
				Target: Short(r.Path, home), Effect: EffectAllow, Enforced: ok, EnforcedText: text,
				Source: Source{Origin: OriginTego},
			})
		}
	}
	if len(d.Lists[kFSWrite]) == 0 {
		v.Group(GroupChange).Default = "Cannot change any file."
	} else {
		v.Group(GroupChange).Default = "Cannot change anything else."
	}

	// Asks you first, and the never-read entries an ask_read becomes above tier landlock.
	askReadAsks := f == nil || f.Tier == backend.TierLandlock || f.observe
	for _, it := range d.Lists[kFSAskRead] {
		if askReadAsks {
			s, t := PathSentence("Asks you before it reads", it.Entry, home)
			entry(GroupAsk, kFSAskRead, it, s, t, EffectAsk, claim{true, TextHeld})
			continue
		}
		s, t := PathSentence("Can never read", it.Entry, home)
		entry(GroupNeverRead, kFSAskRead, it, s, t, EffectDeny, claim{true, TextAskReadTier})
	}
	for _, it := range d.Lists[kFSAsk] {
		s, t := PathSentence("Asks you before it changes", it.Entry, home)
		entry(GroupAsk, kFSAsk, it, s, t, EffectAsk, claim{true, TextHeld})
	}
	for _, it := range d.Lists[kNetAsk] {
		entry(GroupAsk, kNetAsk, it, "Asks you before it connects to "+NetTarget(it.Entry), it.Entry, EffectAsk, claim{true, TextHeld})
	}

	// Never reads.
	for _, it := range d.Lists[kFSDenyRead] {
		s, t := PathSentence("Can never read", it.Entry, home)
		entry(GroupNeverRead, kFSDenyRead, it, s, t, EffectDeny, f.denyRead(it.Entry))
	}

	// Never changes.
	userDW := claim{true, TextKernel}
	if f != nil && f.best[agent.BestEffortUserDenyWrite] {
		userDW = claim{false, TextBestEffort}
	}
	for _, it := range d.Lists[kFSDenyWrite] {
		s, t := PathSentence("Can never change", it.Entry, home)
		entry(GroupNeverChange, kFSDenyWrite, it, s, t, EffectDeny, userDW)
	}

	buildPrograms(&v, d, f, add, src, entry)
	buildNetwork(&v, d, f, add, src, entry)
	buildGate(&v, d, f, add, src)
	buildEnv(&v, d, f, entry)

	// The questions' last line, once the gate's are listed too: they wait as long.
	if g := v.Group(GroupAsk); len(g.Rules) > 0 {
		wait := "a few minutes"
		if d.AskTimeout != "" {
			wait = human(d.AskTimeout)
		} else if f != nil && f.rt.AskConfig != nil && f.rt.AskConfig.Timeout > 0 {
			wait = human(f.rt.AskConfig.Timeout.String())
		}
		g.Default = "If you do not answer within " + wait + ", the answer is no."
		if d.AskAlways {
			g.Default = "If you do not answer within " + wait + ", the answer is no for the rest of the run."
		}
	}

	buildLimits(d, f, add, src)
	if len(d.Limits) == 0 {
		v.Group(GroupLimits).Default = "No limits of its own: this computer's defaults apply."
	}

	buildAlwaysOn(&v, d, f, add, src)

	if len(d.Extends) > 0 {
		if f != nil {
			v.Notes = append(v.Notes, "Includes the rules of "+strings.Join(d.Extends, ", ")+"; their entries are marked as from a profile.")
		} else {
			// Read as text, the top file alone: what the profiles add (a folder it may change, a program it may run, a
			// host it may reach) is not here, so no default below can be said to hold. The rules listed are only this
			// file's; the defaults are left out rather than stated over rules that are not shown.
			v.Notes = append(v.Notes, "Builds on "+strings.Join(d.Extends, ", ")+", whose rules are not shown here: only this file's own rules are listed, and what is allowed beyond them cannot be said.")
			for i := range v.Groups {
				v.Groups[i].Default, v.Groups[i].Open = "", false
			}
		}
	}
	for _, m := range d.MCPServers {
		if m.Relayed {
			v.Notes = append(v.Notes, "Its MCP servers behind tego's relay are held to tool rules that are not listed here.")
			break
		}
	}
	return v
}

// buildPrograms fills the programs group.
func buildPrograms(v *View, d Declaration, f *facts, add func(string, Rule), src func(agent.Pos) Source, entry func(string, string, Item, string, string, Effect, claim)) {
	home := f.home()
	g := v.Group(GroupPrograms)
	if len(d.Command) > 0 {
		name := path.Base(d.Command[0])
		ok, text := f.at(kernel)
		// A run names the command's rule as the command is written (agent.ExecRule.RuleName of its Raw): /bin/sh is
		// exec[/bin/sh], ./agent.sh exec[./agent.sh]. A compiled table's file names replace it below.
		r := Rule{
			Key: "command", Entry: d.Command[0], RuleKey: "exec[" + d.Command[0] + "]", Sentence: "Can run " + name + ", the command it starts with",
			Target: name, Effect: EffectAllow, Enforced: ok, EnforcedText: text,
			Source: Source{File: d.File, Line: d.CmdPos.Line, Origin: OriginContract},
		}
		cmd := -1
		if f != nil {
			if cmd = commandRule(f.rt); cmd >= 0 {
				if k, c, ok := f.exec.keys(cmd); ok {
					r.RuleKey, r.Covers = k, c
				}
			}
		}
		if !f.repeats(d.Lists[kExecAllow], cmd, r.RuleKey) {
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
	words := claim{true, TextKernel}
	if f != nil && f.best[agent.BestEffortExecRules] {
		words = claim{false, TextTegoCommands}
	}
	for _, it := range d.Lists[kExecAllow] {
		s, t := ProgramSentence("Can run", it.Entry, home)
		c := kernel
		if withWords(it.Entry) { // as compile reads it: a quoted path with a space is one word, a tab splits words
			c = words
		}
		entry(GroupPrograms, kExecAllow, it, s, t, EffectAllow, c)
	}
	// A tool with command words in exec.allow is constrained: every invocation of it no entry names is refused under
	// exec.args[<tool>] (execmatch Decision.Rule), a rule in force that no entry spells, so it is listed after the
	// entries that constrain it, where the lines it refuses are counted.
	if f != nil && f.rt.ExecCommands != nil {
		for _, tool := range f.rt.ExecCommands.Index.ConstrainedTools() {
			r := Rule{
				Key: kExecArgs, Entry: tool, RuleKey: RuleKey(kExecArgs, tool), Target: tool, Effect: EffectDeny,
				Sentence: "Cannot run " + tool + " with any other words than the commands allowed above",
				Source:   Source{Origin: OriginBuiltIn},
			}
			for _, it := range d.Lists[kExecAllow] {
				if withWords(it.Entry) && entryTool(it.Entry) == tool {
					r.Source = src(it.Pos)
					break
				}
			}
			r.Enforced, r.EnforcedText = f.at(words)
			add(GroupPrograms, r)
		}
	}
	buildMCPPrograms(v, d, f, add)
	// exec.privileged is accepted by the schema and refused by this build (schema-only, P2): an entry is a
	// declaration that grants and refuses nothing, said so, so a file that names one is not read as holding fewer rules.
	for _, it := range d.Lists[kExecPriv] {
		add(GroupPrograms, Rule{
			Key: kExecPriv, Entry: it.Entry, Target: it.Entry, Effect: EffectNote, Source: src(it.Pos),
			Sentence: "Declares " + it.Entry + " as a privileged command, which this version of tego does not support yet: a rules file that names it does not compile",
		})
	}
	// exec.deny and exec.ask entries are command rules: tego decides them on its copy of the command's words, so
	// they are best effort wherever exec.allow's words are (ADR 0048 (6)).
	for _, it := range d.Lists[kExecDeny] {
		s, t := ProgramSentence("Can never run", it.Entry, home)
		entry(GroupPrograms, kExecDeny, it, s, t, EffectDeny, words)
	}
	// exec.ask is reserved: every match is refused at every tier until ADR 0044 gives it a way to ask, so it is a
	// refusal here and never a question in "Asks you first" (no approval card, no timeout).
	reserved := claim{words.ok, TextExecAskReserved}
	if !words.ok {
		reserved.text = TextExecAskReservedBest
	}
	for _, it := range d.Lists[kExecAsk] {
		s, t := ProgramSentence("Can never run", it.Entry, home)
		entry(GroupPrograms, kExecAsk, it, s+" (asking first is not supported yet)", t, EffectDeny, reserved)
	}
	switch {
	case !d.HasExec:
		g.Default, g.Open = "Can run any program.", true
	case d.ExecAllowKey:
		g.Default = "Cannot run any other program."
	default:
		g.Default, g.Open = "Can run any other program.", true
	}
}

// buildMCPPrograms lists the programs the agent starts for its stdio MCP servers (mcp[].command): each gets exec
// rights implicitly (R8) unless it is a business-rules worker, whose command runs out of the run. A server's lines
// carry the rule of the file its command resolved to; a view read as text names it by the command as written.
func buildMCPPrograms(v *View, d Declaration, f *facts, add func(string, Rule)) {
	for _, m := range d.MCPServers {
		if len(m.Command) == 0 {
			continue
		}
		name := path.Base(m.Command[0])
		r := Rule{
			Key: "mcp", Entry: m.Name, RuleKey: "exec[" + m.Command[0] + "]", Target: name, Effect: EffectAllow,
			Sentence: "Can run " + name + ", the command of its MCP server " + m.Name,
			Source:   Source{File: d.File, Line: m.Pos.Line, Origin: OriginContract},
		}
		if m.Pos.File != "" && m.Pos.File != d.File {
			r.Source = Source{File: m.Pos.File, Line: m.Pos.Line, Origin: OriginProfile}
		}
		switch {
		case m.BusinessRules:
			r.RuleKey, r.Effect = "", EffectNote
			r.Sentence = "Declares " + name + " as the business-rules worker of its MCP server " + m.Name + ": it runs out of the run, with no program grant for the agent"
		case m.Relayed:
			r.Sentence += ", with its tool calls held to tego's MCP relay (the relay's tool rules are not listed here)"
		}
		if f != nil && !m.BusinessRules {
			for i := range f.rt.Exec {
				if FromSource(f.rt.Exec[i].Source, agent.ExecSourceMCP+":"+m.Name) {
					if k, c, ok := f.exec.keys(i); ok {
						r.RuleKey, r.Covers = k, c
					}
					break
				}
			}
			r.Enforced, r.EnforcedText = f.at(kernel)
		}
		add(GroupPrograms, r)
	}
}

// buildMCPNetwork lists the HTTP MCP servers the agent connects to (mcp[].url). Under a net: section a server not
// behind the relay gets the net rule its URL needs (R16a), which its lines carry; a relayed server's only route is
// the relay, so its URL derives no rule.
func buildMCPNetwork(d Declaration, f *facts, add func(string, Rule)) {
	for _, m := range d.MCPServers {
		if m.URL == "" || len(m.Command) > 0 {
			continue
		}
		r := Rule{Key: "mcp", Entry: m.Name, Target: m.URL, Effect: EffectAllow, Sentence: "Can connect to its MCP server " + m.Name + " at " + m.URL,
			Source: Source{File: d.File, Line: m.Pos.Line, Origin: OriginContract}}
		if m.Pos.File != "" && m.Pos.File != d.File {
			r.Source = Source{File: m.Pos.File, Line: m.Pos.Line, Origin: OriginProfile}
		}
		if m.Relayed {
			r.Effect = EffectNote
			r.Sentence = "Reaches its MCP server " + m.Name + " at " + m.URL + " only through tego's MCP relay, which holds its tool calls to tool rules not listed here"
		}
		if f != nil && !m.Relayed && d.HasNet {
			for i := range f.rt.Net {
				if f.rt.Net[i].MCP == m.Name {
					r.RuleKey = f.rt.Net[i].RuleName()
					break
				}
			}
			r.Enforced, r.EnforcedText = f.at(f.connect())
		}
		add(GroupNetwork, r)
	}
}

// buildNetwork fills the network group.
func buildNetwork(v *View, d Declaration, f *facts, add func(string, Rule), src func(agent.Pos) Source,
	entry func(string, string, Item, string, string, Effect, claim)) {
	buildMCPNetwork(d, f, add)
	for _, it := range d.Lists[kModels] {
		entry(GroupNetwork, kModels, it, "Can reach its model service at "+NetTarget(it.Entry), it.Entry, EffectAllow, f.connect())
	}
	for _, it := range d.Lists[kNetAllow] {
		verb := "Can connect to "
		if strings.HasPrefix(it.Entry, "unix:") {
			verb = "Can use "
		}
		entry(GroupNetwork, kNetAllow, it, verb+NetTarget(it.Entry), it.Entry, EffectAllow, f.connect())
	}
	for _, it := range d.Lists[kNetListen] {
		entry(GroupNetwork, kNetListen, it, "Can accept connections on "+NetTarget(it.Entry), it.Entry, EffectAllow, f.connect())
	}
	// net.http: the requests tego's model proxy sends on to a model service, decided on each request it holds.
	for i, h := range d.HTTP {
		r := Rule{Key: kNetHTTP, Entry: h.Host, Sentence: httpSentence(h), Target: h.Host, Effect: EffectAllow, Source: src(h.Pos)}
		if len(h.Allow) == 0 {
			r.Effect = EffectNote // it grants nothing, so it allows and claims nothing
		} else {
			r.Enforced, r.EnforcedText = f.at(claim{true, TextTegoRequest})
		}
		if f != nil || len(d.Extends) == 0 { // read as text, a profile's entries would come first
			r.RuleKey = kNetHTTP + "[" + strconv.Itoa(i) + "]"
		}
		add(GroupNetwork, r)
	}
	// net.ingress: the sources a listener accepts, which the run's kernel programs admit packet by packet. No ledger
	// line names an ingress rule: a packet they refuse only adds to a counter (run_end's network refusals, "ingress"),
	// and one they admit is not recorded, so the rows carry no rule key and count no hits.
	for _, in := range d.Ingress {
		r := Rule{Key: kNetIngress, Entry: in.From + " -> " + in.To, Target: in.To, Effect: EffectAllow, Source: src(in.Pos),
			Sentence: "Can accept connections on " + NetTarget(in.To) + " from " + fromPhrase(in.From)}
		r.Enforced, r.EnforcedText = f.at(kernel)
		add(GroupNetwork, r)
	}
	g := v.Group(GroupNetwork)
	switch {
	case d.HasNet && len(g.Rules) == 0:
		g.Default = "Cannot connect anywhere."
	case d.HasNet:
		g.Default = "Cannot connect anywhere else."
	case d.HostSockets:
		g.Default, g.Open = "Can connect anywhere, other programs' local sockets included.", true
	default:
		g.Default, g.Open = "Can connect to any address. Other programs' local sockets stay closed (see Always on).", true
	}
	if len(d.HTTP) > 0 {
		g.Default += " Every other request to its model services is refused."
	}
	if d.IngressKey {
		g.Default += " Nothing else can connect to its listeners."
	}
	// At tier landlock tego decides each datagram on the address it copied and lets the agent's own call send one it
	// does not refuse: a sibling thread can change the address between the two, so the refusal of
	// every other destination is best effort for datagrams. Under a net: section that holds for every run of the tier,
	// whatever its entries admit (racesDatagrams).
	if d.HasNet && f.racesDatagrams() {
		ok, text := f.at(claim{false, TextDatagram})
		add(GroupNetwork, Rule{Key: "built-in.datagrams", Sentence: "Cannot send datagrams anywhere it may not connect",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	}
	// Tier cgroup with no decision plane (its fanotify listener) leaves a unix datagram's name to the kernel's own
	// program only on Linux 6.7 and later (cgroup/sendmsg_unix); below it tego checks the name on its copy and the
	// agent's call sends it. The view is given no kernel, so it says the boundary, as the landlock row says its race.
	if d.HasNet && f.leavesUnixDatagrams() {
		ok, text := f.at(claim{false, TextDatagramRoot})
		add(GroupNetwork, Rule{Key: "built-in.datagrams", Sentence: "Cannot send unix datagrams to a socket it may not connect to",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	}
}

// leavesUnixDatagrams reports whether a root tier's run has no decision plane, so a kernel below 6.7 leaves its unix
// datagrams to tego's copy of the address (racesDatagrams is tier landlock's, at every kernel). Not an observe run.
func (f *facts) leavesUnixDatagrams() bool {
	return f != nil && !f.observe && f.Tier == backend.TierCgroup && !f.plane
}

// racesDatagrams reports whether a run under a net: section can race a datagram past tego's decision: at tier
// landlock, every run, whatever its entries admit. The socket allowlist admits a UDP and a local datagram socket under
// every net: section (enforce-landlock's socket(2) arm), and a sendmsg that names no address is continued undecided
// (sendUnaddressed; relayed only on an IP socket under the models[] guard or a net gate), so a sibling
// that writes an address in before the kernel copies the header sends where nothing decided. An addressed datagram
// is continued once admitted, too: by an entry, the machine's resolver (net.dns mode system), the DNS broker's socket
// the runtime grants at launch (mode broker), or a socket the run bound beneath a write entry, the
// last two in no compiled table. Landlock refuses a raced datagram itself only from ABI 10 for a UDP port no entry
// declares, from ABI 9 for a pathname socket outside the run's places and from ABI 6 for an abstract name bound
// outside the run, which this view, given no kernel, does not count on. Not in an observe run, which refuses
// nothing, nor read as text, which names no tier.
//
// Not at tiers cgroup and bpflsm, whose cgroup sendmsg programs, which every such run attaches, decide a UDP datagram
// on the kernel's own copy. A local socket's datagram is not wholly theirs: below Landlock ABI 9 one to a relative
// name, which their unix programs leave to tier 1, or to a name that leads elsewhere stays the supervisor's best
// effort there, and so does every one on a kernel those programs do not load on (before 6.7) where no decision plane
// decides it. This view does not list that residual yet: which runs it holds for turns on
// the run's attached hooks (run_start.net_guarantees) and Landlock ABI, which Of is not given.
func (f *facts) racesDatagrams() bool {
	return f != nil && f.Tier == backend.TierLandlock
}

// httpSentence says a net.http entry: "Can send POST requests to api.example.com under /v1/messages". An entry whose
// allow list is empty grants nothing (httppolicy.Compile).
func httpSentence(h HTTPRule) string {
	what := "requests"
	if len(h.Methods) > 0 {
		what = strings.Join(h.Methods, ", ") + " requests"
	}
	if len(h.Allow) == 0 {
		return "Can send no " + what + " to " + h.Host + " by this entry (its allow list is empty)"
	}
	for _, p := range h.Allow {
		if strings.TrimSuffix(p, "/") == "" {
			return "Can send " + what + " to " + h.Host + " at any path"
		}
	}
	return "Can send " + what + " to " + h.Host + " under " + strings.Join(h.Allow, ", ")
}

// gateCells are the best-effort cells (ADR 0041 D1) of a gate predicate's decisions: where the run lists one, the
// rule's score rests on copied syscall facts a program built to race tego could change.
var gateCells = map[gate.Predicate][]string{
	gate.ReadMatches:          {agent.BestEffortGateFSReadOpen, agent.BestEffortGateFSReadMove, agent.BestEffortGateFSReadOPath},
	gate.WriteOutsideWorktree: {agent.BestEffortGateFSWriteOpen, agent.BestEffortGateFSWriteMutation},
	gate.ExecMatches:          {agent.BestEffortGateExec},
	gate.NetUndeclared:        {agent.BestEffortGateNetUnixDatagram, agent.BestEffortGateNetUnixConnect},
}

// buildGate lists the gate's scored rules, with the rule keys its lines carry (gate.rules[i]).
// Scores only add up, so each rule is listed where its score alone puts an action it matches: above the ask threshold
// among the refusals of its kind; from the allow threshold among the questions, save a command, which tego cannot hold
// to ask about and refuses; below it as what it adds, among the questions, save a command's, which can only bring a
// refusal nearer and is listed among the programs. A question is held until you answer and a refusal scored before
// the action happens, each best effort where the run lists a best-effort cell of its kind (gateCells). A note says how
// the scores add up.
func buildGate(v *View, d Declaration, f *facts, add func(string, Rule), src func(agent.Pos) Source) {
	if d.GateBad {
		v.Notes = append(v.Notes, "Its gate: section does not read as a gate, so its risk scores are not listed.")
	}
	rules := d.Gate.Rules()
	if len(rules) == 0 {
		return
	}
	allow, ask := d.Gate.Thresholds()
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
		case gr.Predicate == gate.ExecMatches: // tego never asks before a program runs
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
				c = claim{false, TextHeldBest}
			case r.Effect == EffectAsk:
				c = claim{true, TextHeld}
			case best:
				c = claim{false, TextBestEffort}
			default:
				c = claim{true, TextGate}
			}
			r.Enforced, r.EnforcedText = f.at(c)
		}
		if f != nil || len(d.Extends) == 0 { // read as text, a profile's rules would come first
			r.RuleKey = "gate.rules[" + strconv.Itoa(i) + "]"
		}
		var p agent.Pos
		if i < len(d.GatePos) {
			p = d.GatePos[i]
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
		p := Short(r.Argument, home)
		return "read a file matching " + p, "reads a file matching " + p, GroupNeverRead, p
	case gate.ExecMatches:
		return "run a command matching " + r.Argument, "runs a command matching " + r.Argument, GroupPrograms, r.Argument
	case gate.NetUndeclared:
		return "connect to a host its rules do not name", "connects to a host its rules do not name", GroupNetwork, ""
	case gate.NetTo:
		return "connect to " + NetTarget(r.Argument), "connects to " + NetTarget(r.Argument), GroupNetwork, r.Argument
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
func buildEnv(v *View, d Declaration, f *facts, entry func(string, string, Item, string, string, Effect, claim)) {
	removed := map[string]bool{}
	if f != nil && f.rt.Env != nil {
		kept := map[string]bool{}
		for _, n := range f.rt.Env {
			kept[n] = true
		}
		for _, it := range d.Lists[kEnvPass] {
			if !kept[it.Entry] {
				removed[it.Entry] = true
			}
		}
	}
	for _, it := range d.Lists[kEnvPass] {
		if removed[it.Entry] {
			entry(GroupEnv, kEnvPass, it, "Does not get "+it.Entry+" from your shell: tego sets it for the run", it.Entry, EffectDeny, claim{true, TextEnvRemoved})
			continue
		}
		entry(GroupEnv, kEnvPass, it, "Gets "+it.Entry+" from your shell", it.Entry, EffectAllow, claim{true, TextEnvRemoved})
	}
	for _, it := range d.Lists[kEnvSet] {
		entry(GroupEnv, kEnvSet, it, "Gets "+it.Entry+", set in its rules", it.Entry, EffectAllow, claim{true, ""})
	}
	for _, it := range d.Lists[kEnvDeny] {
		entry(GroupEnv, kEnvDeny, it, "Never gets "+it.Entry, it.Entry, EffectDeny, claim{true, TextEnvRemoved})
	}
	g := v.Group(GroupEnv)
	if d.EnvPassKey {
		g.Default = "Every other variable in your shell, secrets included, is removed before it starts."
	} else {
		g.Default, g.Open = "Gets every variable in your shell, secrets included.", true
	}
}

// buildLimits fills the limits group. Read as text, each limit is as written. Compiled, each is what the table holds,
// the contract's value clamped to this computer's ceilings: a limit a ceiling lowers says the
// lower value and the one its rules ask for, and a limit only a ceiling sets is listed after the contract's, from the
// machine config. Limits make no enforcement claim.
func buildLimits(d Declaration, f *facts, add func(string, Rule), src func(agent.Pos) Source) {
	declared := map[string]bool{}
	for _, l := range d.Limits {
		declared[l.Key] = true
		s := LimitSentence(l.Key, l.Value)
		if v, ok := f.Limit(l.Key); ok && v != l.Value {
			s = LimitSentence(l.Key, v) + ", this computer's limit; its rules ask for " + limitAmount(l.Key, l.Value)
		}
		add(GroupLimits, Rule{Key: "limits." + l.Key, Entry: l.Value, Sentence: s, Effect: EffectLimit, Source: src(l.Pos)})
	}
	for _, k := range LimitKeys {
		if v, ok := f.Limit(k); ok && !declared[k] {
			add(GroupLimits, Rule{Key: "limits." + k, Entry: v, Sentence: LimitSentence(k, v), Effect: EffectLimit,
				Source: Source{Origin: OriginMachine}})
		}
	}
}

// limit is the run's budget on limits key k as the table holds it, spelled as the contract spells it ("2h", "4GiB");
// ok is false without a table or when neither the contract nor a ceiling bounds it.
func (f *facts) Limit(k string) (v string, ok bool) {
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

// keyAndCovers is a built-in rule's ledger key, the first of keys, and its Covers, the rest: nil, never an empty list,
// when there is no other, since Covers is omitempty and the view the dashboard and `tego rules --json` serve must read
// back as the view it was (a home with one of the usual secret files, or one hooks folder beneath a write entry).
func keyAndCovers(keys []string) (string, []string) {
	switch len(keys) {
	case 0:
		return "", nil
	case 1:
		return keys[0], nil
	}
	return keys[0], keys[1:]
}

// buildAlwaysOn fills the always-on group: the protections no contract line writes.
func buildAlwaysOn(v *View, d Declaration, f *facts, add func(string, Rule), src func(agent.Pos) Source) {
	at := func(c claim) (bool, string) { return f.at(c) }
	if d.DenyReadOff {
		add(GroupAlwaysOn, Rule{
			Key: kFSDenyRead, Sentence: "The usual secret files are NOT protected: this file turns that list off (deny_read: [])",
			Effect: EffectAllow, Source: src(d.DenyReadPos),
		})
	} else {
		keys, c := f.builtInDenyRead()
		ok, text := at(c)
		r := Rule{
			Key: "built-in.deny_read", Sentence: "Can never read the usual secret files: SSH and cloud keys, browser profiles, .env files and similar",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text,
		}
		r.RuleKey, r.Covers = keyAndCovers(keys)
		add(GroupAlwaysOn, r)
	}
	// The built-in deny_write set holds only the files of its kinds a compile finds beneath the write entries (R20): a
	// compiled view lists it when compile found some, and a view read as text, which cannot look, says that condition.
	if present, keys, c := f.builtInDenyWrite(); present || (f == nil && len(d.Lists[kFSWrite]) > 0) {
		ok, text := at(c)
		r := Rule{
			Key: "built-in.deny_write", Sentence: "Can never change files that would run code outside the agent: git hooks, shell startup files and agent settings",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text,
		}
		if f == nil {
			r.Sentence += ", where a run finds any in the folders it can change"
		}
		r.RuleKey, r.Covers = keyAndCovers(keys)
		add(GroupAlwaysOn, r)
	}
	// ADR 0158: every contract may write the five standard data devices, and a compiled view says so only for the
	// devices the table holds a row for (a host whose file at the name is not the device has none, and an entry of
	// the contract that names one decides it instead); a view read as text, which cannot look, says it for the set.
	if (f == nil && d.HasFS) || f.hasStandardDevices() {
		add(GroupAlwaysOn, Rule{
			Key: "built-in.standard_devices", RuleKey: agent.BuiltinStandardDevices,
			Sentence: "Can write the standard data devices /dev/null, /dev/zero, /dev/full, /dev/random and /dev/urandom, which hold no file; no other device",
			Effect:   EffectAllow,
		})
	}
	if f == nil || f.rt.Builtins != nil {
		for _, entry := range []struct{ id, sentence string }{
			{agent.BuiltinHostIPC, "Cannot reach session services, non-SSH credential agents, system D-Bus, X11 or the listed multiplexer and editor sockets; protects their folders from changes"},
			{agent.BuiltinTegoSurface, "Cannot reach tego's control sockets or local control ports; its own runtime folder stays available"},
			{agent.BuiltinOtherTTY, "Cannot open other terminals; its own terminal and ptys it creates stay available"},
		} {
			c := claim{true, "Enforced by the operating system and tego"}
			if entry.id != agent.BuiltinOtherTTY && f != nil && !f.plane {
				c = claim{false, TextBestEffort}
			}
			enforced, words := at(c)
			add(GroupAlwaysOn, Rule{Key: entry.id, RuleKey: entry.id, Sentence: entry.sentence, Effect: EffectDeny, Enforced: enforced, EnforcedText: words})
		}
	}
	ok, text := at(kernel)
	add(GroupAlwaysOn, Rule{Key: "built-in.own-records", Sentence: "Can never read or change tego's records of its runs", Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	add(GroupAlwaysOn, Rule{Key: "built-in.contract", Sentence: "Cannot change its own rules file", Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	if !d.HasNet {
		if d.HostSockets {
			add(GroupAlwaysOn, Rule{Key: "host_sockets", Sentence: "Can reach other local sockets except the fixed host IPC and tego control surfaces (host_sockets: true)", Effect: EffectAllow})
		} else {
			c := kernel
			if f != nil && (f.best[agent.BestEffortHostSocketsDatagram] || f.best[agent.BestEffortHostSocketsRoot]) {
				c = claim{false, TextBestEffort}
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
	if d.Setuid {
		add(GroupAlwaysOn, Rule{Key: "setuid", Sentence: "Can gain root through sudo or other setuid programs (setuid: true)", Effect: EffectAllow})
	} else {
		add(GroupAlwaysOn, Rule{Key: "built-in.no-setuid", Sentence: "Cannot gain root through sudo or other setuid programs", Effect: EffectDeny, Enforced: ok, EnforcedText: text})
	}
	switch d.Record {
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

// RuleKey is the ledger rule key a declared entry's events carry, read from its text (agent.FSRule.RuleName and the
// others name a declared entry by its text): fs.write[./tmp/], fs.ask_read[...], exec[git], net[tcp://chatgpt.com:443],
// exec.deny[git push] (execmatch Pattern.Rule). An exec.allow entry is named by its program: an allowed exec carries
// its program's rule, so "git status" is exec[git] (the entry is in the line's command_rule), and a quoted path is
// named without its quotes. In a compiled table an exec.allow entry takes the name of the rule it resolved to
// instead (execNames), which may be another entry's spelling.
func RuleKey(key, entry string) string {
	switch key {
	case kFSWrite, kFSAsk, kFSDenyRead, kFSAskRead, kFSDenyWrite, kFSWatch:
		return key + "[" + entry + "]"
	case kExecAllow:
		return "exec[" + programWord(entry) + "]"
	case kExecDeny, kExecAsk, kExecArgs:
		return key + "[" + entry + "]"
	case kNetAllow, kNetAsk:
		return "net[" + entry + "]"
	}
	return ""
}

// defaultKinds are the ledger line kinds whose unmatched lines a group's default decides (Group.DefaultKind): every
// exec no rule names is the programs default's, every connect, datagram, bind and listen the network default's.
var defaultKinds = map[string]string{GroupPrograms: string(record.KindExec), GroupNetwork: string(record.KindNet)}

// New is a view with every group, in order, and its copy.
func New() View {
	v := View{Groups: make([]Group, 0, len(GroupOrder))}
	for _, id := range GroupOrder {
		c := GroupCopy[id]
		v.Groups = append(v.Groups, Group{ID: id, Title: c[0], Lede: c[1], DefaultKind: defaultKinds[id]})
	}
	return v
}
