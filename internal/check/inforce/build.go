// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"path"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// facts is what a compiled table says about enforcement at one tier; nil for a view built from text.
type facts struct {
	rt      *agent.RuleTable
	tier    backend.Tier
	best    map[string]bool
	observe bool
	held    bool // the run holds its reads (ReadsHeldAt), so a shadowed deny_read is refused all the same
}

func newFacts(rt *agent.RuleTable, tier backend.Tier, planeMode string) *facts {
	if tier == "" {
		tier = rt.Tier
	}
	f := &facts{rt: rt, tier: tier, best: map[string]bool{}, observe: tier == backend.TierObserve}
	for _, c := range rt.BestEffortCellsAt(tier, planeMode) {
		f.best[c] = true
	}
	f.held = rt.ReadsHeldAt(tier)
	return f
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
		g := v.Group(group)
		g.Rules = append(g.Rules, r)
	}
	entry := func(group, key string, it item, sentence, target string, eff Effect, c claim) {
		ok, text := f.at(c)
		add(group, Rule{
			Key: key, Entry: it.entry, RuleKey: ruleKey(key, it.entry), Covers: coverKeys(key, it.entry), Sentence: sentence,
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
	buildNetwork(&v, d, f, entry)
	buildEnv(&v, d, f, entry)

	// Limits: the budgets as written; the machine's ceilings may lower them.
	for _, l := range d.limits {
		add(GroupLimits, Rule{
			Key: "limits." + l.key, Entry: l.value, Sentence: limitSentence(l.key, l.value), Effect: EffectLimit,
			Source: src(l.pos),
		})
	}
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
		r := Rule{
			Key: "command", Entry: d.command[0], RuleKey: "exec[" + name + "]", Sentence: "Can run " + name + ", the command it starts with",
			Target: name, Effect: EffectAllow, Enforced: ok, EnforcedText: text,
			Source: Source{File: d.file, Line: d.cmdPos.Line, Origin: OriginContract},
		}
		if f != nil {
			if k := commandRuleKey(f.rt); k != "" {
				r.RuleKey = k
			}
		}
		if !listed(d.lists[kExecAllow], r.RuleKey) {
			add(GroupPrograms, r)
		}
	}
	if f != nil && f.rt.RunCommandGrant != "" {
		name := path.Base(f.rt.RunCommandGrant)
		ok, text := f.at(kernel)
		key := "exec[" + name + "]"
		for i := range f.rt.Exec {
			if f.rt.Exec[i].Path == f.rt.RunCommandGrant {
				key = f.rt.Exec[i].RuleName()
			}
		}
		add(GroupPrograms, Rule{
			Key: "run-command", Entry: f.rt.RunCommandGrant, RuleKey: key,
			Sentence: "Can run " + name + ", the command this run was started with", Target: name,
			Effect: EffectAllow, Enforced: ok, EnforcedText: text, Source: Source{Origin: OriginCommandLine},
		})
	}
	words := claim{true, textKernel}
	if f != nil && f.best[agent.BestEffortExecRules] {
		words = claim{false, textTegoCommands}
	}
	for _, it := range d.lists[kExecAllow] {
		s, t := programSentence("Can run", it.entry, home)
		c := kernel
		if strings.Contains(strings.TrimSpace(it.entry), " ") {
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
		g.Default = "Can run any program."
	case d.execAllowKey:
		g.Default = "Cannot run any other program."
	default:
		g.Default = "Can run any other program."
	}
}

// buildNetwork fills the network group.
func buildNetwork(v *View, d decl, f *facts, entry func(string, string, item, string, string, Effect, claim)) {
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
	g := v.Group(GroupNetwork)
	switch {
	case d.hasNet && len(g.Rules) == 0:
		g.Default = "Cannot connect anywhere."
	case d.hasNet:
		g.Default = "Cannot connect anywhere else."
	case d.hostSockets:
		g.Default = "Can connect anywhere, other programs' local sockets included."
	default:
		g.Default = "Can connect to any address. Other programs' local sockets stay closed (see Always on)."
	}
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
		g.Default = "Gets every variable in your shell, secrets included."
	}
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
	if present, keys, c := f.builtInDenyWrite(); present || (f == nil && len(d.lists[kFSWrite]) > 0) {
		ok, text := at(c)
		r := Rule{
			Key: "built-in.deny_write", Sentence: "Can never change files that would run code outside the agent: git hooks, shell startup files and agent settings",
			Effect: EffectDeny, Enforced: ok, EnforcedText: text,
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
			g.Rules[i].Enforced, g.Rules[i].EnforcedText, g.Rules[i].State = false, "", StateNone
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

// commandRuleKey is the ledger rule key of the contract command's exec rule, "" when the table has none.
func commandRuleKey(rt *agent.RuleTable) string {
	for i := range rt.Exec {
		for _, s := range strings.Split(rt.Exec[i].Source, ",") {
			if s == "command" {
				return rt.Exec[i].RuleName()
			}
		}
	}
	return ""
}

// listed reports whether an exec.allow entry already carries the rule key.
func listed(items []item, key string) bool {
	for _, it := range items {
		if ruleKey(kExecAllow, it.entry) == key {
			return true
		}
	}
	return false
}

// ruleKey is the ledger rule key a declared entry's events carry (agent.FSRule.RuleName and the others name a
// declared entry by its text): fs.write[./tmp/], fs.ask_read[...], exec[git], net[tcp://chatgpt.com:443].
func ruleKey(key, entry string) string {
	switch key {
	case kFSWrite, kFSAsk, kFSDenyRead, kFSAskRead, kFSDenyWrite, kFSWatch:
		return key + "[" + entry + "]"
	case kExecAllow:
		return "exec[" + entry + "]"
	case kExecDeny, kExecAsk:
		return key + "[" + entry + "]"
	case kNetAllow, kNetAsk:
		return "net[" + entry + "]"
	}
	return ""
}

// coverKeys are the further ledger rule keys a declared entry's events can carry: an exec.allow entry with words is a
// command pattern, which the engine names exec.allow[git status] (execmatch Result.Rule) while a bare program is
// exec[git], so both spellings count for it.
func coverKeys(key, entry string) []string {
	if key == kExecAllow && strings.Contains(strings.TrimSpace(entry), " ") {
		return []string{"exec.allow[" + entry + "]"}
	}
	return nil
}

// newView is a view with every group, in order, and its copy.
func newView() View {
	v := View{Groups: make([]Group, 0, len(GroupOrder))}
	for _, id := range GroupOrder {
		c := groupCopy[id]
		v.Groups = append(v.Groups, Group{ID: id, Title: c[0], Lede: c[1]})
	}
	return v
}
