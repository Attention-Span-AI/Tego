// SPDX-License-Identifier: Apache-2.0

package compiledview

import (
	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The group ids, in the one order every view lists them (Groups).
const (
	GroupRead        = "read"
	GroupChange      = "change"
	GroupAsk         = "ask"
	GroupNeverRead   = "never-read"
	GroupNeverChange = "never-change"
	GroupPrograms    = "programs"
	GroupNetwork     = "network"
	GroupEnv         = "env"
	GroupLimits      = "limits"
	GroupLive        = "live"
	GroupAlwaysOn    = "always-on"
)

// GroupOrder is every group id in display order.
var GroupOrder = []string{
	GroupRead, GroupChange, GroupAsk, GroupNeverRead, GroupNeverChange, GroupPrograms, GroupNetwork, GroupEnv,
	GroupLimits, GroupLive, GroupAlwaysOn,
}

// State is a rule's enforcement claim (Rule.State).
type State string

// The enforcement states.
const (
	StateEnforced    State = "enforced"     // the run enforces it in full
	StateBestEffort  State = "best_effort"  // tego refuses it, but a program built to race tego could get past
	StateNotEnforced State = "not_enforced" // the run does not enforce it (a shadowed entry, an observe run)
	StateNone        State = "none"         // the view makes no claim
)

// StateOf is the state of a claim as Enforced and EnforcedText say it.
func StateOf(enforced bool, text string) State {
	switch {
	case text == "":
		return StateNone
	case enforced:
		return StateEnforced
	case text == TextBestEffort || text == TextHeldBest || text == TextTegoCommands || text == TextExecAskReservedBest ||
		text == TextLive || text == TextDatagram || text == TextDatagramRoot:
		return StateBestEffort
	}
	return StateNotEnforced
}

// Effect is what a rule does to the actions it names.
type Effect string

// The effects.
const (
	EffectAllow Effect = "allow" // the agent may
	EffectAsk   Effect = "ask"   // the agent waits for a person
	EffectDeny  Effect = "deny"  // the agent may not
	EffectLimit Effect = "limit" // a budget that ends or slows the run
	EffectNote  Effect = "note"  // a fact about the run that allows and refuses nothing (what it records)
)

// The origins a Source names.
const (
	OriginContract    = "contract"       // the top-level contract file
	OriginProfile     = "profile"        // a profile the contract extends
	OriginBuiltIn     = "built in"       // tego's own protection, in no file
	OriginTego        = "tego"           // a grant the runtime made for this run (its own CODEX_HOME, hook state)
	OriginCommandLine = "command line"   // the command given on tego run's command line
	OriginMachine     = "machine config" // a ceiling of this computer's config that sets a limit the contract does not
)

// Source is where a rule came from.
type Source struct {
	// File is the file the entry is written in, "" for a built-in rule.
	File string `json:"file,omitempty"`
	// Line is its line in File, 0 when unknown.
	Line int `json:"line,omitempty"`
	// Origin is one of the Origin values.
	Origin string `json:"origin"`
}

// Rule is one rule in force, said as one sentence.
type Rule struct {
	// Group is the id of the group the rule is listed in.
	Group string `json:"group"`
	// Key is the contract key the entry is written under ("fs.write", "exec.allow", "limits.memory"), or a name
	// for a built-in rule ("built-in.deny_read").
	Key string `json:"key"`
	// Entry is the entry as its author wrote it ("./src/", "git", "127.0.0.1:8803"); "" for a built-in rule. For
	// an env rule it is the variable's name and never its value.
	Entry string `json:"entry,omitempty"`
	// RuleKey is the rule field a ledger line carries when this rule decides it (fs.write[./tmp/], exec[git],
	// net[tcp://chatgpt.com:443]); "" for a rule no ledger line names. A program entry's is the name the run's lines
	// give the file it resolved to, which can be another entry's spelling: exec[python3] for /usr/bin/python3.13 when
	// python3 links to it and comes first, exec[git] for "git status" (execNames).
	RuleKey string `json:"rule_key,omitempty"`
	// Covers are further ledger rule keys this rule stands for: the built-in secret list is one sentence over
	// many entries, and a program entry stands for every rule of the file it resolved to (a link to it, the file
	// a link leads to), for the helper images compile granted its tool (git's exec-path git) and, for a script
	// command, for the interpreter its #! line was granted. Count adds their hits to this rule.
	Covers []string `json:"covers,omitempty"`
	// Invocation is, for an exec.allow entry with command words ("git status"), the command_rule that entry's
	// admitted lines carry. Its lines carry its program's rule (exec[git]) like every other exec of that program, so
	// the rule key cannot tell them apart: Hits count the lines naming Invocation (Count's CountCommands), not every
	// exec of the program. "" for every other rule.
	Invocation string `json:"invocation,omitempty"`
	// Sentence says the rule in plain words, without a subject: "Can change files in ./src/".
	Sentence string `json:"sentence"`
	// Target is the path, program, destination or variable the rule is about, shortened for display (~ for the
	// home directory); "" when the sentence names no one thing.
	Target string `json:"target,omitempty"`
	// Effect is what the rule does.
	Effect Effect `json:"effect"`
	// Enforced is true when the run enforces the rule in full at its tier. False for a best-effort rule, one the
	// tier leaves unenforced, every rule of an observe run, and every rule of a view built from text (Declared).
	// State tells those cases apart; a view keys a warning on State, not on Enforced.
	Enforced bool `json:"enforced"`
	// State is the enforcement claim in one word: enforced, best_effort, not_enforced, or none when the view makes
	// no claim (limits, notes, env.set, every rule of a Declared view).
	State State `json:"state"`
	// EnforcedText says how the rule is enforced, or why not in full; "" when the view makes no claim.
	EnforcedText string `json:"enforced_text,omitempty"`
	// ByKernel is true when the operating system enforces the rule in full (State enforced, said "Enforced by the
	// operating system"): the usual case, which a rules table may leave unsaid so the exceptions stand out. A view
	// keys that on ByKernel, never on EnforcedText's words.
	ByKernel bool `json:"by_kernel,omitempty"`
	// Source is where the rule came from.
	Source Source `json:"source"`
	// Editable is true for an entry of the top-level contract under a key the dashboard's change form edits.
	Editable bool `json:"editable"`
	// Hits is how many ledger lines named the rule (RuleKey and Covers), as Count added them.
	Hits int `json:"hits"`
	// Live is a live block's state now (internal/check/livestatus), "" for every other rule. The live group's
	// heading follows it: a group that refuses nothing is not headed "Blocked".
	Live livestatus.State `json:"live,omitempty"`
}

// Group is one heading of the view.
type Group struct {
	// ID is one of the Group ids.
	ID string `json:"id"`
	// Title is the heading: "Can change".
	Title string `json:"title"`
	// Lede is one line under the heading saying what the group is about.
	Lede string `json:"lede"`
	// Rules are the group's rules in contract order, then the built-in and runtime ones.
	Rules []Rule `json:"rules"`
	// Default says what happens to everything the rules do not name ("Cannot change any other file."); "" when
	// nothing needs saying.
	Default string `json:"default,omitempty"`
	// Open is true when Default leaves the agent wide open where a contract usually narrows it: any address on the
	// network, any program, every variable of the shell (secrets included). Reads are open by design (only secrets
	// and the never-read entries are closed), so the read group's default is never open. A view keys its mark on
	// Open, never on Default's words.
	Open bool `json:"open,omitempty"`
	// DefaultKind is the kind of the ledger lines no rule names whose verdict the group's default gives: "exec" for
	// the programs, "net" for the network, "" for the other groups (a file line's op, not its kind, says whether it read
	// or changed a file). DefaultHits is how many such lines CountDefault added: lines of the run the default decided.
	DefaultKind string `json:"default_kind,omitempty"`
	DefaultHits int    `json:"default_hits,omitempty"`
}

// View is the rules in force for one contract.
type View struct {
	// Agent is the contract's name.
	Agent string `json:"agent"`
	// ContractPath is the top-level contract file.
	ContractPath string `json:"contract_path"`
	// Tier is the tier the enforcement claims hold for, "" for a view built from text.
	Tier string `json:"tier,omitempty"`
	// Compiled is true when the view was built from a compiled table (Of), false for Declared.
	Compiled bool `json:"compiled"`
	// Groups are every group, in GroupOrder, empty ones included.
	Groups []Group `json:"groups"`
	// Notes are sentences about the whole view: the profiles it extends, what it cannot show.
	Notes []string `json:"notes,omitempty"`
	// Unmatched is how many ledger lines Count saw that no rule named (the defaults decided them), every kind; a group's
	// DefaultHits says how many of them its default decided.
	Unmatched int `json:"unmatched"`
}

// Group returns the group with id, nil when there is none.
func (v *View) Group(id string) *Group {
	for i := range v.Groups {
		if v.Groups[i].ID == id {
			return &v.Groups[i]
		}
	}
	return nil
}

// Rules returns every rule of the view in display order.
func (v *View) Rules() []Rule {
	var out []Rule
	for _, g := range v.Groups {
		out = append(out, g.Rules...)
	}
	return out
}

// editableKeys are the contract keys the dashboard's change form adds to and removes from .
var editableKeys = map[string]bool{
	"fs.write": true, "fs.deny_read": true, "fs.ask_read": true, "fs.ask": true, "fs.deny_write": true,
	"exec.allow": true, "net.allow": true, "net.ask": true,
}

// Editable reports whether the dashboard's change form edits the contract key.
func Editable(key string) bool { return editableKeys[key] }

// Of is the rules in force for a run of the compiled table at tier, whose decision plane is planeMode (run_start's
// decision_plane, "" where none decides). The table's merged contract gives the entries and their positions; the
// table gives what the run enforces of each.
func Of(rt *agent.RuleTable, tier backend.Tier, planeMode string) View {
	if rt == nil || rt.Contract == nil {
		v := New()
		v.Notes = append(v.Notes, "No compiled rules to show.")
		return v
	}
	path := rt.ContractPath
	if path == "" {
		path = rt.Contract.File()
	}
	d := fromContract(rt.DecisionContract(), path)
	v := Build(d, rt, tier, planeMode)
	v.Tier = string(tier)
	v.Compiled = true
	return v
}

// Build renders already parsed declaration data. A nil table makes no
// enforcement claim, for the dashboard's permissive source fallback.
func Build(d Declaration, rt *agent.RuleTable, tier backend.Tier, planeMode string) View {
	var f *facts
	if rt != nil {
		f = newFacts(rt, tier, planeMode)
	}
	return build(d, f)
}
