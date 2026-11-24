// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/compiledview"
	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	GroupRead         = compiledview.GroupRead
	GroupChange       = compiledview.GroupChange
	GroupAsk          = compiledview.GroupAsk
	GroupNeverRead    = compiledview.GroupNeverRead
	GroupNeverChange  = compiledview.GroupNeverChange
	GroupPrograms     = compiledview.GroupPrograms
	GroupNetwork      = compiledview.GroupNetwork
	GroupEnv          = compiledview.GroupEnv
	GroupLimits       = compiledview.GroupLimits
	GroupLive         = compiledview.GroupLive
	GroupAlwaysOn     = compiledview.GroupAlwaysOn
	StateEnforced     = compiledview.StateEnforced
	StateBestEffort   = compiledview.StateBestEffort
	StateNotEnforced  = compiledview.StateNotEnforced
	StateNone         = compiledview.StateNone
	EffectAllow       = compiledview.EffectAllow
	EffectAsk         = compiledview.EffectAsk
	EffectDeny        = compiledview.EffectDeny
	EffectLimit       = compiledview.EffectLimit
	EffectNote        = compiledview.EffectNote
	OriginContract    = compiledview.OriginContract
	OriginProfile     = compiledview.OriginProfile
	OriginBuiltIn     = compiledview.OriginBuiltIn
	OriginTego        = compiledview.OriginTego
	OriginCommandLine = compiledview.OriginCommandLine
	OriginMachine     = compiledview.OriginMachine
)

var GroupOrder = compiledview.GroupOrder

// State is the shared compiled-view state.
type State = compiledview.State

// Effect is the shared compiled-view effect.
type Effect = compiledview.Effect

// Source is the shared compiled-view source.
type Source = compiledview.Source

// Rule is the shared compiled-view rule.
type Rule = compiledview.Rule

// Group is the shared compiled-view group.
type Group = compiledview.Group

// View adds ledger hits, source fallback and live rules to the shared compiled view.
type View compiledview.View

// Group returns the group with id, nil when absent.
func (v *View) Group(id string) *Group { return (*compiledview.View)(v).Group(id) }

// Rules returns the view's rules in display order.
func (v *View) Rules() []Rule { return (*compiledview.View)(v).Rules() }

func newView() View { return View(compiledview.New()) }

// Editable reports whether the dashboard's change form edits entries of the contract key.
func Editable(key string) bool { return compiledview.Editable(key) }

// Of projects the compiled table using the shared sentence renderer.
func Of(rt *agent.RuleTable, tier backend.Tier, planeMode string) View {
	return View(compiledview.Of(rt, tier, planeMode))
}

// Declared is the rules in force read from a contract's text alone, for a contract that no longer compiles: the
// same groups and sentences, positions from the text, and no enforcement claim. Profiles it extends are named in a
// note, not read. err is non-nil only when text is not YAML; the view then holds that note alone.
func Declared(text []byte, path string) (View, error) {
	d, err := fromYAML(text, path)
	if err != nil {
		v := newView()
		v.ContractPath = path
		v.Notes = append(v.Notes, "The rules file is not valid YAML, so no rules can be shown.")
		return v, err
	}
	v := View(compiledview.Build(d, nil, "", ""))
	v.Notes = append(v.Notes, "Read from the file as written: it does not compile now, so nothing here says what a run enforces.")
	return v, nil
}

// AddLive lists a running run's live block in the live group, claiming it in force: kind is liveblock's "exec", "net"
// or "path", value its normalized value, by who added it ("uid:1000 pid:42 dashboard"). Its rule key is the one a
// refusal under it carries, live.block[kind:value]. A caller that knows the run's facts says the block's state with
// AddLiveStatus instead.
func (v *View) AddLive(kind, value, by string) {
	v.AddLiveStatus(kind, value, by, livestatus.InForce, textLive)
}

// AddLiveStatus lists a running run's live block in the live group with its state now (internal/check/livestatus):
// state and sentence are livestatus.Status's for the block on its run, so a block on a watched run reads "Recorded,
// not enforced" and a path block on a run that does not see its reads says reads still go through. The rule is
// LiveRule's.
func (v *View) AddLiveStatus(kind, value, by string, state livestatus.State, sentence string) {
	g := v.Group(GroupLive)
	if g == nil {
		return
	}
	g.Rules = append(g.Rules, LiveRule(kind, value, by, state, sentence))
	g.Title, g.Lede, g.Default = liveGroupCopy(g.Rules)
}

// LiveRule is a live block said as a rule in its state (AddLiveStatus's arguments), without adding it to a group. Its
// rule key is the one a refusal under it carries, live.block[kind:value]. Only an in-force or partial block is best
// effort; every other state is not enforced. An ended run's blocks are said by EndedLiveRule, which builds on it.
func LiveRule(kind, value, by string, state livestatus.State, sentence string) Rule {
	st := StateNotEnforced
	if state.Refuses() {
		st = StateBestEffort
	}
	return Rule{
		Group: GroupLive, Key: "live.block", Entry: kind + ":" + value,
		RuleKey: "live.block[" + kind + ":" + value + "]", Target: value, Effect: EffectDeny,
		Enforced: false, State: st, EnforcedText: sentence, Source: Source{Origin: OriginLive(by)}, Live: state,
		Sentence: liveSentenceIn(kind, value, state),
	}
}

// EndedLiveRule is a live block of a run that has ended, said as a rule by what it did while the run ran, without
// adding it to a group: a caller lists an ended run's blocks apart from the live group, whose rules each refuse
// something now or will. was is the block's state as livestatus.Status gave it on the run's facts with the run not
// ended, against the serial of the add that made it: a block the run put in force reads "Was blocked: cannot run curl"
// (a path block on a run that did not see its reads "Was blocked: cannot change /p/data (reads went through)"), a
// watched run's mark "Was marked (recorded, not refused): …", and a block the run ended before putting in force "Never
// put in force: …". Any other state claims nothing: "Ended with the run: …". Its state now is livestatus.Ended, not
// enforced, so nothing says it refuses anything now.
func EndedLiveRule(kind, value, by string, was livestatus.State) Rule {
	sentence, text := liveEnded(kind, value, was)
	r := LiveRule(kind, value, by, livestatus.Ended, text)
	r.Sentence = sentence
	return r
}

// OriginLive is a live block's origin: who added it, as liveblock recorded the writer.
func OriginLive(by string) string {
	if by == "" {
		return "live block"
	}
	return "live block by " + by
}

// AddHarnessHook lists the exec grant the runtime made on its own authority for the run's harness hook (ADR 0064),
// as run_start's runtime_grants names it: ruleKey is exec.harness-hook[<tego binary>], the rule its lines carry. The
// grant admits the tego binary with the hook's exact arguments and no others, so it is a rule in force among the
// programs, said as the runtime's own (Source origin tego). A key that is not a harness hook's adds nothing. Count
// then counts its lines like any rule's.
func (v *View) AddHarnessHook(ruleKey string) {
	rest, isHook := strings.CutPrefix(ruleKey, "exec."+agent.HarnessHookGrant+"[")
	bin, closed := strings.CutSuffix(rest, "]")
	if !isHook || !closed || bin == "" {
		return
	}
	g := v.Group(GroupPrograms)
	if g == nil {
		return
	}
	r := Rule{
		Group: GroupPrograms, Key: "runtime." + agent.HarnessHookGrant, Entry: bin, RuleKey: ruleKey, Target: filepath.Base(bin),
		Sentence: "Can run tego's hook command for the agent's harness, with its exact arguments and no others",
		Effect:   EffectAllow, Source: Source{Origin: OriginTego}, EnforcedText: compiledview.TextTegoCommands,
	}
	if v.Tier == string(backend.TierObserve) {
		r.EnforcedText = compiledview.TextObserve
	}
	r.State = compiledview.StateOf(false, r.EnforcedText)
	g.Rules = append(g.Rules, r)
}

// NoteProfiles adds the profiles a run's contract merged through extends (run_start's profiles) to the view's notes,
// each with where it was read: built into tego, or a file of the machine config's profiles directory with the start of
// its sha256, which is what a later edit of that file is told apart by. The rules a profile contributes are listed
// (marked as from a profile) only in a view built from a compiled table; one read as text lists the top file alone, and
// says so.
func (v *View) NoteProfiles(refs []record.ProfileRef) {
	if len(refs) == 0 {
		return
	}
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		switch r.Source {
		case record.ProfileSourceBuiltin:
			parts = append(parts, r.Name+" (built into tego)")
		case record.ProfileSourceDir:
			sum := r.SHA256
			if len(sum) > 12 {
				sum = sum[:12]
			}
			parts = append(parts, r.Name+" (the profiles folder, sha256 "+sum+")")
		default:
			parts = append(parts, r.Name)
		}
	}
	v.Notes = append(v.Notes, "The run merged the profiles "+strings.Join(parts, ", ")+".")
}
