// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// baselinePropertyDecisionError is the partial order the baseline promises over
// the same contract's decisions. Rule precedence may change a refusal reason
// only when the new deciding rule belongs to this baseline and has its reason.
func baselinePropertyDecisionError(table *agent.RuleTable, action agent.Action, before, after agent.EvalResult, tier backend.Tier, plane string) error {
	switch before.Verdict {
	case agent.VerdictRefused:
		if after.Verdict != agent.VerdictRefused {
			return fmt.Errorf("baseline loosened refusal")
		}
		if before.Reason != after.Reason && !baselinePropertyOwnReason(table, action, after, tier, plane) {
			return fmt.Errorf("refusal reason changed without a deciding baseline reason")
		}
	case agent.VerdictAsk:
		if after.Verdict != agent.VerdictAsk && after.Verdict != agent.VerdictRefused {
			return fmt.Errorf("baseline loosened ask")
		}
	case agent.VerdictAllow:
		if after.Verdict != agent.VerdictAllow && after.Verdict != agent.VerdictAsk && after.Verdict != agent.VerdictRefused {
			return fmt.Errorf("baseline returned an unsupported decision")
		}
	default:
		return fmt.Errorf("property received an unsupported original decision %q", before.Verdict)
	}
	return nil
}

func baselinePropertyOwnReason(table *agent.RuleTable, action agent.Action, after agent.EvalResult, tier backend.Tier, plane string) bool {
	if table == nil || table.Baseline == nil || !table.Baseline.Applied {
		return false
	}
	fsAction := false
	switch action.Kind {
	case agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir, agent.ActionFSRename, agent.ActionFSLink, agent.ActionFSAttr:
		fsAction = true
	}
	for _, entry := range table.Baseline.Entries {
		if !slices.Contains(entry.Rules, after.Rule) {
			continue
		}
		switch entry.Key {
		case config.BaselineDenyRead:
			if action.Kind == agent.ActionExec || action.Kind == agent.ActionFSRead || action.Kind == agent.ActionFSWrite && tier == backend.TierCgroup && plane == "fanotify" {
				return after.Reason == record.ReasonReadDenied
			}
			return fsAction && after.Reason == agent.FSReason(action.Kind)
		case config.BaselineDenyWrite:
			return fsAction && action.Kind != agent.ActionFSRead && after.Reason == agent.FSReason(action.Kind)
		case config.BaselineDenyExec:
			return action.Kind == agent.ActionExec && after.Reason == record.ReasonExecNotAllowed
		case config.BaselineDenyEnv:
			return false // Environment names are checked separately, with no syscall reason.
		}
	}
	return false
}

func TestBaselineDecisionTighteningAssertions(t *testing.T) {
	readRule := "fs.deny_read[/machine/read]"
	table := &agent.RuleTable{Baseline: &agent.BaselineTable{Applied: true, Entries: []agent.BaselineRule{{
		ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: config.BaselineDenyRead}}, Rules: []string{readRule},
	}}}}
	result := func(verdict agent.Verdict, rule string, reason record.Reason) agent.EvalResult {
		return agent.EvalResult{Verdict: verdict, Rule: rule, Reason: reason}
	}
	allow := result(agent.VerdictAllow, agent.UnmatchedRule, "")
	ask := result(agent.VerdictAsk, "gate.rule[read]", "")
	refusal := result(agent.VerdictRefused, "gate.rule[read]", record.ReasonFSGate)
	baseline := result(agent.VerdictRefused, readRule, record.ReasonReadDenied)
	for _, tc := range []struct {
		name          string
		before, after agent.EvalResult
		wantError     bool
	}{
		{"allow stays allow", allow, allow, false},
		{"allow tightens to ask", allow, ask, false},
		{"allow tightens to refusal", allow, refusal, false},
		{"ask retained", ask, ask, false},
		{"ask tightens", ask, baseline, false},
		{"ask never allows", ask, allow, true},
		{"refusal retained", refusal, refusal, false},
		{"refusal never asks", refusal, ask, true},
		{"refusal never allows", refusal, allow, true},
		{"baseline may replace refusal reason", refusal, baseline, false},
		{"other rule may not replace reason", refusal, result(agent.VerdictRefused, "fs.deny_read[/contract/read]", record.ReasonReadDenied), true},
		{"baseline rule needs own reason", refusal, result(agent.VerdictRefused, readRule, record.ReasonNetNotAllowed), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := baselinePropertyDecisionError(table, agent.Action{Kind: agent.ActionFSRead, Path: "/machine/read/item"}, tc.before, tc.after, backend.TierCgroup, "lsm")
			if (err != nil) != tc.wantError {
				t.Fatalf("decision comparison error=%v, want error=%t: before=%+v after=%+v", err, tc.wantError, tc.before, tc.after)
			}
		})
	}
}

// Dedicated cases keep asks, live transforms and compiler-resolved grant names
// present without multiplying the existing absent/null/empty section product.
func baselinePropertyDecisionSources() []baselinePropertySource {
	fragments := []struct{ name, text string }{
		{"ask-fs", "fs: {ask: [./held]}\n"},
		{"ask-read", "fs: {ask_read: [./held]}\n"},
		{"ask-net", "net: {ask: ['192.0.2.40:443']}\n"},
		{"ask-gate-read", "gate: {rules: [{'fs.read matches \"../read/*\"': 70}]}\n"},
		{"ask-gate-write", "fs: {write: ['../write']}\ngate: {rules: [{'fs.write outside worktree': 70}]}\n"},
		{"ask-gate-net", "net: {allow: ['192.0.2.40:443']}\ngate: {rules: [{'net to 192.0.2.40:443': 70}]}\n"},
		{"fence-read", "exec: {allow: [actor]}\nfs: {deny_read: ['../read']}\nlive: {mode: adjustable, fence: {read: ['../read']}}\n"},
		{"fence-exec", "exec: {deny: [git]}\nlive: {mode: adjustable, fence: {exec: ['{{R}}/b/git']}}\n"},
		{"fence-net", "net: {allow: []}\nlive: {mode: adjustable, fence: {net: ['192.0.2.40:443']}}\n"},
		{"exec-glob-rejected", "exec: {allow: ['{{R}}/read/*']}\n"},
	}
	for _, target := range []string{"read", "write", "home"} {
		root := "{{R}}/" + target
		relative := "../" + target
		link := target + "-link"
		if target == "home" {
			root, relative, link = "{{H}}/machine-secrets", "../h/machine-secrets", "home-link"
		}
		spellings := []struct{ name, path string }{
			{"absolute", root + "/out"}, {"relative", relative + "/out"}, {"trailing", root + "/out/"},
			{"link", link + "/out"}, {"glob", root + "/o*"},
		}
		if target == "home" {
			spellings = append(spellings, struct{ name, path string }{"tilde", "~/machine-secrets/out"})
		}
		for _, key := range []string{"write", "ask", "ask_read"} {
			for _, spelling := range spellings {
				fragments = append(fragments, struct{ name, text string }{"alternate-" + target + "-" + key + "-" + spelling.name,
					"fs: {" + key + ": [" + strconv.Quote(spelling.path) + "]}\n"})
			}
		}
	}
	var sources []baselinePropertySource
	for i, fragment := range fragments {
		source := baselinePropertySource{name: fragment.name, group: "generated", text: "version: 0\nname: generated\ncommand: [actor]\n"}
		shape := i % 3
		if strings.HasPrefix(fragment.name, "fence-") {
			shape = 0 // live belongs to the top-level source, never to a profile.
		}
		switch shape {
		case 0:
			source.text += fragment.text
		case 1:
			source.text += "extends: child\n"
			source.profiles = map[string]string{"child": "extends: base\n" + fragment.text, "base": "env: {deny: [PROFILE_SECRET]}\n"}
		case 2:
			source.text += "extends: [left, right]\n"
			source.profiles = map[string]string{"left": "extends: base\n" + fragment.text, "right": "extends: base\n", "base": "env: {deny: [PROFILE_SECRET]}\n"}
		}
		sources = append(sources, source)
	}
	return sources
}

func TestBaselineDecisionCorpusIncludesReviewCases(t *testing.T) {
	counts := map[string]int{}
	for _, source := range baselinePropertyCorpus(t) {
		for _, kind := range []string{"ask-", "fence-", "alternate-", "exec-glob-"} {
			if strings.HasPrefix(source.name, kind) {
				counts[kind]++
			}
		}
	}
	for kind, want := range map[string]int{"ask-": 6, "fence-": 3, "alternate-": 48, "exec-glob-": 1} {
		if counts[kind] != want {
			t.Fatalf("%s generated cases=%d, want %d", kind, counts[kind], want)
		}
	}
}

// The floor models fs.ask/net.ask as refused in P0. The gate step used by
// compile --test supplies real asks, so this cannot pass by counting a refused
// approval scope as an ask comparison.
func TestBaselineDecisionGeneratedAsksAndFences(t *testing.T) {
	var compared, fences int
	for _, source := range baselinePropertyDecisionSources() {
		if !strings.HasPrefix(source.name, "ask-gate-") && !strings.HasPrefix(source.name, "fence-") {
			continue
		}
		t.Run(source.name, func(t *testing.T) {
			world := newBaselinePropertyWorld(t, source)
			chain := (&agent.ProfileChain{}).WithDir(world.profiles)
			contract, ds, err := agent.LoadBytes(world.contract, []byte(world.text), chain)
			if err != nil {
				t.Fatalf("load generated ask: %v %v", err, ds)
			}
			var tables []*agent.RuleTable
			baselines := world.baselines(t)
			for _, machine := range []*config.Machine{baselines[0], baselines[4]} {
				machine.Home = world.home
				machine.LedgerRoot.Value = filepath.Join(world.root, "ledger")
				machine.Tier.Value = config.TierSetting{Tier: string(backend.TierCgroup)}
				machine.Tier.Bounded = true
				table, err := baselinePropertyCompile(t, contract, machine, append(world.owner(),
					agent.WithPATH(world.bin), agent.WithMountInfo(world.mountInfo), agent.WithTiers(backend.TierCgroup),
					agent.WithResolver(baselinePropertyResolver{}), agent.WithEnviron([]string{"PATH=" + world.bin, "HOME=" + world.home}), agent.Offline())...)
				if err != nil {
					t.Fatalf("compile generated ask: %v", err)
				}
				baselinePropertyHostInputs(t, world, table)
				tables = append(tables, table)
			}
			beforeEval, afterEval := baselinePropertyEvaluator(tables[0], backend.TierCgroup, "lsm"), baselinePropertyEvaluator(tables[1], backend.TierCgroup, "lsm")
			var asks, allowedFences int
			for _, action := range world.actions {
				before, after := beforeEval(action), afterEval(action)
				if _, covered := tables[0].Live.For(action); covered && before.Verdict == agent.VerdictAllow {
					allowedFences++
				}
				if before.Verdict == agent.VerdictAsk {
					asks++
				}
				if err := baselinePropertyDecisionError(tables[1], action, before, after, backend.TierCgroup, "lsm"); err != nil {
					t.Fatalf("generated decision loosened: %v", err)
				}
			}
			if strings.HasPrefix(source.name, "ask-gate-") && asks == 0 {
				t.Fatal("generated gate contract produced no ask decisions")
			}
			if strings.HasPrefix(source.name, "fence-") && (!tables[0].Adjustable() || allowedFences == 0) {
				t.Fatal("generated live contract allowed no action through its fence")
			}
			compared += asks
			fences += allowedFences
		})
	}
	t.Logf("GENERATED real-ask-comparisons=%d allowed-live-fence-comparisons=%d", compared, fences)
}
