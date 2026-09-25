// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestAutoResolvesToTheHighestTierTheBuildHas is ADR 0019 (1): tier: auto compiled to bpflsm, a tier no build
// contains, whatever the binary. With the build's tiers given, auto resolves to the highest of them, Reach
// lists every tier an auto run may land at, and a pin, the contract's or the machine config's, is its one
// tier, since a pin is refused rather than lowered.
func TestAutoResolvesToTheHighestTierTheBuildHas(t *testing.T) {
	landlock, cgroup, bpflsm := backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM
	cases := []struct {
		name        string
		pin         string
		machine     backend.Tier
		built       []backend.Tier
		given       bool
		tier        backend.Tier
		reach       []backend.Tier
		capture     CaptureMode
		lowerSaysSo string
	}{
		{"no build given: the ceiling, as before", "", backend.TierAuto, nil, false, bpflsm, []backend.Tier{bpflsm}, CaptureUprobe, ""},
		{"a tier-1 build", "", backend.TierAuto, []backend.Tier{landlock}, true, landlock, []backend.Tier{landlock}, CaptureForwarder, ""},
		{"the released build", "", backend.TierAuto, []backend.Tier{landlock, cgroup}, true, cgroup, []backend.Tier{landlock, cgroup}, CaptureUprobe, ""},
		{"a contract pin is its one tier", "tier: cgroup\n", backend.TierAuto, []backend.Tier{landlock, cgroup}, true, cgroup, []backend.Tier{cgroup}, CaptureUprobe, ""},
		{"a pin to a tier no build has stays, and is refused at run", "tier: bpflsm\n", backend.TierAuto, []backend.Tier{landlock, cgroup}, true, bpflsm, []backend.Tier{bpflsm}, CaptureUprobe, ""},
		{"a machine config's concrete tier pins it", "", landlock, []backend.Tier{landlock, cgroup}, true, landlock, []backend.Tier{landlock}, CaptureForwarder, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.machine.Tier = tierCeil(tc.machine)
			c := f.load("version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\n" + tc.pin + "net: {}\n")
			var opts []CompileOption
			if tc.given {
				opts = append(opts, WithTiers(tc.built...))
			}
			rt, _ := f.compile(c, opts...)
			if rt.Tier != tc.tier || !slices.Equal(rt.Reach, tc.reach) || rt.Capture != tc.capture {
				t.Errorf("tier %s reach %v capture %s, want %s %v %s", rt.Tier, rt.Reach, rt.Capture, tc.tier, tc.reach, tc.capture)
			}
		})
	}
}

// TestALandlockFindingIsReportedWhereTheRunCanLandThere: a deny_read
// beneath a write entry is unenforced at landlock, and the warning that says so was given only to a table
// compiled to landlock, so an auto contract, compiled to bpflsm, never saw it while its unprivileged runs
// read the secret. It is now given whenever landlock is in the table's reach, marked as landlock's alone
// (Diagnostic.Tier) so `tego run` prints it only to a run that got that tier.
func TestALandlockFindingIsReportedWhereTheRunCanLandThere(t *testing.T) {
	const contract = "version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\n%sfs:\n  reads: direct\n  write: [\"out/\"]\n  deny_read: [\"out/keys/\"]\nnet: {}\n"
	for _, tc := range []struct {
		name  string
		pin   string
		built []backend.Tier
		want  bool
	}{
		{"auto on the released build", "", []backend.Tier{backend.TierLandlock, backend.TierCgroup}, true},
		{"auto on a tier-1 build", "", []backend.Tier{backend.TierLandlock}, true},
		{"pinned to landlock", "tier: landlock\n", []backend.Tier{backend.TierLandlock, backend.TierCgroup}, true},
		{"pinned to cgroup, which never runs at landlock", "tier: cgroup\n", []backend.Tier{backend.TierLandlock, backend.TierCgroup}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			mkdirAll(t, filepath.Join(f.project, "out", "keys"))
			c := f.load(strings.Replace(contract, "%s", tc.pin, 1))
			_, ds := f.compile(c, WithTiers(tc.built...))
			var found *Diagnostic
			for i := range ds {
				if ds[i].Code == CodeUnenforced && strings.Contains(ds[i].Message, "unenforced in the landlock tier") {
					found = &ds[i]
				}
			}
			switch {
			case tc.want && found == nil:
				t.Fatalf("no landlock warning:\n%s", render(ds))
			case !tc.want && found != nil:
				t.Fatalf("a table that never runs at landlock was warned: %v", *found)
			case found != nil && found.Tier != backend.TierLandlock:
				t.Errorf("warning's Tier = %q, want landlock alone", found.Tier)
			}
			if found != nil {
				if got := ForTier(ds, backend.TierCgroup); slices.ContainsFunc(got, func(d Diagnostic) bool { return d.Tier != "" }) {
					t.Errorf("ForTier(cgroup) kept a landlock-only finding: %v", got)
				}
				if got := ForTier(ds, backend.TierLandlock); !slices.ContainsFunc(got, func(d Diagnostic) bool { return d.Tier == backend.TierLandlock }) {
					t.Errorf("ForTier(landlock) dropped the landlock finding: %v", got)
				}
			}
		})
	}
}

// TestAPinTheBuildLacksIsWarned: a contract, or a machine config, pinning a
// tier this binary does not build compiled without a word, and every run of it was then refused. It warns
// [tier-unavailable], naming who pinned it; a pin the build has, and an auto contract, do not.
func TestAPinTheBuildLacksIsWarned(t *testing.T) {
	f := newFixture(t)
	warned := func(ds []Diagnostic, by string) bool {
		return slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == backend.CodeTierUnavailable && !d.IsError() &&
				strings.Contains(d.Message, "not built into this tego") && strings.Contains(d.Message, by)
		})
	}
	built := WithTiers(backend.TierLandlock)
	pinned := f.load("version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\ntier: bpflsm\nnet: {}\n")
	if _, ds := f.compile(pinned, built); !warned(ds, "the contract pins it") {
		t.Errorf("a contract pin of bpflsm on a landlock build: no warning\n%s", render(ds))
	}
	own := f.load("version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\ntier: landlock\nnet: {}\n")
	if _, ds := f.compile(own, built); warned(ds, "") {
		t.Errorf("a pin the build has warned:\n%s", render(ds))
	}
	auto := f.load("version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\nnet: {}\n")
	if _, ds := f.compile(auto, built); warned(ds, "") {
		t.Errorf("an auto contract warned:\n%s", render(ds))
	}
	f.machine.Tier = tierCeil(backend.TierCgroup)
	if _, ds := f.compile(auto, built); !warned(ds, "the machine config pins it") {
		t.Errorf("a machine pin of cgroup on a landlock build: no warning\n%s", render(ds))
	}
}

// TestSetuidOnAnAutoContractIsNotRefusedForTheBuild: a tier-1 build resolves auto to landlock, where no_new_privs
// is mandatory. That is the build's limit, not the contract's pin, so the contract still compiles, with the
// landlock-only warning that setuid has no effect there; a pin to landlock is still the error it was.
func TestSetuidOnAnAutoContractIsNotRefusedForTheBuild(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\nsetuid: true\nnet: {}\n")
	_, ds := f.compile(c, WithTiers(backend.TierLandlock))
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Tier == backend.TierLandlock && strings.Contains(d.Message, "setuid: true has no effect in the landlock tier")
	}) {
		t.Fatalf("no landlock-only setuid warning:\n%s", render(ds))
	}
	pinned := f.load("version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\ntier: landlock\nsetuid: true\nnet: {}\n")
	if _, ds, err := Compile(pinned, f.machine, f.opts(WithTiers(backend.TierLandlock, backend.TierCgroup))...); err == nil {
		t.Fatalf("setuid: true pinned to landlock compiled:\n%s", render(ds))
	}
}

// TestATestRowAnswersInEveryTierOfTheReach is ADR 0019 (2): a row with no tier:
// asserting a refusal that only the root tiers make passed, because rows answered in the tier auto compiled
// to, and the run at landlock allowed the read. It now fails, naming landlock's answer; a row's own tier:
// narrows it to that tier.
func TestATestRowAnswersInEveryTierOfTheReach(t *testing.T) {
	f := newFixture(t)
	mkdirAll(t, filepath.Join(f.project, "out", "keys"))
	c := f.load("version: 0\nname: reach\ncommand: [\"python\", \"agent.py\"]\nfs:\n  reads: direct\n  write: [\"out/\"]\n  deny_read: [\"out/keys/\"]\nnet: {}\n")
	rt, _ := f.compile(c, WithTiers(backend.TierLandlock, backend.TierCgroup))
	table, ds, err := LoadTestTableBytes("t.yaml", []byte(`version: 0
tests:
  - name: every tier
    action: fs.read
    path: out/keys/token
    expect: refused
  - name: tier 2 alone
    action: fs.read
    path: out/keys/token
    tier: cgroup
    expect: refused
`))
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	res := table.Run(rt, f.project)
	if len(res) != 2 {
		t.Fatalf("%d results", len(res))
	}
	every := res[0]
	if every.Pass || len(every.Columns) != 2 || every.Tier != backend.TierLandlock || every.Got.Verdict != VerdictAllow {
		t.Errorf("row with no tier: pass %v, %d columns, reported %s %s; want a failure at landlock over two columns",
			every.Pass, len(every.Columns), every.Tier, every.Got.Verdict)
	}
	if len(every.Columns) == 2 && (every.Columns[1].Tier != backend.TierCgroup || !every.Columns[1].Pass) {
		t.Errorf("cgroup column %+v, want a refusal that passes", every.Columns[1])
	}
	if one := res[1]; !one.Pass || len(one.Columns) != 1 || one.Tier != backend.TierCgroup {
		t.Errorf("row pinned to cgroup: pass %v, %d columns, tier %s", one.Pass, len(one.Columns), one.Tier)
	}
	if got := table.Run(rt, f.project, backend.TierCgroup); !got[0].Pass {
		t.Errorf("given cgroup alone, the row failed: %+v", got[0])
	}
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestRecordOffWithUprobeWarnsThatBudgetsSeeNothing: under
// record: off the uprobe source captures nothing, so a tokens, cost_usd or repeats budget saw no model traffic
// and never tripped, with nothing said. Compile says so; the forwarder, which records what it relays under
// off, and a contract with no such budget are not warned, nor is an auto contract with a models: endpoint, which
// compiles to the forwarder under record: off (TestRecordOffAutoCapturesWithTheForwarder). A budget the contract declares is [budget-unmetered],
// since such a run is refused at launch (runtime.ErrBudgetUnmetered); one a machine ceiling alone imposes stays
// [unenforced], since that run is not refused.
func TestRecordOffWithUprobeWarnsThatBudgetsSeeNothing(t *testing.T) {
	const base = "version: 0\nname: offbudget\ncommand: [\"python\", \"agent.py\"]\nnet: {}\nrecord: off\n" +
		"models:\n  - { provider: anthropic, host: api.anthropic.com, port: 443 }\n"
	for _, tc := range []struct {
		name, extra   string
		machineTokens bool
		want          string // the code of the warning, "" for none
	}{
		{"uprobe with a token budget", "capture: uprobe\nlimits: {tokens: 1000}\n", false, identity.CodeBudgetUnmetered},
		{"uprobe with a machine token ceiling alone", "capture: uprobe\n", true, CodeUnenforced},
		{"uprobe with no budget", "capture: uprobe\n", false, ""},
		{"forwarder with a token budget", "capture: forwarder\nlimits: {tokens: 1000}\n", false, ""},
		// auto under record: off compiles to the forwarder, which records under record: off, with its models[]
		// endpoints guarded, so the run is metered and not refused.
		{"auto with a token budget", "limits: {tokens: 1000}\n", false, ""},
		{"auto with a machine token ceiling alone", "", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// No machine ceiling on the three budgets, so only the contract's own can set one.
			f.machine.Limits.Tokens = config.Ceiling[int64]{}
			f.machine.Limits.CostUSD = config.Ceiling[float64]{}
			f.machine.Limits.Repeats = config.Ceiling[int]{}
			if tc.machineTokens {
				f.machine.Limits.Tokens = config.Ceiling[int64]{Value: 1000, Bounded: true}
			}
			c := f.load(base + tc.extra)
			_, ds := f.compile(c, WithTiers(backend.TierLandlock, backend.TierCgroup))
			var got []string
			for _, d := range ds {
				if strings.Contains(d.Message, "sees none of it") {
					got = append(got, d.Code)
				}
			}
			want := []string{}
			if tc.want != "" {
				want = []string{tc.want}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("warned %v, want %v:\n%s", got, want, render(ds))
			}
		})
	}
}

// TestRecordOffFromTheFlagBlamesTheFlag: `tego run --record off`
// (WithRecord) leaves the uprobe budgets as blind as the contract's record: off, and the warning says what did it.
// When the flag changed the mode (a summary contract, or one with no record key), it names --record off, points at
// the budget rather than at a record: key the contract may not have (or that says summary), and tells the user to run
// without the flag rather than to write what the contract already says. When the contract says record: off itself,
// running without the flag changes nothing: the warning names both, sits at the record: key, and its fix is --record
// summary with record: summary. A budget only the machine's ceiling sets is named as the ceiling's, not placed at line 1
// as if the contract had it. A budget the contract declares under a pinned capture: uprobe is [budget-unmetered], since
// such a run is refused (R32); one the ceiling alone imposes stays [unenforced].
func TestRecordOffFromTheFlagBlamesTheFlag(t *testing.T) {
	const models = "models:\n  - { provider: anthropic, host: api.anthropic.com, port: 443 }\ncapture: uprobe\n"
	for _, tc := range []struct {
		name, record, limits string
		ceiling              bool // the machine config sets a tokens ceiling
		opts                 []CompileOption
		starts               string // the message's first words
		at                   string // the key the warning sits at, "" for the contract's line 1
		fix, notFix          []string
		says                 string
	}{
		{name: "record: summary", record: "record: summary\n", limits: "limits: {tokens: 1000}\n", opts: []CompileOption{WithRecord(RecordOff)},
			starts: "--record off with capture: uprobe", at: "limits.tokens", fix: []string{"run without --record off"}, notFix: []string{"set record"}},
		{name: "no record key", limits: "limits: {tokens: 1000}\n", opts: []CompileOption{WithRecord(RecordOff)},
			starts: "--record off with capture: uprobe", at: "limits.tokens", fix: []string{"run without --record off"}, notFix: []string{"set record"}},
		{name: "record: off contract", record: "record: off\n", limits: "limits: {tokens: 1000, stall_after: 2s}\n", opts: []CompileOption{WithRecord(RecordOff)},
			starts: "record: off, which --record off repeats, with capture: uprobe", at: "record",
			fix: []string{"run with --record summary and set record: summary"}, notFix: []string{"without --record off"}},
		{name: "record: off contract, no flag", record: "record: off\n", limits: "limits: {tokens: 1000}\n",
			starts: "record: off with capture: uprobe", at: "record", fix: []string{"set record: summary"}, notFix: []string{"--record"}},
		{name: "the flag, a ceiling's budget only", ceiling: true, opts: []CompileOption{WithRecord(RecordOff)},
			starts: "--record off with uprobe capture", at: "", fix: []string{"run without --record off"},
			says: "the tokens budget, which the machine config's ceiling sets ("},
		{name: "the flag, a ceiling's budget and the contract's", ceiling: true, limits: "limits: {cost_usd: 1}\n", opts: []CompileOption{WithRecord(RecordOff)},
			starts: "--record off with capture: uprobe", at: "limits.cost_usd", fix: []string{"run without --record off"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.machine.Limits.Tokens = config.Ceiling[int64]{}
			f.machine.Limits.CostUSD = config.Ceiling[float64]{}
			f.machine.Limits.Repeats = config.Ceiling[int]{}
			if tc.ceiling {
				f.machine.Limits.Tokens = bounded(int64(5000))
			}
			c := f.load("version: 0\nname: offbudget\ncommand: [\"python\", \"agent.py\"]\nnet: {}\n" + tc.record + models + tc.limits)
			_, ds := f.compile(c, append([]CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup)}, tc.opts...)...)
			i := slices.IndexFunc(ds, func(d Diagnostic) bool {
				return (d.Code == CodeUnenforced || d.Code == identity.CodeBudgetUnmetered) && strings.Contains(d.Message, "sees none of it")
			})
			if i < 0 {
				t.Fatalf("record off with uprobe capture and a tokens budget was not warned:\n%s", render(ds))
			}
			d := ds[i]
			want := identity.CodeBudgetUnmetered // a declared budget: its run is refused (R32)
			if tc.limits == "" {
				want = CodeUnenforced // the ceiling's budget alone: the run goes ahead with a gap
			}
			if d.Code != want {
				t.Fatalf("the warning is [%s], want [%s]:\n%s", d.Code, want, render(ds))
			}
			if !strings.HasPrefix(d.Message, tc.starts) || !strings.Contains(d.Message, tc.says) {
				t.Fatalf("the warning %q: want it to start %q and say %q", d.Message, tc.starts, tc.says)
			}
			wantLine := 1
			if tc.at != "" {
				wantLine = c.origins[tc.at].Line
			}
			if d.Line != wantLine || wantLine == 0 {
				t.Fatalf("the warning sits at line %d, want %d (%s)", d.Line, wantLine, tc.at)
			}
			for _, s := range tc.fix {
				if !strings.Contains(d.Fix, s) {
					t.Fatalf("the fix %q: want it to say %q", d.Fix, s)
				}
			}
			for _, s := range tc.notFix {
				if strings.Contains(d.Fix, s) {
					t.Fatalf("the fix %q says %q, which does not change this run", d.Fix, s)
				}
			}
		})
	}
}
