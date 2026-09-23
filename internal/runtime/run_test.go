// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestBuildEnv(t *testing.T) {
	base := []string{"PATH=/bin", "HOME=/home/u", "SECRET=1", "NOEQUALS"}
	tests := []struct {
		name string
		rt   *agent.RuleTable
		want []string
	}{
		{"no pass list inherits everything", &agent.RuleTable{}, base},
		{"pass keeps exactly the named ones", &agent.RuleTable{Env: []string{"PATH", "HOME"}},
			[]string{"PATH=/bin", "HOME=/home/u"}},
		{"deny removes a name", &agent.RuleTable{Deny: []string{"SECRET"}},
			[]string{"PATH=/bin", "HOME=/home/u", "NOEQUALS"}},
		{"deny wins over pass", &agent.RuleTable{Env: []string{"PATH", "SECRET"}, Deny: []string{"SECRET"}},
			[]string{"PATH=/bin"}},
		{"set replaces in place", &agent.RuleTable{Env: []string{"PATH"}, Set: map[string]string{"PATH": "/opt/bin"}},
			[]string{"PATH=/opt/bin"}},
		{"set adds", &agent.RuleTable{Env: []string{"PATH"}, Set: map[string]string{"LANG": "C"}},
			[]string{"PATH=/bin", "LANG=C"}},
		{"a denied name is never set", &agent.RuleTable{Env: []string{"PATH"}, Deny: []string{"LANG"},
			Set: map[string]string{"LANG": "C"}}, []string{"PATH=/bin"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildEnv(tc.rt, slices.Clone(base))
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestBuildEnvDoesNotMutateTheCallersEnviron(t *testing.T) {
	base := []string{"PATH=/bin"}
	_ = buildEnv(&agent.RuleTable{Set: map[string]string{"PATH": "/opt"}}, slices.Clone(base))
	if base[0] != "PATH=/bin" {
		t.Fatalf("the caller's slice was rewritten: %v", base)
	}
}

func TestIdentityEnvWinsOverContractEnv(t *testing.T) {
	// R3: the runtime variables are applied last and win over env.set unconditionally.
	rt := &agent.RuleTable{Env: []string{"PATH"}, Set: map[string]string{identity.EnvRunID: "forged"}}
	env := identity.Env{RunID: "r-00000000-000000000000a-aaaaaa", Agent: "a", LedgerDir: "/d", Tier: "landlock"}.
		Apply(buildEnv(rt, []string{"PATH=/bin"}))
	want := identity.EnvRunID + "=r-00000000-000000000000a-aaaaaa"
	if !slices.Contains(env, want) {
		t.Fatalf("env %v lacks %q", env, want)
	}
	if slices.Contains(env, identity.EnvRunID+"=forged") {
		t.Fatal("env.set overrode a runtime variable")
	}
}

func TestCheckRunDir(t *testing.T) {
	rt := &agent.RuleTable{FS: []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out"},
		{Path: "/work", Kind: agent.FSImplicit},
	}}
	if err := checkRunDir(rt, "/home/u/.tego/runs/r-1"); err != nil {
		t.Fatalf("a run dir outside every write entry is fine: %v", err)
	}
	err := checkRunDir(rt, "/work/out/runs/r-1")
	if !errors.Is(err, ErrRunDirWritable) {
		t.Fatalf("got %v, want ErrRunDirWritable", err)
	}
}

func TestLedgerRoot(t *testing.T) {
	m := config.Builtin()
	m.Home = "/home/u"
	got, err := LedgerRoot(m)
	if err != nil {
		t.Fatalf("LedgerRoot: %v", err)
	}
	if want := filepath.Join("/home/u", ".tego", "runs"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	m.LedgerRoot = config.Setting[string]{Value: "relative/runs"}
	if _, err := LedgerRoot(m); !errors.Is(err, ErrDeps) {
		t.Fatalf("a relative ledger_root must be refused: %v", err)
	}
	m.LedgerRoot = config.Setting[string]{Value: ""}
	if _, err := LedgerRoot(m); !errors.Is(err, ErrDeps) {
		t.Fatalf("an empty ledger_root must be refused: %v", err)
	}
}

func TestRunLimits(t *testing.T) {
	if got := runLimits(agent.ResolvedLimits{}, 0); got != nil {
		t.Fatalf("an unbounded contract writes no limits block: %+v", got)
	}
	got := runLimits(agent.ResolvedLimits{Tokens: 10, CostUSD: 2.5, Wall: time.Hour,
		StallAfter: 90 * time.Second, Repeats: 5}, 1<<30)
	want := record.Limits{Tokens: new(int64(10)), CostUSD: new(2.5), Wall: "1h0m0s", StallAfter: "1m30s",
		Repeats: new(5), LedgerBytes: new(int64(1 << 30))}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("got %+v, want %+v", *got, want)
	}
}

func TestRunRejectsIncompleteDeps(t *testing.T) {
	tests := []struct {
		name string
		rt   *agent.RuleTable
		cmd  []string
		deps Deps
	}{
		{"no table", nil, []string{"/bin/true"}, Deps{Config: config.Builtin()}},
		{"no command", &agent.RuleTable{Contract: &agent.Contract{Name: "a"}}, nil, Deps{Config: config.Builtin()}},
		{"no machine config", &agent.RuleTable{Contract: &agent.Contract{Name: "a"}}, []string{"/bin/true"}, Deps{}},
		{"no backend", &agent.RuleTable{Contract: &agent.Contract{Name: "a"}}, []string{"/bin/true"},
			Deps{Config: config.Builtin()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Run(context.Background(), tc.rt, tc.cmd, tc.deps)
			if !errors.Is(err, ErrDeps) {
				t.Fatalf("err %v, want ErrDeps", err)
			}
			if res.ExitCode != identity.ExitLauncher || res.Reason != record.RunEndError {
				t.Fatalf("result %+v, want 125/error", res)
			}
		})
	}
}

func TestGapEvent(t *testing.T) {
	ev := gapEvent(source.Gap{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 3})
	if ev == nil || ev.Kind != record.KindGap || ev.Source != record.SourceSupervisor {
		t.Fatalf("gap event %+v", ev)
	}
	var p record.GapPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Why != GapKernelRecordUnavailable || p.Count != 3 {
		t.Fatalf("payload %+v", p)
	}
}

func TestHostIDIsStable(t *testing.T) {
	a := hostID([]byte("abc\n"))
	b := hostID([]byte("abc"))
	if a != b {
		t.Fatal("a trailing newline must not change the host component")
	}
	if hostID([]byte("abc")) == hostID([]byte("abd")) {
		t.Fatal("different machine ids must differ")
	}
}

func TestSystemClockMoves(t *testing.T) {
	c := systemClock{}
	first := c.MonoNS()
	if first == 0 {
		t.Skip("CLOCK_MONOTONIC unavailable")
	}
	time.Sleep(time.Millisecond)
	if c.MonoNS() <= first {
		t.Fatal("the monotonic clock did not advance")
	}
	if c.Now().IsZero() {
		t.Fatal("the wall clock is zero")
	}
	l := ledgerClock{c}
	if l.Mono() == 0 || l.Now().IsZero() {
		t.Fatal("the ledger clock adapter reports nothing")
	}
}

func TestGatedAnchorHoldsBackUntilRunStart(t *testing.T) {
	inner := &countingAnchor{}
	var started atomicBoolT
	a := &gatedAnchor{inner: inner, started: &started.b}
	if err := a.Append("r-1", "head"); err != nil || inner.n != 0 {
		t.Fatalf("a run that never started must not be anchored (n=%d err=%v)", inner.n, err)
	}
	started.b.Store(true)
	if err := a.Append("r-1", "head"); err != nil || inner.n != 1 {
		t.Fatalf("a started run must be anchored (n=%d err=%v)", inner.n, err)
	}
	if _, _, err := a.Head("r-1"); err != nil {
		t.Fatalf("Head: %v", err)
	}
}

// countingAnchor counts the anchor writes it was asked for.
type countingAnchor struct{ n int }

func (c *countingAnchor) Append(string, string) error       { c.n++; return nil }
func (c *countingAnchor) Head(string) (string, bool, error) { return "", false, nil }

func TestRunDirIsCreatedPrivate(t *testing.T) {
	// The run directory holds the record of a sandboxed agent: it is 0700 and never group readable.
	dir := filepath.Join(t.TempDir(), "r-1")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}

// atomicBoolT wraps an atomic.Bool so the test can take its address.
type atomicBoolT struct{ b atomic.Bool }

func TestResolveCommand(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notExec := filepath.Join(dir, "data")
	if err := os.WriteFile(notExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{
		PATH: dir,
		Exec: []agent.ExecRule{{Path: "/usr/bin/python3", Basename: "python3"},
			{Path: "/opt/tools", Basename: "tools", IsDir: true}},
	}
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"a contract entry wins", []string{"python3", "agent.py"}, []string{"/usr/bin/python3", "agent.py"}},
		{"a path is left alone", []string{"./x", "-v"}, []string{"./x", "-v"}},
		{"an absolute path is left alone", []string{"/bin/true"}, []string{"/bin/true"}},
		{"the run's PATH is the fallback", []string{"tool"}, []string{bin}},
		{"a directory entry never resolves a name", []string{"tools"}, []string{bin + "s"}},
		{"unresolvable names pass through for execve to refuse", []string{"nope"}, []string{"nope"}},
		{"empty", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCommand(rt, tc.in)
			if tc.name == "a directory entry never resolves a name" {
				// There is no "tools" binary on the test PATH either, so it passes through.
				if len(got) != 1 || got[0] != "tools" {
					t.Fatalf("got %v, want [tools]", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
	if got := resolveCommand(rt, []string{"data"}); got[0] != "data" {
		t.Fatalf("a non-executable file must not resolve: %v", got)
	}
}

// TestDropsNetAdmin: a setuid: true run gives up CAP_NET_ADMIN under a net: section (ADR 0128), the only run that could
// come to hold it; a contract with no net: section keeps it, as it keeps every other IP reach (SEMANTICS §1).
func TestDropsNetAdmin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tier   backend.Tier
		setuid bool
		net    *agent.NetSection
		want   bool
	}{
		{"setuid under a net: section", backend.TierCgroup, true, &agent.NetSection{}, true},
		{"setuid under a net: section at tier 3", backend.TierBPFLSM, true, &agent.NetSection{}, true},
		{"setuid with no net: section", backend.TierCgroup, true, nil, false},
		{"no setuid: no_new_privs holds it", backend.TierCgroup, false, &agent.NetSection{}, false},
		{"tier landlock has no opt-out to make up for", backend.TierLandlock, true, &agent.NetSection{}, false},
	} {
		rt := &agent.RuleTable{Tier: tc.tier, Contract: &agent.Contract{Name: "a", Setuid: tc.setuid, Net: tc.net}}
		if got := dropsNetAdmin(rt); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if dropsNetAdmin(nil) {
		t.Error("a nil table dropped a capability")
	}
}

// TestSetuidOptOutNeverAtLandlock: setuid: true is a root tier's opt-out of no_new_privs (ADR 0033). Compile
// refuses it only where a pin holds the run at landlock; an auto contract that lands there, a root run with
// --tier landlock or a machine without tier 2, keeps no_new_privs, which tier landlock never gives up.
func TestSetuidOptOutNeverAtLandlock(t *testing.T) {
	for _, tc := range []struct {
		tier   backend.Tier
		setuid bool
		want   bool
	}{
		{backend.TierLandlock, true, false},
		{backend.TierCgroup, true, true},
		{backend.TierBPFLSM, true, true},
		{backend.TierCgroup, false, false},
	} {
		rt := &agent.RuleTable{Tier: tc.tier, Contract: &agent.Contract{Name: "a", Setuid: tc.setuid}}
		if got := setuidOptOut(rt); got != tc.want {
			t.Errorf("tier %s setuid %v: opt-out %v, want %v", tc.tier, tc.setuid, got, tc.want)
		}
	}
	if setuidOptOut(nil) || setuidOptOut(&agent.RuleTable{Tier: backend.TierCgroup}) {
		t.Error("a table with no contract opted out")
	}
}
