// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

const propertyEnvName = "TEGO_BASELINE_PROPERTY_SECRET"

// The governed owner of every compile in the baseline property tests is a fixture, as its home is. The compiler
// inventories the owner's host IPC directories (/run/user/<uid>, the tmux, emacs, screen and nvim directories named by
// uid or login name, and whatever TMUX_TMPDIR and SCREENDIR name) and writes what it finds there into built-in rows
// of the table. Under the real uid those are the developer's live session: a test of another package made its runtime
// directory in /run/user/<uid> between two compiles of one source, and the tables compared byte for byte differed by
// that row. This uid lies above every range a login is given and no login has this name, so the directories do not
// exist; baselinePropertyHostInputs fails on a machine where one does.
const (
	baselinePropertyOwnerUID  = 2147480042
	baselinePropertyOwnerName = "baseline-property-owner"
)

// owner names the fixture owner to a compile. The caller context carries the owner's name and no TMUX_TMPDIR or
// SCREENDIR, which the compiler otherwise reads from the passwd database and from this process's environment.
func (w baselinePropertyWorld) owner() []agent.CompileOption {
	return []agent.CompileOption{agent.WithCwd(w.project), agent.WithHome(w.home), agent.WithOwnerUID(baselinePropertyOwnerUID),
		agent.WithCallerContext(config.CallerContext{Cwd: w.project, UID: baselinePropertyOwnerUID, Username: baselinePropertyOwnerName, Home: w.home})}
}

// baselinePropertyHostInputs fails when a table was compiled from a host IPC directory that other work on this machine
// can change: every directory its built-in refusals inventory must lie in the world or not exist here. /tmp/.X11-unix
// is the one directory no compile option moves; it is shared, and holds sockets, which add no row to a table.
func baselinePropertyHostInputs(t *testing.T, w baselinePropertyWorld, table *agent.RuleTable) {
	t.Helper()
	if table.Builtins == nil {
		t.Fatal("the table has no built-in refusals, so its host IPC inputs cannot be checked")
	}
	private := []string{w.root}
	if resolved, err := filepath.EvalSymlinks(w.root); err == nil && resolved != w.root {
		private = append(private, resolved)
	}
	for _, dir := range slices.Concat(table.Builtins.Runtime, table.Builtins.IPCDirs) {
		if dir == "/tmp/.X11-unix" || slices.ContainsFunc(private, func(root string) bool { return agent.Covers(root, dir) }) {
			continue
		}
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the table inventories the host IPC directory %s, which is not private to this test (lstat: %v): its entries can change between two compiles", dir, err)
		}
	}
}

type baselinePropertySource struct {
	name, group, text string
	fixture           *Fixture
	profiles          map[string]string
}

type baselinePropertyProfiles struct {
	root string
	data map[string]string
}

func (p baselinePropertyProfiles) Resolve(name string) (string, []byte, error) {
	if text, ok := p.data[name]; ok {
		return filepath.Join(p.root, name+".yaml"), []byte(text), nil
	}
	if strings.HasPrefix(name, presets.Prefix) {
		return presets.Source{}.Resolve(name)
	}
	return "", nil, fmt.Errorf("profile %s: %w", name, fs.ErrNotExist)
}

type baselinePropertyResolver struct{}

func (baselinePropertyResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("offline property fixture")
}

type baselinePropertyCounts struct {
	inputs, loadRefused, baseOK, baseRefused, appliedOK, appliedRefused int
	refusalsRetained, decisionComparisons, baselineChecks, emptyBytes   int
	asksRetainedOrTightened, reasonsChangedToBaseline                   int
	environmentComparisons, environmentRefusalsRetained                 int
	allowedBefore, allowedAfter, newlyRefused                           int
	compilerCalls                                                       int
	compileRefusals                                                     int
}

type baselinePropertyCompilation struct {
	table *agent.RuleTable
	err   error
}

// TestBaselineRefusalSuperset keeps the ADR 0144 decision-tightening implication over
// source text, rather than hand-built Contracts. It exercises the real compiler
// and decision/plane rows without starting a process or probing a kernel tier.
// Refusals remain refused, asks never become allows, and a refusal reason changes
// only to the deciding baseline entry's own reason. Compile/placement failures
// mean no launch; successful comparisons and minimum counts prevent an
// implementation that always refuses from satisfying the test.
// A source refused before materialization must remain refused with every baseline.
// The population is finite: the seven baseline choices are fixed, and mount
// topology is synthetic. It does not generate arbitrary baseline combinations,
// successive nonempty-baseline changes, system-only absent targets, or mutations
// during admission. Those cases require separate regression or guest checks.
func TestBaselineRefusalSuperset(t *testing.T) {
	sources := baselinePropertyCorpus(t)
	counts := map[string]*baselinePropertyCounts{}
	for _, group := range []string{"examples", "presets", "conformance", "generated"} {
		counts[group] = &baselinePropertyCounts{}
	}
	contexts := []struct {
		name  string
		tier  backend.Tier
		plane string
	}{
		{"landlock", backend.TierLandlock, ""},
		{"cgroup/lsm", backend.TierCgroup, "lsm"},
		{"cgroup/fmod_ret", backend.TierCgroup, "fmod_ret"},
		{"cgroup/fanotify", backend.TierCgroup, "fanotify"},
		{"bpflsm/lsm", backend.TierBPFLSM, "lsm"},
	}
	baselineNames := []string{"empty", "read", "write", "exec", "env", "all", "home"}
	compatibility := map[string][2]int{}
	for _, source := range sources {
		stat := counts[source.group]
		start := *stat
		stat.inputs++
		world := newBaselinePropertyWorld(t, source)
		profileChain := (&agent.ProfileChain{}).WithBuiltin(presets.Source{}).WithDir(world.profiles)
		contract, ds, err := agent.LoadBytes(world.contract, []byte(world.text), profileChain)
		if err != nil {
			stat.loadRefused++
			if source.group == "presets" {
				t.Fatalf("preset subset %s must load: %v %v", source.name, err, ds)
			}
			t.Logf("source refused %s/%s: %v %v", source.group, source.name, err, ds)
			continue
		}
		canonical, err := contract.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		mode := contract.ExecUnrestricted()
		baselines := world.baselines(t)
		// Compile has no plane input. Share those immutable results for the
		// three cgroup mechanisms; each still gets its own BaselineAt check
		// and real decision model below.
		compilations := map[backend.Tier][]baselinePropertyCompilation{}
		for _, cell := range contexts {
			machineFor := func(snapshot *config.Machine) *config.Machine {
				machine := *snapshot
				machine.Home = world.home
				machine.LedgerRoot.Value = filepath.Join(world.root, "ledger")
				machine.Tier.Value = config.TierSetting{Tier: string(cell.tier)}
				machine.Tier.Bounded = true
				return &machine
			}
			opts := append(world.owner(),
				agent.WithPATH(world.bin), agent.WithMountInfo(world.mountInfo), agent.WithTiers(cell.tier),
				agent.WithClock(func() time.Time { return time.Unix(1700000000, 0) }),
				agent.WithResolver(baselinePropertyResolver{}), agent.WithEnviron([]string{"PATH=" + world.bin, "HOME=" + world.home, propertyEnvName + "=fixture"}), agent.Offline(),
			)
			compiled, have := compilations[cell.tier]
			if !have {
				compiled = make([]baselinePropertyCompilation, len(baselines)+1)
				before, _, compileErr := agent.Compile(contract, machineFor(baselines[0]), opts...)
				stat.compilerCalls++
				compiled[0] = baselinePropertyCompilation{before, compileErr}
				for bi, snapshot := range baselines {
					after, _, err := agent.Compile(contract, machineFor(snapshot), opts...)
					stat.compilerCalls++
					compiled[bi+1] = baselinePropertyCompilation{after, err}
				}
				for _, c := range compiled {
					if c.err == nil {
						baselinePropertyHostInputs(t, world, c.table)
					}
				}
				compilations[cell.tier] = compiled
			}
			before := compiled[0].table
			if compiled[0].err != nil {
				stat.baseRefused++
				t.Logf("SOURCE-COMPILE-REFUSAL %s/%s at %s: %v", source.group, source.name, cell.name, compiled[0].err)
				if source.group == "presets" {
					t.Fatalf("preset subset %s must compile at %s: %v", source.name, cell.name, compiled[0].err)
				}
				for bi := range baselines {
					after := compiled[bi+1]
					if after.err == nil && after.table.BaselineAt(cell.tier, cell.plane) == nil {
						t.Fatalf("baseline made a refused source launchable %s/%s baseline=%s at %s: original=%v", source.group, source.name, baselineNames[bi], cell.name, compiled[0].err)
					}
					stat.compileRefusals++
				}
				continue
			}
			stat.baseOK++
			beforePrint := baselinePropertyPrint(t, before)
			beforeEval := baselinePropertyEvaluator(before, cell.tier, cell.plane)
			for bi := range baselines {
				after, compileErr := compiled[bi+1].table, compiled[bi+1].err
				key := source.group + "/" + baselineNames[bi] + "/" + cell.name
				pair := compatibility[key]
				refusalStage := "compile"
				if compileErr == nil {
					refusalStage = "placement"
					compileErr = after.BaselineAt(cell.tier, cell.plane)
				}
				if compileErr != nil {
					stat.appliedRefused++
					t.Logf("EFFECTIVE-REFUSAL %s/%s baseline=%s at %s stage=%s: %v", source.group, source.name, baselineNames[bi], cell.name, refusalStage, compileErr)
					pair[1]++
					compatibility[key] = pair
					if bi == 0 {
						t.Fatalf("empty baseline newly refused %s/%s at %s: %v", source.group, source.name, cell.name, compileErr)
					}
					continue
				}
				pair[0]++
				compatibility[key] = pair
				stat.appliedOK++
				if after.ExecUnrestricted() != mode {
					t.Fatalf("image mode changed %s/%s baseline=%s at %s", source.group, source.name, baselineNames[bi], cell.name)
				}
				if after.Hash != before.Hash || after.Contract != contract {
					t.Fatalf("source contract/hash replaced %s/%s baseline=%s", source.group, source.name, baselineNames[bi])
				}
				configured, _ := baselines[bi].BaselineSnapshot()
				if !configured.Empty() && (after.Baseline == nil || !after.Baseline.Applied || len(after.Baseline.Entries) != len(configured.Entries())) {
					t.Fatalf("configured baseline disappeared %s/%s baseline=%s at %s", source.group, source.name, baselineNames[bi], cell.name)
				}
				if bi == 0 {
					if got := baselinePropertyPrint(t, after); got != beforePrint || after.EffectiveHash != before.Hash {
						t.Fatalf("empty baseline changed table bytes/hash %s/%s at %s: source hash %x, effective hash %x, table lines (- before, + with the empty baseline):\n%s",
							source.group, source.name, cell.name, before.Hash, after.EffectiveHash, baselinePropertyDiff(beforePrint, got))
					}
					stat.emptyBytes++
				}
				afterEval := baselinePropertyEvaluator(after, cell.tier, cell.plane)
				for _, action := range world.actions {
					b, a := beforeEval(action), afterEval(action)
					stat.decisionComparisons++
					if b.Verdict == agent.VerdictAllow {
						stat.allowedBefore++
						if a.Verdict == agent.VerdictRefused {
							stat.newlyRefused++
						}
					}
					if a.Verdict == agent.VerdictAllow {
						stat.allowedAfter++
					}
					if err := baselinePropertyDecisionError(after, action, b, a, cell.tier, cell.plane); err != nil {
						t.Fatalf("%s: %s/%s baseline=%s at %s action=%+v before=%+v after=%+v", err, source.group, source.name, baselineNames[bi], cell.name, action, b, a)
					}
					if b.Verdict == agent.VerdictRefused {
						stat.refusalsRetained++
						if b.Reason != a.Reason {
							stat.reasonsChangedToBaseline++
						}
					}
					if b.Verdict == agent.VerdictAsk {
						stat.asksRetainedOrTightened++
					}
				}
				if after.Baseline != nil {
					for _, entry := range after.Baseline.Entries {
						if entry.Key == config.BaselineDenyEnv {
							if !slices.Contains(after.Deny, entry.Value) || after.ValidateBaselineEnv([]string{entry.Value + "=not-a-secret"}) == nil {
								t.Fatalf("baseline environment name was admitted: %s/%s %s", source.group, source.name, entry.Value)
							}
							stat.baselineChecks++
							continue
						}
						for _, action := range world.entryActions(entry.Key, entry.Expanded) {
							stat.baselineChecks++
							if got := afterEval(action); got.Verdict != agent.VerdictRefused {
								t.Fatalf("baseline entry allowed covered action %s/%s baseline=%s at %s entry=%+v action=%+v got=%+v", source.group, source.name, baselineNames[bi], cell.name, entry, action, got)
							}
						}
					}
				}
				baselinePropertyEnvironment(t, before, after, stat)
			}
		}
		afterCanonical, err := contract.Canonical()
		if err != nil || !bytes.Equal(canonical, afterCanonical) {
			t.Fatalf("source text mutated %s/%s: %v", source.group, source.name, err)
		}
		t.Logf("INPUT %s/%s base-ok=%d base-refused=%d effective-ok=%d effective-refused=%d", source.group, source.name,
			stat.baseOK-start.baseOK, stat.baseRefused-start.baseRefused, stat.appliedOK-start.appliedOK, stat.appliedRefused-start.appliedRefused)
	}
	for _, group := range []string{"examples", "presets", "conformance", "generated"} {
		c := counts[group]
		if c.inputs == 0 || c.baseOK == 0 || c.appliedOK <= c.baseOK || c.decisionComparisons == 0 || c.refusalsRetained == 0 || c.baselineChecks == 0 || c.emptyBytes == 0 || c.allowedBefore == 0 || c.allowedAfter == 0 || c.newlyRefused == 0 {
			t.Fatalf("vacuous property corpus %s: %+v", group, c)
		}
		if c.compileRefusals != c.baseRefused*len(baselineNames) {
			t.Fatalf("compile refusals were not compared against every baseline in %s: %+v", group, c)
		}
		t.Logf("CORPUS %s inputs=%d load-refused=%d base-ok=%d base-refused=%d effective-ok=%d effective-refused=%d decision-comparisons=%d refusals-retained=%d asks-retained-or-tightened=%d baseline-reason-changes=%d baseline-checks=%d empty-byte-checks=%d", group,
			c.inputs, c.loadRefused, c.baseOK, c.baseRefused, c.appliedOK, c.appliedRefused, c.decisionComparisons, c.refusalsRetained, c.asksRetainedOrTightened, c.reasonsChangedToBaseline, c.baselineChecks, c.emptyBytes)
		if group == "generated" && (c.asksRetainedOrTightened == 0 || c.reasonsChangedToBaseline == 0) {
			t.Fatal("generated corpus compared no ask decision or no baseline refusal-reason change")
		}
		t.Logf("ENVIRONMENT %s comparisons=%d refusals-retained=%d", group, c.environmentComparisons, c.environmentRefusalsRetained)
		t.Logf("NONVACUOUS %s allowed-before=%d allowed-after=%d newly-refused=%d", group, c.allowedBefore, c.allowedAfter, c.newlyRefused)
		t.Logf("COMPILATIONS %s calls=%d", group, c.compilerCalls)
		t.Logf("COMPILE-REFUSALS %s retained=%d", group, c.compileRefusals)
	}
	for _, baseline := range baselineNames {
		for _, cell := range contexts {
			if pair := compatibility["generated/"+baseline+"/"+cell.name]; pair[0] == 0 {
				t.Fatalf("no generated contract successfully applied baseline %s at %s", baseline, cell.name)
			}
		}
	}
	var keys []string
	for key := range compatibility {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		pair := compatibility[key]
		t.Logf("COMPAT %s success=%d refuse=%d", key, pair[0], pair[1])
	}
}

func baselinePropertyPrint(t *testing.T, table *agent.RuleTable) string {
	t.Helper()
	var out bytes.Buffer
	if err := agent.PrintRuleTable(&out, table); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// baselinePropertyDiff lists the lines two table prints do not share, each with its line number: "-" for a line of
// before alone, "+" for a line of after alone.
func baselinePropertyDiff(before, after string) string {
	a, b := strings.Split(before, "\n"), strings.Split(after, "\n")
	// common[i][j] is the length of the longest common subsequence of a[i:] and b[j:].
	common := make([][]int, len(a)+1)
	for i := range common {
		common[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				common[i][j] = common[i+1][j+1] + 1
			} else {
				common[i][j] = max(common[i+1][j], common[i][j+1])
			}
		}
	}
	var out strings.Builder
	for i, j := 0, 0; i < len(a) || j < len(b); {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case j == len(b) || (i < len(a) && common[i+1][j] >= common[i][j+1]):
			fmt.Fprintf(&out, "-%d: %s\n", i+1, a[i])
			i++
		default:
			fmt.Fprintf(&out, "+%d: %s\n", j+1, b[j])
			j++
		}
	}
	if out.Len() == 0 {
		return "(no line differs)\n"
	}
	return out.String()
}

func baselinePropertyEvaluator(table *agent.RuleTable, tier backend.Tier, plane string) func(agent.Action) agent.EvalResult {
	if plane == "lsm" || plane == "fmod_ret" {
		e := decide.NewPlaneEvaluator(table)
		return func(a agent.Action) agent.EvalResult {
			return agent.EvaluateGateRow(table, a, e.Evaluate(a, decide.Env{}))
		}
	}
	e := decide.NewEvaluator(table)
	return func(a agent.Action) agent.EvalResult {
		return agent.EvaluateGateRow(table, a, e.Evaluate(a, tier))
	}
}

func baselinePropertyEnvironment(t *testing.T, before, after *agent.RuleTable, stat *baselinePropertyCounts) {
	t.Helper()
	allows := func(table *agent.RuleTable, name string) bool {
		return !slices.Contains(table.Deny, name) && (table.Env == nil || slices.Contains(table.Env, name))
	}
	for _, name := range []string{propertyEnvName, "PATH", "HOME", "GITHUB_TOKEN", "ORDINARY_VAR"} {
		stat.environmentComparisons++
		if !allows(before, name) {
			stat.environmentRefusalsRetained++
			if allows(after, name) {
				t.Fatalf("baseline reopened environment name %s", name)
			}
		}
	}
	if err := after.ValidateBaselineEnv([]string{"ORDINARY_VAR=fixture"}); err != nil {
		t.Fatalf("ordinary final environment was refused: %v", err)
	}
}

type baselinePropertyWorld struct {
	root, project, home, bin, contract, text, mountInfo string
	profiles                                            baselinePropertyProfiles
	actions                                             []agent.Action
}

func newBaselinePropertyWorld(t *testing.T, source baselinePropertySource) baselinePropertyWorld {
	t.Helper()
	root, err := os.MkdirTemp("", "mb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	w := baselinePropertyWorld{root: root, project: filepath.Join(root, "p"), home: filepath.Join(root, "h"), bin: filepath.Join(root, "b"),
		contract: filepath.Join(root, "agent.yaml"), mountInfo: filepath.Join(root, "mountinfo")}
	for _, dir := range []string{w.project, w.home, w.bin, filepath.Join(root, "machine"), filepath.Join(root, "read"), filepath.Join(root, "write"),
		filepath.Join(w.home, ".ssh"), filepath.Join(w.home, "machine-secrets"), filepath.Join(w.home, ".codex", "sessions"), filepath.Join(w.home, ".local", "share", "tego", "codex-chatgpt"),
		filepath.Join(root, "read", "out"), filepath.Join(root, "write", "out"), filepath.Join(w.home, "machine-secrets", "out"),
		filepath.Join(w.project, "out"), filepath.Join(w.project, "work", "tmp"), filepath.Join(w.project, "held"), filepath.Join(w.project, "config"), filepath.Join(w.project, ".deps"), filepath.Join(w.project, ".claude-state", "tmp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte, mode fs.FileMode) {
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(root, "read", "item"), filepath.Join(root, "write", "item"), filepath.Join(w.home, "machine-secrets", "item"), filepath.Join(w.home, ".ssh", "id_ed25519"),
		filepath.Join(w.home, ".codex", "auth.json"), filepath.Join(w.home, ".codex", "history.jsonl"), filepath.Join(w.home, ".codex", "config.toml"), filepath.Join(w.project, "existing"), filepath.Join(w.project, ".env")} {
		write(path, []byte("fixture\n"), 0o600)
	}
	if err := os.Symlink(filepath.Join(root, "read"), filepath.Join(w.project, "read-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "write"), filepath.Join(w.project, "write-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(w.home, "machine-secrets"), filepath.Join(w.project, "home-link")); err != nil {
		t.Fatal(err)
	}
	image := baselinePropertyELF()
	for _, name := range []string{"actor", "claude", "codex", "bash", "sh", "git", "python", "python3", "make", "go", "env", "mcp-postgres", "cat", "ls", "mkdir", "touch", "grep", "sed", "head", "tail", "find", "wc", "tr", "sort", "codex-code-mode-host", "rm", "npm", "node", "busybox", "custom"} {
		write(filepath.Join(w.bin, name), image, 0o755)
	}
	// A synthetic, complete single-mount topology is a compiler input fixture.
	// It is not a claim about this host or any real mount/alias configuration.
	write(w.mountInfo, []byte("1 0 0:1 / / rw - ext4 fixture rw\n"), 0o600)
	subst := strings.NewReplacer("{{P}}", w.project, "{{R}}", w.root, "{{H}}", w.home, "{{PORT}}", "41001", "{{PORT2}}", "41002", "{{LOADER}}", "/lib64/ld-linux-x86-64.so.2",
		"/home/USER/", w.home+"/", "/CHANGE/codex-code-mode-host", filepath.Join(w.bin, "codex-code-mode-host")).Replace
	w.text = subst(source.text)
	w.profiles = baselinePropertyProfiles{root: filepath.Join(root, "profiles"), data: map[string]string{}}
	for name, text := range source.profiles {
		w.profiles.data[name] = subst(text)
	}
	if source.fixture != nil {
		if err := Layout(w.project, source.fixture, image, subst); err != nil {
			t.Fatalf("layout %s: %v", source.name, err)
		}
		for _, cell := range source.fixture.Cells {
			if a, ok := w.cellAction(cell, subst); ok {
				w.actions = append(w.actions, a)
			}
		}
	}
	write(w.contract, []byte(w.text), 0o600)
	w.actions = append(w.actions,
		agent.Action{Kind: agent.ActionFSRead, Path: filepath.Join(w.home, ".ssh", "id_ed25519")},
		agent.Action{Kind: agent.ActionFSRead, Path: filepath.Join(w.project, ".env")},
		agent.Action{Kind: agent.ActionFSRead, Path: filepath.Join(w.project, "held", "item")},
		agent.Action{Kind: agent.ActionFSWrite, Path: filepath.Join(w.project, "held", "item")},
		agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.40", Port: 443, Proto: "tcp"},
		agent.Action{Kind: agent.ActionExec, Path: filepath.Join(w.bin, "git"), Argv: []string{"git", "status"}},
		agent.Action{Kind: agent.ActionFSWrite, Path: filepath.Join(w.project, "out", "new")},
		agent.Action{Kind: agent.ActionFSWrite, Path: filepath.Join(root, "outside")},
		agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.1", Port: 443, Proto: "tcp"},
		agent.Action{Kind: agent.ActionNetConnect, Path: "unix:/run/docker.sock"},
		agent.Action{Kind: agent.ActionExecAnon},
	)
	for _, target := range []string{filepath.Join(root, "read", "out"), filepath.Join(root, "write", "out"), filepath.Join(w.home, "machine-secrets", "out")} {
		w.actions = append(w.actions, agent.Action{Kind: agent.ActionFSRead, Path: filepath.Join(target, "item")},
			agent.Action{Kind: agent.ActionFSWrite, Path: filepath.Join(target, "item")})
	}
	for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite, config.BaselineDenyExec} {
		value := filepath.Join(root, "read")
		switch key {
		case config.BaselineDenyRead, config.BaselineDenyEnv:
		case config.BaselineDenyWrite:
			value = filepath.Join(root, "write")
		case config.BaselineDenyExec:
			value = "git push"
		}
		w.actions = append(w.actions, w.entryActions(key, value)...)
	}
	return w
}

func baselinePropertyELF() []byte {
	h := make([]byte, 64)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(h[16:], 2)
	binary.LittleEndian.PutUint16(h[18:], 0x3e)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint64(h[32:], 64)
	binary.LittleEndian.PutUint16(h[52:], 64)
	binary.LittleEndian.PutUint16(h[54:], 56)
	binary.LittleEndian.PutUint16(h[56:], 1)
	program := make([]byte, 56)
	binary.LittleEndian.PutUint32(program, 1) // PT_LOAD, no interpreter
	return append(h, program...)
}

func (w baselinePropertyWorld) baselines(t *testing.T) []*config.Machine {
	t.Helper()
	read, write := strconv.Quote(filepath.Join(w.root, "read")), strconv.Quote(filepath.Join(w.root, "write"))
	texts := []string{"", "baseline: {fs: {deny_read: [" + read + "]}}", "baseline: {fs: {deny_write: [" + write + "]}}",
		"baseline: {exec: {deny: ['git push']}}", "baseline: {env: {deny: [" + propertyEnvName + "]}}",
		"baseline: {fs: {deny_read: [" + read + "], deny_write: [" + write + "]}, exec: {deny: ['git push']}, env: {deny: [" + propertyEnvName + "]}}",
		"baseline: {fs: {deny_read: ['~/machine-secrets']}}"}
	var out []*config.Machine
	for i, text := range texts {
		path := filepath.Join(w.root, "machine", strconv.Itoa(i)+".yaml")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		m, ds, err := config.LoadSources(config.Sources{User: path}, w.home, os.Getuid(), config.TrustAbort)
		if err != nil {
			t.Fatalf("baseline fixture %d: %v %v", i, err, ds)
		}
		out = append(out, m)
	}
	return out
}

func (w baselinePropertyWorld) entryActions(key config.BaselineKey, value string) []agent.Action {
	switch key {
	case config.BaselineDenyRead:
		return []agent.Action{{Kind: agent.ActionFSRead, Path: filepath.Join(value, "item")}}
	case config.BaselineDenyWrite:
		return []agent.Action{{Kind: agent.ActionFSWrite, Path: filepath.Join(value, "item")}, {Kind: agent.ActionFSDelete, Path: filepath.Join(value, "item")}, {Kind: agent.ActionFSMkdir, Path: filepath.Join(value, "new")}}
	case config.BaselineDenyExec:
		return []agent.Action{{Kind: agent.ActionExec, Path: filepath.Join(w.bin, "git"), Argv: []string{"git", "push", "--dry-run"}},
			{Kind: agent.ActionExec, Path: filepath.Join(w.bin, "git"), Argv: []string{"git", "-C", ".", "push"}},
			{Kind: agent.ActionExec, Path: filepath.Join(w.bin, "busybox"), Argv: []string{"busybox", "git", "push"}}}
	case config.BaselineDenyEnv:
		return nil // final environment names use ValidateBaselineEnv above
	}
	return nil
}

func (w baselinePropertyWorld) cellAction(c Cell, subst func(string) string) (agent.Action, bool) {
	if _, ok := compileAction(&c); !ok || c.NoCompile != "" {
		return agent.Action{}, false
	}
	abs := func(p string) string {
		p = subst(p)
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(w.project, p)
	}
	a := agent.Action{Path: abs(c.Path), DestPath: abs(c.Dest), Script: abs(c.Script), ScriptArg: c.ScriptArg, Argv: slices.Clone(c.Argv)}
	switch c.Op {
	case OpRead:
		a.Kind = agent.ActionFSRead
	case OpWriteOpen, OpCreate, OpCreat, OpOpenTrunc, OpTruncate, OpSymlink, OpMknod:
		a.Kind = agent.ActionFSWrite
	case OpUnlink, OpRmdir:
		a.Kind = agent.ActionFSDelete
	case OpMkdir:
		a.Kind = agent.ActionFSMkdir
	case OpRename:
		a.Kind = agent.ActionFSRename
	case OpLink:
		a.Kind = agent.ActionFSLink
	case OpChmod, OpChown, OpSetxattr, OpSetfacl:
		a.Kind = agent.ActionFSAttr
	case OpExec, OpExecLoader, OpExecveatFD, OpExecProcFD:
		a.Kind = agent.ActionExec
	case OpMapExec, OpMapExecRIE, OpMprotectExec, OpMprotectRIE:
		a.Kind = agent.ActionMapExec
	case OpConnectUnix:
		a.Kind, a.Path = agent.ActionNetConnect, "unix:"+subst(c.Addr)
	case OpConnectTCP, OpConnectUDP, OpSendUDP:
		host, port, err := net.SplitHostPort(subst(c.Addr))
		if err != nil {
			return agent.Action{}, false
		}
		a.Kind, a.Path, a.Host = agent.ActionNetConnect, "", host
		a.Port, _ = strconv.Atoi(port)
		a.Proto = "tcp"
		if c.Op != OpConnectTCP {
			a.Proto = "udp"
		}
	default:
		return agent.Action{}, false
	}
	if fi, err := os.Stat(a.Path); err == nil {
		a.Dir = fi.IsDir()
	}
	return a, true
}

func baselinePropertyCorpus(t *testing.T) []baselinePropertySource {
	t.Helper()
	var sources []baselinePropertySource
	profiles := map[string]string{}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(filepath.Join(root, "examples", "profiles"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(filepath.Join(root, "examples", "profiles"), path)
		if err != nil {
			return err
		}
		profiles[strings.TrimSuffix(filepath.ToSlash(rel), ".yaml")] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(filepath.Join(root, "examples"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sources = append(sources, baselinePropertySource{name: filepath.ToSlash(path), group: "examples", text: string(data), profiles: profiles})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	list := presets.List()
	if len(list) > 12 {
		t.Fatal("preset property corpus needs an explicit bound above 12 presets")
	}
	for mask := 0; mask < 1<<len(list); mask++ {
		var refs []string
		for i, p := range list {
			if mask&(1<<i) != 0 {
				refs = append(refs, strconv.Quote(p.Ref()))
			}
		}
		extends := ""
		if len(refs) > 0 {
			extends = "extends: [" + strings.Join(refs, ", ") + "]\n"
		}
		sources = append(sources, baselinePropertySource{name: fmt.Sprintf("subset-%02d", mask), group: "presets", text: "version: 0\nname: presets\ncommand: [actor]\n" + extends})
	}
	for _, space := range Spaces() {
		for _, fixture := range space.Fixtures() {
			fx := fixture
			sources = append(sources, baselinePropertySource{name: space.Name + "/" + fx.Name, group: "conformance", text: fx.Contract, fixture: &fx})
		}
	}
	execSections := []string{"", "exec: null\n", "exec: {}\n", "exec: {allow: null}\n", "exec: {allow: []}\n", "exec: {allow: [git]}\n", "exec: {deny: ['git status']}\n", "exec: {allow: ['git status']}\n"}
	fsSections := []string{"", "fs: null\n", "fs: {}\n", "fs: {write: null}\n", "fs: {write: []}\n", "fs: {deny_read: null}\n", "fs: {deny_read: []}\n", "fs: {write: ['./out/'], deny_read: ['./existing']}\n"}
	envSections := []string{"", "env: null\n", "env: {}\n", "env: {pass: null}\n", "env: {pass: []}\n", "env: {pass: [PATH]}\n", "env: {deny: [ORDINARY_VAR]}\n"}
	for ei, ex := range execSections {
		for fi, fsSection := range fsSections {
			for vi, envSection := range envSections {
				fragment := ex + fsSection + envSection
				shape := (ei + fi + vi) % 3
				text := "version: 0\nname: generated\ncommand: [actor]\n"
				p := map[string]string{}
				switch shape {
				case 0:
					text += fragment
				case 1:
					text += "extends: child\n"
					p["child"], p["base"] = "extends: base\n"+fragment, "env: {deny: [PROFILE_SECRET]}\n"
				case 2:
					text += "extends: [left, right]\n" + envSection
					p["left"], p["right"], p["base"] = "extends: base\n"+ex, "extends: base\n"+fsSection, "env: {deny: [PROFILE_SECRET]}\n"
				}
				sources = append(sources, baselinePropertySource{name: fmt.Sprintf("exec-%d-fs-%d-env-%d-shape-%d", ei, fi, vi, shape), group: "generated", text: text, profiles: p})
			}
		}
	}
	return append(sources, baselinePropertyDecisionSources()...)
}
