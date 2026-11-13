// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The root runner (ADR 0017 (a), (c)): every cell's action performed in a real `tego run` at tier landlock and
// at tier cgroup, all the actions of one fixture in one run. Per action it takes the kernel's own result as the
// judge and checks it against the cell, checks the ledger line's verdict and rule against the cell, and checks
// the invariants derived from the contract alone. Tier cgroup and the plane axes need root (tier 2 loads programs
// and a fanotify group, and a root run drops the agent to the sudo caller); without root the tier landlock axis runs
// alone, as the caller (ADR 0017: tier 1 on the hosted runner; CI's integration step and make integration run it, and
// it skips only on a machine whose doctor offers no tier landlock). test/vm/root-suites.sh runs every axis in a KVM
// guest and root-must-pass.txt holds it to passing there.
//
// The mode axis (ADR 0017, TIER3-PLAN §5, T6): tier cgroup runs once on the fanotify listener and once per decision
// plane mode this machine passes (fmod_ret wherever doctor's probe admits it, lsm where bpf is an active LSM),
// each pinned by the test build's TEGO_TEST_PLANE as bpf.plane would pin it. The plane modes answer the one plane
// column (ADR 0019 as amended: tier cgroup with a plane and tier bpflsm share it, Key{bpflsm, lsm}) and the
// invariants of the tier that column is (bpflsm), and each reports its failures under its own name, cgroup@<mode>.
//
// Tier bpflsm (T7, T11) is an axis of its own where doctor offers it (bpf an active LSM and LSM mode passing): `tego
// run --tier bpflsm`, answering the plane column. A machine where bpf is an active LSM and tier bpflsm is not offered,
// or the lsm mode is not selected under its pin, fails the test rather than dropping the axis, and so does an axis
// TEGO_CONFORMANCE_REQUIRE names (cgroup, fmod_ret, lsm, bpflsm; root-suites.sh sets it per boot). On that axis the kernel is also checked against compile --test's
// bpflsm column directly, cell by cell (enforce-plane I9, R25's kernel cells): runner "parity", baselined like the
// others where the run's effective verdict is not the plane's own (the Landlock floor under it, a hook of a later
// step).

// axis is one run of every fixture: the tier `tego run --tier` names, the plane pin it runs under, the expectation
// it answers, the tier whose invariants bind, and the name its failures are reported and baselined under.
type axis struct {
	tier      Tier
	pin       string
	want      Key
	invariant Tier
	label     Tier
	// decisionPlane is the mode a plane-decided ledger line names in decision_plane ("" where no plane decides).
	decisionPlane string
	// fallback is a plane pin whose run the plane cannot hold (Model.PlaneCannotHold), so tier cgroup's listener
	// decides it: its run_start names fanotify, and the listener's column and invariants answer it.
	fallback bool
}

// onListener is ax for a fixture the plane cannot hold: at tier cgroup under a plane pin the run falls back to the
// fanotify listener (enforce/cgroup choosePlane), which answers the listener's column under the axis' own label.
func (ax axis) onListener() axis {
	if ax.tier != TierCgroup || ax.decisionPlane == "" {
		return ax
	}
	ax.want, ax.invariant, ax.decisionPlane, ax.fallback = Key{TierCgroup, ModeFanotify}, TierCgroup, "", true
	return ax
}

// planeAxis is tier cgroup in a plane mode: the plane column.
func planeAxis(m Mode) axis {
	return axis{tier: TierCgroup, pin: string(m), want: Key{TierBPFLSM, ModeLSM}, invariant: TierBPFLSM,
		label: Tier(string(TierCgroup) + "@" + string(m)), decisionPlane: string(m)}
}

// runPlane is the decision_plane the axis' run_start line must name: the plane mode it pins, "fanotify" for tier
// cgroup on the listener, none at tier landlock.
func (ax axis) runPlane() string {
	switch {
	case ax.fallback:
		return string(ModeFanotify)
	case ax.decisionPlane != "":
		return ax.decisionPlane
	}
	return ax.pin
}

// planeFirst says the axis' plane answers before Landlock's own hooks (Machine.PlaneFirst): fmod_ret always, lsm
// where bpf is ahead of landlock in the LSM order; never on an axis no plane decides.
func (ax axis) planeFirst() bool {
	switch Mode(ax.decisionPlane) {
	case ModeFmodRet:
		return true
	case ModeLSM:
		return bpfBeforeLandlock()
	case ModeNone, ModeFanotify:
	}
	return false
}

// doctor is `tego doctor args...` in environ: the test's own machine config, chain anchor and log home
// (machineConfig), so a doctor run, a failing one included, reads and writes nothing of the invoking user's
// ~/.tego, which the unprivileged landlock axis runs as.
func doctor(bin string, environ []string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, append([]string{"doctor"}, args...)...)
	cmd.Env = environ
	return cmd
}

// planeSelected is the plane doctor selects for tier cgroup under TEGO_TEST_PLANE=pin.
func planeSelected(bin string, environ []string, pin string) string {
	cmd := doctor(bin, append(slices.Clone(environ), "TEGO_TEST_PLANE="+pin), "--json")
	out, _ := cmd.Output()
	var rep struct {
		Plane *struct {
			Selected string `json:"selected"`
		} `json:"plane"`
	}
	if json.Unmarshal(out, &rep) != nil || rep.Plane == nil {
		return ""
	}
	return rep.Plane.Selected
}

func TestConformanceKernel(t *testing.T) {
	required := os.Getenv(RequireEnv)
	// Without root only the tier landlock axis runs (ADR 0017: tier 1 on the hosted runner, its integration step):
	// the agent is the caller itself, and nothing is chowned. Tier cgroup and the plane axes load BPF programs and a
	// fanotify group, so an environment that requires one of them and is not root fails here.
	root := os.Geteuid() == 0
	uid, gid := -1, -1
	if root {
		var ok bool
		if uid, gid, ok = sudoIDs(); !ok {
			t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
		}
	} else {
		for _, a := range []string{string(TierCgroup), string(ModeFmodRet), string(ModeLSM), string(TierBPFLSM)} {
			if AxisRequired(required, a) {
				t.Fatalf("%s names %s, which needs root (tier cgroup and the plane load BPF programs); this test runs as uid %d",
					RequireEnv, a, os.Geteuid())
			}
		}
	}
	actor := buildActor(t)
	binDir := t.TempDir()
	var bin string
	var err error
	haveBPF := false
	if root {
		bin, err = buildTego(binDir, "tegobpf")
		haveBPF = err == nil
		if !haveBPF && AxisRequired(required, "cgroup") {
			t.Fatalf("%s names cgroup but the tegobpf build failed: %v", RequireEnv, err)
		}
		if !haveBPF {
			t.Logf("no tegobpf build (%v): tier cgroup is not run", err)
		}
	} else {
		t.Logf("not root (uid %d): only the tier landlock axis runs", os.Geteuid())
	}
	if !haveBPF {
		if bin, err = buildTego(binDir); err != nil {
			t.Fatal(err)
		}
	}
	doctorEnv := machineConfig(t, &env{base: t.TempDir()})
	if out, err := doctor(bin, doctorEnv, "--require", "landlock").CombinedOutput(); err != nil {
		if root || AxisRequired(required, string(TierLandlock)) {
			t.Fatalf("tego doctor --require landlock: %v\n%s", err, out)
		}
		t.Skipf("this machine offers no tier landlock (tego doctor --require landlock: %v):\n%s", err, out)
	}
	// A baseline that does not load, or an update that names no space, fails the test now and not after the runs
	// (settleBaseline reads the baseline again at the end).
	requestedSpace(t)
	if _, err := LoadBaseline(baselinePath); err != nil {
		t.Fatal(err)
	}
	axes := []axis{{tier: TierLandlock, want: Key{TierLandlock, ModeNone}, invariant: TierLandlock, label: TierLandlock}}
	if haveBPF {
		if out, err := doctor(bin, doctorEnv, "--require", "cgroup").CombinedOutput(); err != nil {
			if AxisRequired(required, "cgroup") {
				t.Fatalf("%s names cgroup but tego doctor --require cgroup failed: %v\n%s", RequireEnv, err, out)
			}
			t.Logf("this machine offers no tier cgroup (tego doctor --require cgroup: %v):\n%s", err, out)
		} else {
			axes = append(axes, axis{tier: TierCgroup, pin: string(ModeFanotify), want: Key{TierCgroup, ModeFanotify},
				invariant: TierCgroup, label: TierCgroup})
			// An axis this machine should run and does not fails the test rather than leave its column unchecked
			// behind a green parent: one the environment requires (root-suites.sh sets it per boot), and the lsm
			// mode and tier bpflsm wherever bpf is an active LSM, as the tier bpflsm axis always did.
			for _, m := range []Mode{ModeFmodRet, ModeLSM} {
				if got := planeSelected(bin, doctorEnv, string(m)); got == string(m) {
					axes = append(axes, planeAxis(m))
				} else {
					switch {
					case AxisRequired(required, string(m)):
						t.Fatalf("%s names plane mode %s but doctor selects %q under that pin", RequireEnv, m, got)
					case m == ModeLSM && bpfActiveLSM():
						t.Errorf("bpf is an active LSM here but doctor selects %q under the plane pin lsm: the cgroup@lsm axis would be dropped", got)
					default:
						t.Logf("plane mode %s is not available here (doctor selects %q under that pin): its axis is not run", m, got)
					}
				}
			}
			if out, err := doctor(bin, doctorEnv, "--require", "bpflsm").CombinedOutput(); err == nil {
				axes = append(axes, axis{tier: TierBPFLSM, want: Key{TierBPFLSM, ModeLSM}, invariant: TierBPFLSM, label: TierBPFLSM,
					decisionPlane: string(ModeLSM)})
			} else if AxisRequired(required, string(TierBPFLSM)) {
				t.Fatalf("%s names bpflsm but tego doctor --require bpflsm failed: %v\n%s", RequireEnv, err, out)
			} else if bpfActiveLSM() {
				t.Errorf("bpf is an active LSM here but doctor offers no tier bpflsm (tego doctor --require bpflsm: %v):\n%s", err, out)
			} else {
				t.Logf("bpf is not an active LSM here: the tier bpflsm axis is not run")
			}
		}
	}
	// Below Landlock ABI 3 tier 1's filter refuses every truncate(2) (enforce-landlock E31): the truncate cells want
	// that floor here (Cell.WantOn).
	abi, err := sys.LandlockABI()
	if err != nil {
		t.Fatalf("the Landlock ABI: %v", err)
	}
	t.Logf("Landlock ABI %d", abi)
	machine, err := CurrentMachine()
	if err != nil {
		t.Fatal(err)
	}
	// The thirdparty cell's line follows whether another party's refusal is in security_file_open's return here
	// (Machine.FanotifyInChain): measured, never read off the version.
	if machine.FanotifyInChain, err = fanotifyInChain(); err != nil {
		t.Fatalf("fanotify in the chain's return: %v", err)
	}
	t.Logf("another party's fanotify refusal is in security_file_open's return: %t", machine.FanotifyInChain)
	var report io.Writer
	reportPrefix := ""
	if path := os.Getenv(ReportEnv); path == "-" {
		report, reportPrefix = os.Stdout, ReportRowPrefix
	} else if path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("%s: %v", ReportEnv, err)
		}
		defer f.Close() //nolint:errcheck // each row is written whole, and a failed write fails WriteRows
		report = f
	}
	strict := os.Getenv(BudgetEnv) == "strict"
	failures := map[string]string{}
	ran := map[string]bool{}
	fixtures, _ := selectedFixtures(t)
	gen := generatedColumns(t, bin, actor, fixtures)
	names := make([]string, len(fixtures))
	for i := range fixtures {
		names[i] = fixtures[i].Name
	}
	for _, ax := range axes {
		rep := NewAxisReport(ax.label)
		start := time.Now()
		// Each fixture's report, merged in fixture order once the axis is done.
		reports := make([]*AxisReport, len(fixtures))
		t.Run(string(ax.label), func(t *testing.T) {
			for i := range fixtures {
				fx := fixtures[i]
				t.Run(fx.Name, func(t *testing.T) {
					// The tier landlock runs share nothing but the CPU (each has its project, machine config,
					// state and ledger), so they run side by side, up to -parallel at once: the fs grid's 64 runs
					// keep the axis within its 10 s. The root axes share the machine's cgroup tree, BPF plane and
					// fanotify listener across runs, and run one at a time, well within their 180 s.
					if ax.tier == TierLandlock {
						t.Parallel()
					}
					reports[i] = fixtureReport(t, runFixture(t, bin, actor, uid, gid, &fx, ax, machine, gen[fx.Name]))
				})
			}
		})
		for i, fr := range reports {
			if fr != nil {
				rep.Merge(fr)
				continue
			}
			// A fixture -run or -skip left out (or one that failed before its report, which fails the test anyway)
			// judged none of its cells on this axis: its baseline entries are neither applied nor stale (NotRunKey).
			for j := range fixtures[i].Cells {
				rep.Ran[NotRunKey(fixtures[i].ID(&fixtures[i].Cells[j]), string(ax.label))] = true
			}
		}
		rep.Wall = time.Since(start)
		t.Log(rep.Line())
		// The ledger runner holds every judged grid cell's rule to compile's (judgeAnswers): an axis that ran a fixture
		// with a generated column and compared no rule dropped that check, which would let naming drift pass in silence.
		// A fixture -run or -skip left out has no report and does not count (UncomparedGenerated).
		if name := rep.UncomparedGenerated(names, reports, func(n string) bool { return gen[n] != nil }); name != "" {
			t.Errorf("AXIS %s ran %s, a generated fixture with compile --test's column, and held no ledger rule to the column's", ax.label, name)
		}
		for _, miss := range rep.BudgetMisses() {
			if strict {
				t.Errorf("%s (%s=strict)", miss, BudgetEnv)
			} else {
				t.Log(miss)
			}
		}
		if report != nil {
			if err := rep.WriteRows(report, reportPrefix); err != nil {
				t.Errorf("%s: %v", ReportEnv, err)
			}
		}
		maps.Copy(failures, rep.Failures)
		maps.Copy(ran, rep.Ran)
	}
	var keys []string
	for k := range failures {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("FAILURE %s :: %s", k, failures[k])
	}
	settleBaseline(t, "the kernel and a cell", ran, failures)
}

// fixtureReport reports, as the fixture subtest's errors, the judge's verdicts that no baseline holds, and returns
// the report: the baselinable disagreements are settled at the end, against testdata/baseline.json.
func fixtureReport(t *testing.T, fr *AxisReport) *AxisReport {
	for _, f := range fr.FailOpens {
		t.Errorf("FAIL-OPEN %s", f)
	}
	for _, f := range fr.Effects {
		t.Errorf("EFFECT %s", f)
	}
	for _, f := range fr.Problems {
		t.Error(f)
	}
	for _, f := range fr.Findings {
		t.Logf("FINDING %s", f)
	}
	return fr
}

// runFixture runs one fixture on one axis and judges it: the harness's own errors (a fixture that did not run, a
// ledger that cannot be read) fail the subtest at once, and everything the judge finds goes into the report.
// A generated fixture's compile --test answers, every tier's, come in gen (generatedColumns): its cells have no want,
// and the axis' column, ax.want's tier, is what the kernel's answer is held to.
func runFixture(t *testing.T, bin, actor string, uid, gid int, fx *Fixture, ax axis, machine Machine, gen map[string]compileCell) *AxisReport {
	if fx.Model.PlaneCannotHold {
		ax = ax.onListener()
	}
	tier := ax.tier
	machine.PlaneFirst = ax.planeFirst()
	rep := NewAxisReport(ax.label)
	// Not t.TempDir(): its parent is 0700, and the agent (the sudo caller) must reach the project through it.
	dir, err := os.MkdirTemp("", "eyconf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := materialize(t, dir, fx, actor)
	environ := machineConfig(t, e)
	// A root run's agent is the sudo caller, and owns the project; without root it is this process already.
	if err := filepath.Walk(e.project, func(p string, _ os.FileInfo, err error) error {
		if err != nil || uid < 0 {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}
	hostControl(t, e)
	bpfControl(t, e, fx)
	memfdControl(t, e, fx)
	if missing := missingControls(e, fx, os.Geteuid() == 0); len(missing) > 0 {
		t.Fatalf("%s: the controls %v its cells need did not run, so a refusal the machine gives could pass as the run's", fx.Name, missing)
	}
	// The column is asked before the run, of the tree the run starts from: after it, a path the run made (a symlink
	// into a deny_read) is answered where it now leads, not where the action found it.
	// A generated fixture's column was asked of a tree laid out alike (generatedColumns). A row is named by the
	// column's tier, ax.want's: a plane axis of tier cgroup reads the plane column, bpflsm.
	var column map[string]compileCell
	switch {
	case gen != nil:
		column = gen
	case generated(fx):
		t.Fatalf("%s is generated, and generatedColumns asked compile --test nothing for it", fx.Name)
	case tier == TierBPFLSM && hasCompileRow(fx):
		column = compileAnswers(t, bin, e, environ, columnTable(e, fx, tier))
	}
	colTier := ax.want.Tier
	// Space 5: a fixture's mounts are made in a mount namespace of the run's own, by root.
	notRun := func() *AxisReport { // the fixture's baseline entries are not judged on this axis (NotRunKey)
		for i := range fx.Cells {
			rep.Ran[NotRunKey(fx.ID(&fx.Cells[i]), string(ax.label))] = true
		}
		return rep
	}
	if len(fx.Mounts) > 0 && uid < 0 {
		t.Logf("MOUNTS %s/%s not run: its mounts need root", ax.label, fx.Name)
		return notRun()
	}
	// The effect judge reads the tree as the run found it and as it left it (effects.go); a fixture with mounts has
	// its namespace's helper take both, so they hold the mounted trees the agent saw.
	before, err := Snapshot(e.project)
	if err != nil {
		t.Fatalf("snapshot before the run: %v", err)
	}
	// Space 6: a third party's listener refuses the fixture's files while the run lasts; it needs root.
	stopListeners := func() []string { return nil }
	if len(fx.ThirdPartyDeny) > 0 {
		if uid < 0 {
			t.Logf("THIRD-PARTY %s/%s not run: its fanotify listener needs root (CAP_SYS_ADMIN)", ax.label, fx.Name)
			return notRun()
		}
		paths := make([]string, len(fx.ThirdPartyDeny))
		for i, p := range fx.ThirdPartyDeny {
			paths[i] = e.path(p)
		}
		stopListeners = startThirdParty(t, paths)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--tier", string(tier), "agent.yaml")
	cmd.Dir, cmd.Env = e.project, environ
	if ax.pin != "" {
		cmd.Env = append(cmd.Env, "TEGO_TEST_PLANE="+ax.pin)
	}
	snapshots := filepath.Join(e.base, "snapshot-")
	if len(fx.Mounts) > 0 {
		spec := mountnsSpec{Project: e.project, Scratch: e.base, UID: uid, GID: gid, Mounts: fx.Mounts,
			Before: snapshots + "before.json", After: snapshots + "after.json", Argv: cmd.Args, Env: cmd.Env, Dir: cmd.Dir}
		helper, err := mountnsCommand(filepath.Join(e.base, "mountns.json"), spec)
		if err != nil {
			t.Fatal(err)
		}
		cmd = exec.CommandContext(ctx, helper.Path)
		cmd.Args, cmd.Env, cmd.SysProcAttr = helper.Args, helper.Env, helper.SysProcAttr
	}
	stdout, stderr := newAwaitWriter(), bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	cmd.WaitDelay = 15 * time.Second
	var later func() // a fixture's later files (ADR 0043): written by this process, outside the run, once the actor waits
	if len(fx.Later) > 0 {
		later = func() {
			for rel, content := range fx.Later {
				p := e.path(rel)
				if err := os.WriteFile(p, []byte(e.subst(content)), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Lchown(p, uid, gid); uid >= 0 && err != nil {
					t.Fatal(err)
				}
			}
			if before, err = Snapshot(e.project); err != nil { // the tree the first cell finds holds them
				t.Fatalf("snapshot before the cells: %v", err)
			}
			if err := os.WriteFile(e.path(AwaitGo), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	runErr := runAwaiting(cmd, stdout, later)
	for _, p := range stopListeners() {
		rep.Problems = append(rep.Problems, fmt.Sprintf("THIRD-PARTY %s at %s: %s", fx.Name, ax.label, p))
	}
	var exitErr *exec.ExitError
	if len(fx.Mounts) > 0 && errors.As(runErr, &exitErr) && (exitErr.ExitCode() == mountnsSetupFailed || exitErr.ExitCode() == mountnsNoFS) {
		msg := stderr.String()
		if i := strings.LastIndex(msg, mountnsSetupTag); i >= 0 {
			msg = strings.TrimSpace(msg[i+len(mountnsSetupTag):])
		}
		kind := strings.Fields(msg + " ?")[0]
		if exitErr.ExitCode() == mountnsSetupFailed || slices.Contains(strings.Fields(os.Getenv(FSRequireEnv)), kind) {
			t.Fatalf("MOUNTS %s/%s: %s", ax.label, fx.Name, msg)
		}
		// The kernel has no such filesystem and this run does not require it (FSRequireEnv): a row whose guests load
		// no module, whose kernel has it built in or not at all.
		t.Logf("MOUNTS-ABSENT %s/%s not run: %s", ax.label, fx.Name, msg)
		return notRun()
	}
	rep.Runs++
	var after Tree
	if len(fx.Mounts) > 0 {
		before, after = readSnapshot(t, snapshots+"before.json"), readSnapshot(t, snapshots+"after.json")
	} else if after, err = Snapshot(e.project); err != nil {
		t.Fatalf("snapshot after the run: %v", err)
	}
	results := map[string]Outcome{}
	sc := bufio.NewScanner(strings.NewReader(stdout.String()))
	for sc.Scan() {
		var r struct {
			ID    string `json:"id"`
			OK    bool   `json:"ok"`
			Errno int    `json:"errno"`
			Value string `json:"value"`
		}
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.ID != "" {
			results[r.ID] = Outcome{OK: r.OK, Errno: r.Errno, Value: r.Value}
			if r.Value != "" { // a race's counts: the soak's evidence that it interleaved (cmd/actor/race.go)
				t.Logf("VALUE %s at %s: %s", r.ID, ax.label, r.Value)
			}
		}
	}
	// Under fs.assurance: kernel, protected write targets require a decision plane (ADR 0041 D1 (a)): the
	// Landlock and listener axes refuse the fixture before its actor performs any action, and the tree is as the
	// run found it. By default those axes run it, the supervisor refusing the targets best effort (R15c), and check
	// each cell as any other.
	if fx.Model.FSAssuranceKernel && len(fx.Model.DenyWrite) > 0 && ax.want.Tier != TierBPFLSM {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) || exit.ExitCode() != 125 || len(results) != 0 ||
			!strings.Contains(stderr.String(), "protected write targets require a kernel decision plane") ||
			!strings.Contains(stderr.String(), "fs.assurance: kernel") {
			t.Fatalf("protected-write startup at %s: %v, %d actions\nstdout:\n%s\nstderr:\n%s",
				ax.label, runErr, len(results), stdout.String(), stderr.String())
		}
		if !maps.Equal(before, after) {
			rep.FailOpens = append(rep.FailOpens, fmt.Sprintf("%s at %s: the project tree changed although the run was refused before its actor started",
				fx.Name, ax.label))
		}
		t.Logf("STARTUP %s/%s refused before actor actions: fs.assurance: kernel needs a decision plane for its protected write targets",
			ax.label, fx.Name)
		return rep
	}
	// A table the plane cannot hold is refused at tier bpflsm before its actor performs any action (ErrPlaneCannotHold,
	// ErrPlaneDetachedPart), and one the listener cannot hold either at tier cgroup (ErrListenerAlias); the tree is as
	// the run found it.
	wantStderr := mountStartupRefusal(fx, ax)
	if wantStderr != nil {
		why := wantStderr[len(wantStderr)-1]
		said := true
		for _, w := range wantStderr {
			said = said && strings.Contains(stderr.String(), w)
		}
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) || exit.ExitCode() != 125 || len(results) != 0 || !said {
			t.Fatalf("a table the plane cannot hold at %s: %v, %d actions\nstdout:\n%s\nstderr:\n%s",
				ax.label, runErr, len(results), stdout.String(), stderr.String())
		}
		if !maps.Equal(before, after) {
			rep.FailOpens = append(rep.FailOpens, fmt.Sprintf("%s at %s: the project tree changed although the run was refused before its actor started",
				fx.Name, ax.label))
		}
		t.Logf("STARTUP %s/%s refused before actor actions: %s", ax.label, fx.Name, why)
		for j := range fx.Cells { // judged by the refusal: none of its cells ran here
			rep.Ran[NotRunKey(fx.ID(&fx.Cells[j]), string(ax.label))] = true
		}
		return rep
	}
	if len(results) != len(fx.Cells) {
		t.Fatalf("tego run --tier %s: %v, %d of %d actions reported\nstdout:\n%s\nstderr:\n%s", tier, runErr, len(results), len(fx.Cells),
			stdout.String(), stderr.String())
	}
	events := ledgerEvents(t, filepath.Join(e.base, "state", "ledger"))
	if len(fx.Mounts) > 0 {
		for _, ev := range events {
			if ev["kind"] == "refused" && ev["rule"] == "mount-topology" {
				t.Logf("mount fixture capability refusal: %v", ev)
			}
		}
	}
	t.Logf("tier %s, plane %q, answering %v, %d ledger lines", tier, ax.pin, ax.want, len(events))
	label := ax.label
	rep.Ran[RunnerKernel+"|"+string(label)], rep.Ran[RunnerLedger+"|"+string(label)] = true, true
	if column != nil {
		rep.Ran[RunnerParity+"|"+string(label)] = true
	}
	// The capability cross-check (capability.go): the oracle's predicates against the run's own capability line.
	var start map[string]any
	for _, ev := range events {
		if ev["kind"] == "run_start" {
			start = ev
			break
		}
	}
	for _, p := range RunCapabilityCrossCheck(fx.Model, ax.invariant, ax.runPlane(), start) {
		rep.Problems = append(rep.Problems, fmt.Sprintf("CAPABILITY %s at %s: %s", fx.Name, label, p))
	}
	effects := JudgeEffects(fx, before, after, results)
	failures := rep.Failures
	// judgeCell judges one cell on this axis and returns its CELL line, "" for a cell the axis does not answer.
	judgeCell := func(c *Cell) (cellLine string) {
		id := fx.ID(c)
		o, eff := results[id], effects[id]
		// The invariants and the effect judge first: they bind wherever the action ran, a column the cell leaves
		// unasked included (Cell.Unasked).
		finding := rep.JudgeFailOpens(fx, c, label, ax.invariant, o, eff)
		w, has := c.WantOn(ax.want, machine)
		if !has && !c.Generated {
			return
		}
		// floor: tier 1's floor answers this cell on this kernel, not the rules compile --test's column holds.
		floor := has && w != c.Want[ax.want]
		// judged: a generated cell the floor does not answer, whose judge is the kernel (ADR 0017 D1).
		judged := c.Generated && !has
		got, isVerdict := o.Verdict()
		lines := ledgerLines(e, c, o.Value, events)
		if len(lines) == 0 && mapOps[c.Op] && !w.NoLine {
			for _, ev := range events { // what the plane named instead, for the matcher (refusedMapLines)
				if ev["kind"] == "refused" && (ev["op"] == "mmap" || ev["op"] == "mprotect") {
					t.Logf("MAPLINE %s at %s: no line matched; the run's refused %v names %v", id, label, ev["op"], ev["target"])
				}
			}
		}
		cellLine = fmt.Sprintf("CELL %-58s kernel=%-7s errno=%-3d ledger=%s want=%s/%s effect=%s", id, verdictOrErr(got, isVerdict), o.Errno, describe(lines),
			w.Verdict, w.Rule, eff.Class)
		row := NewReportRow(machine, label, id)
		row.KernelVerdict, row.Errno, row.Ledger, row.Effect = verdictOrErr(got, isVerdict), o.Errno, describe(lines), string(eff.Class)
		if eff.Detail != "" {
			row.Effect += ": " + eff.Detail
		}
		if a, ok := column[rowName(id, colTier)]; ok {
			row.Compile = a.Verdict + "/" + a.Rule
		}
		rowAt := len(rep.Rows)
		rep.Rows = append(rep.Rows, row)

		a, inColumn := column[rowName(id, colTier)]
		if _, compiles := compileAction(c); column != nil && c.Generated && compiles && c.NoCompile == "" && !inColumn {
			// answersOf holds every row the table asked; a generated cell is asked at every tier, so its row is missing
			// only if the table lost it: its kernel-vs-column check is never skipped in silence.
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s at %s: compile --test's %s column has no row for the cell", id, label, colTier))
		}
		// The kernel against the cell, and against compile --test's column itself (I9); the ledger line against the
		// cell, and a judged cell's rule against the column's, but for the known naming classes (naming.go, ADR 0017's
		// 2026-10-19 note), which are counted, not baselined (judgeAnswers, judge_answers_test.go).
		ev := cellEvidence{fx: fx, cell: c, axis: NamingAxis{Tier: tier, Plane: ax.decisionPlane}, colTier: colTier, want: w,
			floor: floor, judged: judged, finding: finding, outcome: o, lines: lines}
		ev.want.Rule = strings.ReplaceAll(e.subst(w.Rule), "{{PEER}}", o.Value)
		if inColumn {
			ev.column = &a
		}
		j := judgeAnswers(ev)
		for runner, msg := range j.Failures {
			failures[FailureKey(runner, id, label)] = msg
		}
		if j.RuleCompared {
			rep.RulesCompared++
		}
		if j.Naming != "" {
			rep.Namings[j.Naming]++
			rep.Rows[rowAt].Naming = j.Naming
		}
		return
	}
	for i := range fx.Cells {
		c := &fx.Cells[i]
		// A handwritten cell's line is always logged; a generated cell's only where the cell drew a judgement (a
		// failure, fail-open, effect, problem or finding): the fs grid's 2,496 lines an axis are the report rows'
		// (TEGO_CONFORMANCE_REPORT), and through a guest's serial console they cost the landlock axis its budget
		// (9.2 s with them, 3.0 s without, on 6.17, lsm-bpf boot).
		n := rep.Judgements()
		if line := judgeCell(c); line != "" && (!c.Generated || rep.Judgements() != n) {
			t.Log(line)
		}
	}
	return rep
}

// mountStartupRefusal is the startup decision expected from a fixture's mount topology, after the axis has
// applied its plane fallback. Whole-tree aliases remain holdable by a plane, so only listener axes refuse them.
func mountStartupRefusal(fx *Fixture, ax axis) []string {
	switch {
	case fx.Model.PlaneCannotHold && ax.tier == TierBPFLSM:
		return []string{"cannot hold this contract in the decision plane", "where the decision plane's walk never meets the entry"}
	case fx.Model.ListenerRefuses && ax.tier == TierCgroup && ax.decisionPlane == "":
		return []string{"fanotify cannot hold a deny_read tree visible under another name"}
	default:
		return nil
	}
}

func verdictOrErr(v string, ok bool) string {
	if ok {
		return v
	}
	return "ERROR"
}

// describe spells every verdict line of one action, so a cell with several says which sources wrote them.
func describe(lines []map[string]any) string {
	if len(lines) == 0 {
		return "none"
	}
	var parts []string
	for _, l := range lines {
		parts = append(parts, fmt.Sprintf("%v/%v/%v", l["verdict"], l["rule"], l["source"]))
	}
	return strings.Join(parts, " + ")
}

// ledgerLines finds the verdict lines of the cell's action: an fs or exec line whose path is the cell's own
// canonical path (every cell owns its path), a net line whose destination is its address, or a process or control
// line of its op (controlLines; peer is the pid the actor reported for it).
func ledgerLines(e *env, c *Cell, peer string, events []map[string]any) (out []map[string]any) {
	kind, key, val := "fs", "path", e.path(c.canon())
	spelled := e.path(c.Path)
	switch c.Op {
	case OpExec:
		kind = "exec"
	case OpExecveatFD, OpExecProcFD:
		// An exec by descriptor is recorded under the image's path or under the descriptor's: the supervisor writes
		// /proc/self/fd/N as spelled, the plane's kernel line the bprm filename, /dev/fd/N for execveat (each allow's
		// rule names the image resolved). A descriptor-spelled line is the cell's by its argv[0], the actor's path.
		for _, ev := range events {
			argv, _ := ev["argv"].([]any)
			p := fmt.Sprint(ev["path"])
			if ev["kind"] == "exec" && ev["verdict"] != nil && ev["verdict"] != "" &&
				(p == val || fdPath.MatchString(p) && len(argv) > 0 && fmt.Sprint(argv[0]) == c.Path) {
				out = append(out, ev)
			}
		}
		return out
	case OpExecLoader:
		// The loader as PT_INTERP spells it (/lib64/...) or where that leads.
		kind = "exec"
		if real, err := filepath.EvalSymlinks(spelled); err == nil {
			val = real
		}
	case OpMemfdCreate:
		return nil // nothing ran: the arm's refusal and a created memfd write no line (enforce-landlock R11a)
	case OpMemfdExec:
		// An anonymous image's exec is recorded fileless: under the memfd's name by the supervisor, under the
		// descriptor the exec spelled (/proc/self/fd/N) by the plane's kernel line. The cell is its fixture's one.
		for _, ev := range events {
			if ev["kind"] == "exec" && ev["verdict"] != nil && ev["verdict"] != "" && ev["fileless"] == true {
				out = append(out, ev)
			}
		}
		return out
	case OpMemfdMapExec, OpMapExecRIE, OpMprotectExec, OpMprotectRIE, OpExecmod, OpExecmem:
		return refusedMapLines(events, func(target string) bool {
			if c.Op == OpMemfdMapExec {
				return target == "anonymous" // the plane names an anonymous image's map so (AL2023's 6.1, 2026-10-19)
			}
			return target == val || target == spelled || devInoName(target, filepath.Base(val))
		})
	case OpConnectTCP, OpConnectUDP, OpSendUDP:
		kind, key, val = "net", "dst", e.subst(c.Addr)
		if strings.HasPrefix(c.Addr, "$") { // an address the run made, which the actor read from its environment
			val = peer
		}
	case OpConnectUnix:
		kind, key, val = "net", "dst", "unix:"+e.subst(c.Addr)
	case OpPtraceAttach, OpPtraceTraceme, OpKeyctl, OpAddKey, OpRequestKey, OpBPF:
		return controlLines(c, peer, events)
	case OpMapExec:
		return refusedMapLines(events, func(target string) bool { return target == val || target == spelled })
	case OpRaceArgvExec:
		// The exec lines of the copy whose copied argv read the denied word (the supervisor's copy, ADR 0048 (3)).
		for _, ev := range events {
			argv, _ := ev["argv"].([]any)
			if ev["kind"] == "exec" && ev["verdict"] != nil && ev["verdict"] != "" && fmt.Sprint(ev["path"]) == val &&
				len(argv) == 2 && fmt.Sprint(argv[1]) == c.Argv[1] {
				out = append(out, ev)
			}
		}
		return out
	case OpRaceSymlinkRead, OpRaceSymlinkWrite:
		// The target's lines only. Where the kernel's recorder answers (the listener, the plane) they are every open
		// of the target, and judgeAnswers holds them to no allow and, for a refused race, at least one refusal. At
		// tier landlock the supervisor's advisory lines (ADR 0016 (2)) name the link, the name the agent spelled, each
		// with the model's prediction for what the link led to when the supervisor resolved it; the swap can change
		// that before the kernel's open, so they disagree with the kernel both ways and go unjudged.
		spelled = val
	}
	for _, ev := range events {
		if ev["kind"] != kind || ev["verdict"] == nil || ev["verdict"] == "" {
			continue
		}
		if got := fmt.Sprint(ev[key]); got == val || (kind != "net" && got == spelled) {
			out = append(out, ev)
		}
	}
	return out
}

// readSnapshot reads a tree the mount namespace helper wrote.
func readSnapshot(t *testing.T, path string) Tree {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the helper's snapshot: %v", err)
	}
	var tree Tree
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatalf("the helper's snapshot %s: %v", path, err)
	}
	return tree
}

// ledgerEvents reads the one run's ledger under root.
func ledgerEvents(t *testing.T, root string) []map[string]any {
	t.Helper()
	runs, err := filepath.Glob(filepath.Join(root, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledgers under %s: %v (%v), want exactly one run", root, runs, err)
	}
	data, err := os.ReadFile(runs[0])
	if err != nil {
		t.Fatal(err)
	}
	var events []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("ledger line %q: %v", line, err)
		}
		events = append(events, ev)
	}
	return events
}

// refusedMapLines are the plane's refused map lines whose target match accepts. A refused map or mprotect is the
// plane's own refused line (op mmap or mprotect, target the file, ADR 0027), which carries no verdict key: refused
// lines are no action (spec/record/v1).
func refusedMapLines(events []map[string]any, match func(target string) bool) (out []map[string]any) {
	for _, ev := range events {
		if ev["kind"] == "refused" && (ev["op"] == "mmap" || ev["op"] == "mprotect") && match(fmt.Sprint(ev["target"])) {
			line := map[string]any{"verdict": Refused}
			for k, v := range ev {
				line[k] = v
			}
			out = append(out, line)
		}
	}
	return out
}

// controlLines are a process or control cell's refused lines: those with its op's ledger op (controlOps), and for a
// ptrace op the pid its hook names, which the actor reported (peer). A refused line carries no verdict key
// (spec/record/v1); the copy says refused. Every fixture has one cell of each keyring and bpf op, so their lines are
// found by op alone.
func controlLines(c *Cell, peer string, events []map[string]any) (out []map[string]any) {
	op := controlOps[c.Op]
	for _, ev := range events {
		if ev["kind"] != "refused" || ev["op"] != op {
			continue
		}
		if _, named := targetOps[c.Op]; named && (peer == "" || fmt.Sprint(ev["target"]) != peer) {
			continue
		}
		line := map[string]any{"verdict": Refused}
		maps.Copy(line, ev)
		out = append(out, line)
	}
	return out
}

// mapOps are the ops whose line is the plane's refused map line (refusedMapLines).
var mapOps = map[string]bool{OpMapExec: true, OpMemfdMapExec: true, OpMapExecRIE: true, OpMprotectExec: true, OpMprotectRIE: true,
	OpExecmod: true, OpExecmem: true}

// fdPath is an exec's path spelled through the process's own descriptor table.
var fdPath = regexp.MustCompile(`^/(proc/self|dev)/fd/[0-9]+$`)

// devInoName reports whether a plane's refused map line names its target as dev:ino/name with this name: the plane
// names a file outside the run's rows by its device, inode and dentry name (enforce-plane, the refused line).
func devInoName(target, name string) bool {
	dev, rest, ok := strings.Cut(target, "/")
	return ok && rest == name && devIno.MatchString(dev)
}

var devIno = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
