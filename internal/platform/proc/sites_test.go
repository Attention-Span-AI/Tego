// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// modulePath is this module's import path, and moduleRoot is where its go.mod is, seen from this package's
// directory (go test runs a package's tests in it).
const modulePath = "github.com/attention-span-ai/tego"

var moduleRoot = filepath.Join("..", "..", "..")

// armRelation says when a start site runs against proc.Arm. The first mark of this process's fanotify group arms
// the process and the group's last unmark disarms it (ADR 0021 (3)); a start while armed is refused, and a start
// in flight holds Arm off, so what a row claims is that no mark of this process's group can exist while the
// start forks and execs.
type armRelation string

const (
	// beforeArm: the start is ordered before this process's first mark, or the process holds no group at all.
	// The launcher starts its reaper and its stage before runner.arm places the first mark; doctor probes
	// before Prepare, or under `tego doctor`, which never marks anything.
	beforeArm armRelation = "before-arm"
	// afterDetach: the start waits until this process's marks are gone, Detach having unmarked and disarmed it.
	afterDetach armRelation = "after-detach"
	// guarded: the start is a shared one, whose callers' own rows say when they call it. The scan follows the
	// function by its name (followedStartFuncs), so every reference to it is a row, and proc.Start refuses it with
	// ErrArmed while this process is armed: a caller that is late fails the start, never the host. A row is
	// guarded exactly when its function is one the scan follows (startFuncProblems).
	guarded armRelation = "guarded"
)

// startFunc is the functions of one package that start a process, or hand a command to one that does, and where
// a reference to one of them is found.
type startFunc struct {
	pkg     string   // import path; empty when no other package can name any of them
	name    string   // the package's name: how a reference through an import reads, and what the lint's pattern matches
	funcs   []string // the functions: an exported one is found through any import of pkg, each of them bare in home
	methods []string // unexported methods: found as the name of a selector, on any value, in home
	home    string   // the package's directory below the module root, whose files name the functions bare
}

// startFuncs are the starts lint can name, each with a forbidigo rule (TestLintExclusionsAreTheStartSites).
// proc.Start is the one start of non-test code (ADR 0021 (3)): lint bans os/exec outside this package and every
// other way to fork or exec, so every start passes through it. cgroup.StartHelper and StartHelperExec are the one
// wrapper over it, which tego's detached helpers start through (the run's reaper, the build's linger timer and
// ring trimmer, a library's probe removal): a new helper is the likely shape of ADR 0021 (6)'s privileged-exec
// broker, so it is listed with the start it hands its command to. proc.Command only builds a command, and a
// command is started through the functions above or not at all (lint refuses exec.Cmd's own Start, Run, Output
// and CombinedOutput), so its callers are not sites. An unexported function that makes one of these starts is
// followed too, though no lint rule can name it (followedStartFuncs).
var startFuncs = []startFunc{
	{pkg: modulePath + "/internal/platform/proc", name: "proc", funcs: []string{"Start"}},
	{pkg: modulePath + "/internal/handoff", name: "handoff", funcs: []string{"Spawn"}, home: "internal/handoff"},
	{pkg: modulePath + "/internal/runtime/cgroup", name: "cgroup", funcs: []string{"StartHelper", "StartHelperExec"},
		home: "internal/runtime/cgroup"},
}

// lintCall reports whether call, a startRef's or a startSite's, is a start lint can name, one of startFuncs'.
func lintCall(call string) bool {
	for _, sf := range startFuncs {
		for _, fn := range sf.funcs {
			if call == sf.name+"."+fn {
				return true
			}
		}
	}
	return false
}

// lintExemptPath is the path .golangci.yml exempts from every ADR 0021 forbidigo rule: test code, this package,
// the test helpers and the tools, none of which is the engine (ADR 0021 (3)). The exemption is scoped to the
// rules' text, lintExemptText, so this package stays under ADR 0023's descriptor rules. The scan skips the same
// files, and the config test below checks that .golangci.yml still says this.
const lintExemptPath = `(_test\.go$|internal/platform/proc/|internal/testutil/|^tools/|^test/)`

// lintExemptText is the text the exemption is scoped to: it must match every ADR 0021 rule's message.
const lintExemptText = "ADR 0021"

var lintExempt = regexp.MustCompile(lintExemptPath)

// siteRuleText is what the lint's message for a start site says, and what each file's exclusion in .golangci.yml
// matches, so that the exclusion lifts these rules for the file and no other forbidigo rule.
const siteRuleText = "reviewed process-start site"

// A startSite is one function that starts a process, or hands a command to a start, and says when that runs
// against Arm. A row is exact: the function must make n such calls, so a second start in a listed function is a
// change someone reads, and a row whose function no longer starts anything is removed with its exclusion.
type startSite struct {
	file string // below the module root, slash-separated
	fn   string // the enclosing function, Type.Method for a method; a package variable's initializer is its name
	call string // "proc.Start", "cgroup.StartHelper", "cgroup.StartHelperExec", or a function a row makes a start (package.name)
	n    int
	rel  armRelation
	when string // what the relation stands on
}

// startSites is every site of the tree, which ADR 0021 (6) makes mechanical. A new one, E70's broker for
// example, needs a row here saying when it runs against Arm, and an exclusion for its file in .golangci.yml when
// its call is one lint names: the broker starts before the stage, which is a beforeArm start in every mode. A
// function of its own that makes the start is followed from then on (followedStartFuncs): its row is guarded, and
// each function that calls it is a row too, with the relation of its own.
var startSites = []startSite{
	{
		file: "internal/doctor/planeexecpin.go", fn: "exercisePlaneExecPin", call: "doctor.startPinGate", n: 1, rel: beforeArm,
		when: "the exec pin cell's gates, cloned into its scratch cgroup by doctor before the cell arms it, before Prepare in a " +
			"run (doctor.ForRun) and under `tego doctor`, where no mark exists",
	},
	{
		file: "internal/doctor/planeexecpin.go", fn: "exercisePlaneExecPin", call: "doctor.startPlaneChildAs", n: 1, rel: beforeArm,
		when: "the exec pin cell's writer child, cloned into its scratch cgroup by doctor before the cell arms it, before Prepare " +
			"in a run (doctor.ForRun) and under `tego doctor`, where no mark exists",
	},
	{
		file: "internal/doctor/planeexecpin.go", fn: "startPinGate", call: "proc.Start", n: 1, rel: guarded,
		when: "the exec pin cell's gate: its callers' rows say when they call it, and Start refuses it with ErrArmed while this " +
			"process holds marks",
	},
	{
		file: "internal/doctor/planeknown.go", fn: "planeKnownActions", call: "doctor.planeKnownExec", n: 3, rel: beforeArm,
		when: "the known answers' three exec actions, run by the plane probe's known-answer child (planeKnownMain), a process of " +
			"its own that holds no group",
	},
	{
		file: "internal/doctor/planeknown.go", fn: "planeKnownExec", call: "proc.Start", n: 1, rel: guarded,
		when: "doctor's known-answer exec: its callers' rows say when they call it, and Start refuses it with ErrArmed while " +
			"this process holds marks",
	},
	{
		file: "internal/doctor/planeknown.go", fn: "exercisePlaneKnown", call: "doctor.startPlaneChildAs", n: 1, rel: beforeArm,
		when: "the known answers' child, cloned into the probe's scratch cgroup by doctor, before Prepare in a run (doctor.ForRun) " +
			"and under `tego doctor`, where no mark exists",
	},
	{
		file: "internal/doctor/planeprobe.go", fn: "exercisePlane", call: "doctor.planeAction", n: 1, rel: beforeArm,
		when: "doctor's own outside snapshot, one syscall per hook, which runs before Prepare in a run (doctor.ForRun) and under " +
			"`tego doctor`, which marks nothing ever",
	},
	{
		file: "internal/doctor/planeprobe.go", fn: "PlaneProbeMain", call: "doctor.planeAction", n: 1, rel: beforeArm,
		when: "the probe child's one syscall per hook, made in a process of its own that holds no group",
	},
	{
		file: "internal/doctor/planeprobe.go", fn: "planeAction", call: "proc.Start", n: 1, rel: guarded,
		when: "the probe row's bprm_check exec, the one hook whose syscall starts a process: its callers' rows say when they call it, " +
			"and Start refuses it with ErrArmed while this process holds marks",
	},
	{
		file: "internal/doctor/planeprobe.go", fn: "startPlaneChild", call: "doctor.startPlaneChildAs", n: 1, rel: beforeArm,
		when: "the probe row's child, cloned into the scratch cgroup by exercisePlane, before Prepare in a run (doctor.ForRun) " +
			"and under `tego doctor`, where no mark exists",
	},
	{
		file: "internal/doctor/planeprobe.go", fn: "startPlaneChildAs", call: "proc.Start", n: 1, rel: guarded,
		when: "the plane probe's children, cloned into its scratch cgroup by doctor: its callers' rows say when they call it, and " +
			"Start refuses it with ErrArmed while this process holds marks",
	},
	{
		file: "internal/doctor/planeprobe_control.go", fn: "planeControlAction", call: "doctor.startPlaneChildAs", n: 2, rel: beforeArm,
		when: "the ptrace controls' helper children, started inside a hook's action when none was made beforehand, which is " +
			"doctor's outside snapshot (exercisePlane): before Prepare in a run (doctor.ForRun) and under `tego doctor`, where " +
			"no mark exists",
	},
	{
		file: "internal/doctor/planeprobe_control.go", fn: "planePre.prepareControls", call: "doctor.startPlaneChildAs", n: 2, rel: beforeArm,
		when: "the ptrace controls' two helper children, made by the probe's child beside its fixtures (newPlanePre) before the " +
			"probe row is armed, in a process of its own that holds no group",
	},
	{
		file: "internal/cli/asknotice.go", fn: "startNotifier", call: "proc.Start", n: 1, rel: guarded,
		when: "tego run's desktop notice of a held ask (ADR 0122): its caller's row says when it calls it, and Start refuses it " +
			"with ErrArmed while this process holds marks",
	},
	{
		file: "internal/cli/asknotice.go", fn: "desktopNotice.send", call: "cli.startNotifier", n: 1, rel: beforeArm,
		when: "a held ask's notice during the run, wired only for a tier-landlock run of a non-root launcher (askNotices): " +
			"that launcher holds no fanotify group, since only enforce/cgroup's listener (tiers cgroup and bpflsm) calls proc.Arm",
	},
	{
		file: "internal/cli/mcp_relay.go", fn: "startRelayedServer", call: "proc.Start", n: 1, rel: guarded,
		when: "the MCP relay shim's start of the waiting server stage (ADR 0126 §4), registered before exec: its caller's row says when it calls it, and " +
			"Start refuses it with ErrArmed while this process holds marks",
	},
	{
		file: "internal/cli/mcp.go", fn: "cmdMCP", call: "cli.startRelayedServer", n: 1, rel: beforeArm,
		when: "`tego mcp relay`, a process of its own inside a run that only relays lines: it places no fanotify mark, since " +
			"only enforce/cgroup's listener in a launcher calls proc.Arm",
	},
	{
		file: "internal/control/cli/open.go", fn: "openURL", call: "proc.Start", n: 1, rel: guarded,
		when: "the dashboard's browser opener (serve --open): its caller's row says when it calls it, and Start refuses it with " +
			"ErrArmed while this process holds marks",
	},
	{
		file: "internal/control/cli/serve.go", fn: "cmdServe", call: "cli.openURL", n: 1, rel: beforeArm,
		when: "serve --open starts the browser once the dashboard listens, in tego-control's own process, which holds no fanotify " +
			"group: nothing it links calls Arm",
	},
	{
		file: "internal/handoff/exec.go", fn: "Spawn", call: "proc.Start", n: 1, rel: guarded,
		when: "the start of the sealed tego-control as a child (ADR 0100 (1b), (1e)): a shared start whose callers' rows say when " +
			"they call it, none in this tree yet; tego-control and the CLI verbs that spawn it hold no fanotify group, and Start " +
			"refuses it with ErrArmed while the process holds marks",
	},
	{
		file: "internal/maze/cli/save.go", fn: "saveLocked", call: "cli.verifyEngine", n: 1, rel: beforeArm,
		when: "maze's check of a saved contract (`tego compile --test --offline`), run once the rules are saved, in the maze " +
			"CLI's own process, which holds no group: nothing it links calls Arm",
	},
	{
		file: "internal/maze/cli/save.go", fn: "verifyEngine", call: "proc.Start", n: 1, rel: guarded,
		when: "maze's one start, of the engine's compile check: saveLocked is its one caller, and its row says when; Start refuses " +
			"it with ErrArmed while the process holds marks, which maze's never does",
	},
	{
		file: "internal/selftest/checks.go", fn: "checks", call: "selftest.runUnlisted", n: 1, rel: beforeArm,
		when: "tego test's exec check (ADR 0074), run by the hidden __check verb, a process of its own that links no Arm: " +
			"directly, and as the agent of a self-test run, which holds no group",
	},
	{
		file: "internal/selftest/checks.go", fn: "runUnlisted", call: "proc.Start", n: 1, rel: guarded,
		when: "the exec check's start of the decoy copy of /bin/true: the checks row says when it runs, and Start refuses it " +
			"with ErrArmed while the process holds marks",
	},
	{
		file: "internal/selftest/driver.go", fn: "driver.check", call: "selftest.startTego", n: 1, rel: beforeArm,
		when: "tego test's starts of tego __check and tego run (ADR 0074), in tego test's own process, which holds no fanotify " +
			"group: nothing it does calls Arm",
	},
	{
		file: "internal/selftest/driver.go", fn: "driver.events", call: "selftest.startTego", n: 1, rel: beforeArm,
		when: "tego test's start of tego events to read a run's ledger, in tego test's own process, which holds no group",
	},
	{
		file: "internal/selftest/driver.go", fn: "startTego", call: "proc.Start", n: 1, rel: guarded,
		when: "tego test's one start of the tego binary: its callers' rows say when, and Start refuses it with ErrArmed while " +
			"the process holds marks",
	},
	{
		file: "internal/runtime/adopt_reap.go", fn: "adoption.startReaper", call: "runtime.startAdoptReaperProcess", n: 1,
		rel: beforeArm,
		when: "an adoption's reaper, started after the adoption's record is written and before the agent is moved, so before " +
			"Prepare and Arm; an adopter places no fanotify mark at all (a record-only table has no listener rule, a boundary " +
			"needs a plane mode, checked before Arm)",
	},
	{
		file: "internal/runtime/adopt_reap.go", fn: "startAdoptReaperProcess", call: "cgroup.StartHelper", n: 1, rel: guarded,
		when: "the adoption's reaper as one of tego's helpers: adoption.startReaper is its one caller, and its row says when",
	},
	{
		file: "internal/runtime/capture/uprobe/shared.go", fn: "StartDetaches", call: "uprobe.spawnDetach", n: 1, rel: afterDetach,
		when: "a library's probe removal: Source.Stop queues it (queueDetach) and `tego run` starts it with StartDetaches once the " +
			"run's enforcement is released and no mark of this process is left (ADR 0026 (7))",
	},
	{
		file: "internal/runtime/capture/uprobe/shared.go", fn: "spawnDetach", call: "cgroup.StartHelperExec", n: 1, rel: guarded,
		when: "a library's probe removal as one of tego's helpers: StartDetaches is its one caller, and its row says when",
	},
	{
		file: "internal/runtime/cgroup/helper.go", fn: "StartHelper", call: "cgroup.startHelperIn", n: 1, rel: guarded,
		when: "StartHelper hands startHelperIn the real mount, euid, /proc/self/cgroup and pid: its callers' rows say when they call it",
	},
	{
		file: "internal/runtime/cgroup/helper.go", fn: "StartHelperExec", call: "cgroup.StartHelper", n: 1, rel: guarded,
		when: "StartHelperExec is StartHelper with the plain helper's command: the same start, and its callers' rows say when they call it",
	},
	{
		file: "internal/runtime/cgroup/helper.go", fn: "startHelperIn", call: "proc.Start", n: 2, rel: guarded,
		when: "StartHelper's own start, once into helpers.scope and once, if that fails, in this cgroup: its callers' rows say when " +
			"they call it, and Start refuses it with ErrArmed while this process holds marks",
	},
	{
		file: "internal/runtime/enforce/cgroup/linger.go", fn: "startHelperProcess", call: "cgroup.StartHelperExec", n: 1, rel: guarded,
		when: "this package's one start of a helper, a variable so that a test sees what would be started: its callers' rows say " +
			"when they call it, the linger timer's and the ring trimmer's",
	},
	{
		file: "internal/runtime/enforce/cgroup/linger.go", fn: "startTimerProcess", call: "cgroup.startHelperProcess", n: 1, rel: afterDetach,
		when: "a build's linger timer, started where no mark of this process can exist: its own build's, once this launcher is " +
			"the last out of it, by Close, after Detach has closed the group, and by a failed Prepare's unwind, before any mark " +
			"was placed; another build's whose timer died, by Prepare's re-arm pass (rearmExpired), which runs once the build " +
			"lock is held and before Arm places the first mark; and by processes that hold no group: a reaper (ReapBuild) and " +
			"`tego stop` (RearmTimers)",
	},
	{
		file: "internal/runtime/enforce/cgroup/rings.go", fn: "Handle.parkRings", call: "cgroup.startHelperProcess", n: 1, rel: afterDetach,
		when: "the ring trimmer, started once the slot is released (releaseSlotAndPark): by Detach, after the group's close, and by " +
			"a failed Prepare's unwind, before any mark was placed",
	},
	{
		file: "internal/runtime/launch/launcher.go", fn: "Launcher.Start", call: "launch.startOnKeptThread", n: 1, rel: beforeArm,
		when: "the run's child stage: runtime.startChild starts it after Prepare, which made the group with no mark, and after the " +
			"reaper, and before runner.arm places the first mark (ADR 0021 (2))",
	},
	{
		file: "internal/runtime/launch/deputy.go", fn: "stage.spawnDeputy", call: "launch.startDeputy", n: 1, rel: beforeArm,
		when: "the run's open deputy (ADR 0041 D2), started by the child stage, a process that holds no fanotify mark, after " +
			"landlock_restrict_self and before the stage reports on its control pipe, so before runner.arm places the first mark",
	},
	{
		file: "internal/runtime/launch/deputy.go", fn: "stage.startDeputy", call: "proc.Start", n: 1, rel: guarded,
		when: "the deputy's one start: stage.spawnDeputy is its one caller, and its row says when; Start refuses it with " +
			"ErrArmed while the process holds marks, which the stage never does",
	},
	{
		file: "internal/runtime/launch/launcher.go", fn: "startOnKeptThread", call: "proc.Start", n: 1, rel: guarded,
		when: "the launcher's one start, on a thread kept for the child's PR_SET_PDEATHSIG: Launcher.Start is its one caller, and its " +
			"row says when; Start refuses it with ErrArmed while this process holds marks",
	},
	{
		file: "internal/runtime/reap.go", fn: "runner.startDNSReaper", call: "runtime.startReaperProcess", n: 1, rel: beforeArm,
		when: "a DNS broker's run's reaper, started as soon as setupDNSBroker has bound the endpoint, before Prepare, so before the " +
			"stage and Arm (ADR 0020 (2), finding dns-5)",
	},
	{
		file: "internal/runtime/reap.go", fn: "runner.startReaper", call: "runtime.startReaperProcess", n: 1, rel: beforeArm,
		when: "every other run's reaper, started after Prepare and before the stage, so before Arm (ADR 0020 (2))",
	},
	{
		file: "internal/runtime/reap.go", fn: "startReaperProcess", call: "cgroup.StartHelper", n: 1, rel: guarded,
		when: "the run's reaper as one of tego's helpers: its callers' rows say when they call it, startDNSReaper's and startReaper's",
	},
}

// siteFunc splits a row's fn into the function's own name and whether it is a method.
func siteFunc(fn string) (name string, method bool) {
	if _, m, ok := strings.Cut(fn, "."); ok {
		return m, true
	}
	return fn, false
}

// followedStartFuncs is what the scan looks for: startFuncs, and each function a row says makes one of their
// starts. Lint names an exported function through its package, but no rule can name a bare name inside the package
// that declares it, so a new call of an unexported function that starts a process, from another file of that
// package, would pass lint and pass a scan of startFuncs alone: the start would go unreviewed behind the wrapper
// that is a row. Such a function is a start function in turn, found by its bare name in its own package's
// directory (an unexported method as the name of a selector, on any value, there), and each call of it is a row of
// its own. The scan follows a start one function out: the function that calls the wrapper is where the start is
// decided, and its row says when; what calls that is the package's own order, which ADR 0021 (2) fixes and the
// arming tests check.
func followedStartFuncs(sites []startSite) []startFunc {
	followed := make([]startFunc, len(startFuncs))
	for i, sf := range startFuncs {
		followed[i] = sf
		followed[i].funcs = slices.Clone(sf.funcs)
		followed[i].methods = slices.Clone(sf.methods)
	}
	for _, s := range sites {
		name, method := siteFunc(s.fn)
		if !lintCall(s.call) || token.IsExported(name) || strings.HasPrefix(name, "<") {
			continue // no start of its own, or one startFuncProblems refuses
		}
		dir := path.Dir(s.file)
		i := slices.IndexFunc(followed, func(sf startFunc) bool { return sf.home == dir })
		if i < 0 {
			followed = append(followed, startFunc{name: path.Base(dir), home: dir})
			i = len(followed) - 1
		}
		list := &followed[i].funcs
		if method {
			list = &followed[i].methods
		}
		if !slices.Contains(*list, name) {
			*list = append(*list, name)
		}
	}
	return followed
}

// startFuncProblems checks what followedStartFuncs relies on the rows for: that each start a row makes is one the
// scan can follow, and that a row is guarded exactly when its function is followed, since only then do its
// callers' rows exist to say when they call it. None is the table being consistent.
func startFuncProblems(sites []startSite) []string {
	var problems []string
	for _, sf := range startFuncs {
		for _, fn := range sf.funcs {
			if !token.IsExported(fn) {
				problems = append(problems, fmt.Sprintf("startFuncs lists %s.%s, which is not exported: lint cannot name it, "+
					"and a row makes an unexported function a start function itself", sf.name, fn))
			}
		}
	}
	followed := followedStartFuncs(sites)
	isFollowed := func(s startSite) bool {
		name, method := siteFunc(s.fn)
		for _, sf := range followed {
			names := sf.funcs
			if method {
				names = sf.methods
			}
			if sf.home == path.Dir(s.file) && slices.Contains(names, name) {
				return true
			}
		}
		return false
	}
	for _, s := range sites {
		name, method := siteFunc(s.fn)
		follows := isFollowed(s)
		refused := false // a start the scan cannot follow, whose relation is then no matter
		if lintCall(s.call) {
			switch {
			case strings.HasPrefix(name, "<"):
				problems = append(problems, fmt.Sprintf("startSites row %s %s %s starts a process from a declaration with no name, "+
					"which no scan can follow: make it a function", s.file, s.fn, s.call))
				refused = true
			case token.IsExported(name) && method:
				problems = append(problems, fmt.Sprintf("startSites row %s %s %s is an exported method that starts a process, "+
					"and a call of it from another package cannot be told from any other method's: start through a function",
					s.file, s.fn, s.call))
				refused = true
			case token.IsExported(name) && !follows:
				problems = append(problems, fmt.Sprintf("startSites row %s %s %s is an exported function that starts a process, "+
					"which other packages can call: list it in startFuncs, with a forbidigo rule for it in .golangci.yml, "+
					"so that a call of it is a site", s.file, s.fn, s.call))
				refused = true
			}
		}
		switch {
		case follows && s.rel != guarded:
			problems = append(problems, fmt.Sprintf("startSites row %s %s %s is a function the scan follows, whose callers' "+
				"rows say when they call it, so its relation is guarded, not %q", s.file, s.fn, s.call, s.rel))
		case !follows && !refused && s.rel == guarded:
			problems = append(problems, fmt.Sprintf("startSites row %s %s %s is guarded, but no row makes %s a function the scan "+
				"follows, so no row of a caller says when: it says when it runs against Arm itself", s.file, s.fn, s.call, s.fn))
		}
	}
	slices.Sort(problems)
	return problems
}

// A startRef is one reference to a start function in the tree.
type startRef struct {
	file string
	line int
	fn   string
	call string
}

// scanStartRefs reads every non-test Go file below root that lint does not exempt and returns each reference to
// one of funcs: a selector naming it through whatever name its package is imported under, or its bare name
// inside its own package's directory, which is the only place an unexported one can be named. Whether the
// reference is a call does not matter, since a function value is a start as much as a call is, and a name a
// declaration gives is no reference. Directories the go tool ignores (a name starting with "." or "_", testdata,
// vendor) and nested modules are not read, and neither is any file other than a .go file. A dot import of a start
// package is an error: it would hide every reference behind a bare name.
func scanStartRefs(root string, funcs []startFunc) ([]startRef, error) {
	var refs []startRef
	fsys := os.DirFS(root)
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" {
				return fs.SkipDir
			}
			if _, err := fs.Stat(fsys, path.Join(p, "go.mod")); err == nil {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || lintExempt.MatchString(p) {
			return nil
		}
		found, err := scanStartFile(fsys, p, funcs)
		refs = append(refs, found...)
		return err
	})
	return refs, err
}

// scanStartFile is scanStartRefs for one file of fsys. Only a file that imports a package with an exported start
// function, or lies in the directory of one with any, is parsed beyond its imports.
func scanStartFile(fsys fs.FS, p string, funcs []startFunc) ([]startRef, error) {
	src, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	head, err := parser.ParseFile(fset, p, src, parser.ImportsOnly|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	local := map[string]*startFunc{} // the names this file calls a start package by
	var homes []*startFunc           // the start packages this file belongs to, whose functions it may name bare
	for i := range funcs {
		sf := &funcs[i]
		if sf.home != "" && path.Dir(p) == sf.home {
			homes = append(homes, sf)
		}
		if sf.pkg == "" || !slices.ContainsFunc(sf.funcs, token.IsExported) {
			continue // no other package can name one of its functions
		}
		for _, imp := range head.Imports {
			if ip, err := strconv.Unquote(imp.Path.Value); err != nil || ip != sf.pkg {
				continue
			}
			switch {
			case imp.Name == nil:
				local[sf.name] = sf
			case imp.Name.Name == "_":
				// Imported for its effects: it names nothing.
			case imp.Name.Name == ".":
				return nil, fmt.Errorf("%s dot-imports %s, which hides every reference to its start behind a bare name: import it by name", p, sf.pkg)
			default:
				local[imp.Name.Name] = sf
			}
		}
	}
	if len(local) == 0 && len(homes) == 0 {
		return nil, nil
	}
	f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	var refs []startRef
	add := func(pos token.Pos, fn string, sf *startFunc, name string) {
		refs = append(refs, startRef{file: p, line: fset.Position(pos).Line, fn: fn, call: sf.name + "." + name})
	}
	var visit func(root ast.Node, fn string)
	visit = func(root ast.Node, fn string) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				// The selector's right side is a field, a method or a package's member. The member of an imported
				// start package can be a start when it is exported, and a method, named on any value, can be one
				// in the home package; the selector's left side may hold more.
				id, plain := n.X.(*ast.Ident)
				var pkg *startFunc // the start package n.X names, when it is an import's name
				if plain {
					pkg = local[id.Name]
				}
				switch {
				case pkg != nil:
					if token.IsExported(n.Sel.Name) && slices.Contains(pkg.funcs, n.Sel.Name) {
						add(n.Pos(), fn, pkg, n.Sel.Name)
					}
				default:
					for _, h := range homes {
						if slices.Contains(h.methods, n.Sel.Name) {
							add(n.Pos(), fn, h, n.Sel.Name)
						}
					}
				}
				if !plain {
					visit(n.X, fn)
				}
				return false
			case *ast.Ident:
				for _, h := range homes {
					if slices.Contains(h.funcs, n.Name) {
						add(n.Pos(), fn, h, n.Name)
					}
				}
			}
			return true
		})
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			// The declared name is not a reference: only the receiver, the signature and the body are read.
			name := funcDeclName(d)
			if d.Recv != nil {
				visit(d.Recv, name)
			}
			visit(d.Type, name)
			if d.Body != nil {
				visit(d.Body, name)
			}
		case *ast.GenDecl:
			// The names a spec declares are no references either: its type and the values of a variable are read, and
			// the first name of a variable is the function its values' references are in.
			for _, spec := range d.Specs {
				switch sp := spec.(type) {
				case *ast.ValueSpec:
					name := "<" + d.Tok.String() + ">"
					if len(sp.Names) > 0 {
						name = sp.Names[0].Name
					}
					if sp.Type != nil {
						visit(sp.Type, name)
					}
					for _, v := range sp.Values {
						visit(v, name)
					}
				case *ast.TypeSpec:
					if sp.TypeParams != nil {
						visit(sp.TypeParams, "<type>")
					}
					visit(sp.Type, "<type>")
				}
			}
		}
	}
	return refs, nil
}

// funcDeclName is a function's name, or Type.Name for a method.
func funcDeclName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	t := d.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	switch g := t.(type) {
	case *ast.IndexExpr:
		t = g.X
	case *ast.IndexListExpr:
		t = g.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + d.Name.Name
	}
	return d.Name.Name
}

// startSiteProblems compares what the tree has with what the list says, and names each difference in terms
// that say what to do about it. None is the list being exact.
func startSiteProblems(refs []startRef, sites []startSite) []string {
	type key struct{ file, fn, call string }
	have := map[key][]startRef{}
	for _, r := range refs {
		k := key{r.file, r.fn, r.call}
		have[k] = append(have[k], r)
	}
	var problems []string
	want := map[key]startSite{}
	for _, s := range sites {
		k := key{s.file, s.fn, s.call}
		if _, dup := want[k]; dup {
			problems = append(problems, fmt.Sprintf("startSites lists %s %s %s twice", s.file, s.fn, s.call))
			continue
		}
		if s.n < 1 {
			problems = append(problems, fmt.Sprintf("startSites row %s %s %s counts %d calls: a row names at least one", s.file, s.fn, s.call, s.n))
		}
		switch s.rel {
		case beforeArm, afterDetach, guarded:
		default:
			problems = append(problems, fmt.Sprintf("startSites row %s %s %s has the relation %q, which is none of before-arm, after-detach and guarded", s.file, s.fn, s.call, s.rel))
		}
		if strings.TrimSpace(s.when) == "" {
			problems = append(problems, fmt.Sprintf("startSites row %s %s %s says nothing of when it runs against Arm", s.file, s.fn, s.call))
		}
		want[k] = s
	}
	for k, rs := range have {
		s, ok := want[k]
		switch {
		case !ok && lintCall(k.call):
			problems = append(problems, fmt.Sprintf("%s:%d: %s uses %s, a process start no row of startSites names: "+
				"add a row saying when it runs against Arm and an exclusion for the file in .golangci.yml (ADR 0021 (6))",
				k.file, rs[0].line, k.fn, k.call))
		case !ok:
			problems = append(problems, fmt.Sprintf("%s:%d: %s uses %s, a function that starts a process and that no row of "+
				"startSites names: add a row saying when it runs against Arm (ADR 0021 (6)); lint cannot name it, so the "+
				"file needs no exclusion for it", k.file, rs[0].line, k.fn, k.call))
		case s.n != len(rs):
			problems = append(problems, fmt.Sprintf("%s: %s uses %s %d times, its row says %d: the row is exact, "+
				"so read each start's arming and change n", k.file, k.fn, k.call, len(rs), s.n))
		}
	}
	for k := range want {
		if _, ok := have[k]; !ok {
			problems = append(problems, fmt.Sprintf("startSites lists %s %s %s, which the tree no longer has: "+
				"remove the row, and the file's exclusion in .golangci.yml when no other row of the file calls a start lint names",
				k.file, k.fn, k.call))
		}
	}
	slices.Sort(problems)
	return problems
}

// TestEveryProcessStartSiteIsListed is ADR 0021 (6) made mechanical, and the second guard beside lint. Under (3) no
// process starts while this process holds fanotify marks, so every start in non-test code goes through proc.Start,
// directly or through cgroup.StartHelper and StartHelperExec, the one wrapper over it; and (6) conditions E70, which
// starts privileged commands, on a helper forked before the marks. Nothing but review stopped a start from a
// supervisor's ask handler, the shape E70 would take, and at run time that fails closed only with ErrArmed, once a
// run has met the refusal. The lint rule in .golangci.yml now refuses a start from a file it does not name; this
// test refuses one that startSites does not name, by function and by count, so a second start in a file the lint
// allows is a change someone reads too. It reads every Go file of the module whatever its build tags, which the
// lint, run under integration and tegobpf and under none, does not: a file built only under tegotesthooks was
// never linted. And it holds no list but this file's own, so the lint config can be edited, or its rule dropped,
// without a site going unreviewed.
//
// It follows a start one function out, which lint cannot: a function that makes a start and that no other package
// can name (startHelperIn, startHelperProcess, startOnKeptThread, the reaper's, the detacher's and doctor's) is a
// start function in its own package's directory (followedStartFuncs), so a call of it from a file of that package,
// one no rule names and no exclusion covers, is a row too.
//
// Verified: a throwaway file in internal/runtime/supervisor that took proc.Start as a function value through an
// aliased import, and called cgroup.StartHelperExec, made this test fail naming each, and golangci-lint refuse each
// with the rule's message; a clone constant added to reap.go, a file the rule excludes, was still refused by the
// other forbidigo rule. And new files that called startHelperIn in internal/runtime/cgroup, startHelperProcess in
// internal/runtime/enforce/cgroup and startOnKeptThread in internal/runtime/launch passed this test and
// golangci-lint (0 issues) until those functions were followed, and fail this test after, naming each. All
// these edits were reverted.
func TestEveryProcessStartSiteIsListed(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil || !strings.Contains(string(mod), "module "+modulePath+"\n") {
		t.Fatalf("%s is not this module's go.mod (%v): the tree scan would read another project", moduleRoot, err)
	}
	for _, p := range startFuncProblems(startSites) {
		t.Error(p)
	}
	refs, err := scanStartRefs(moduleRoot, followedStartFuncs(startSites))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) == 0 {
		t.Fatal("the scan found no process start in the whole tree: it reads nothing, which is not a pass")
	}
	for _, p := range startSiteProblems(refs, startSites) {
		t.Error(p)
	}
}

// writeTree writes files, a map from a path below dir to its content, creating the directories.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStartSiteScanSeesEveryWayToNameAStart holds the scan itself to what it is for, on a tree of its own: a
// scan that stopped seeing a spelling would pass the real tree with that spelling in it. Each spelling that
// names a start is found, whatever the import is called, a call or a function value, in a method, a closure or
// a package variable; so is a bare call of startHelperIn, startHelperProcess and startOnKeptThread, the unexported
// functions the rows make start functions, in a file of their own package's directory that is no row, while the
// declaration of such a function is not a reference. And what is not a start is not: another package that is
// called proc, a method named StartHelper, proc.Command and the rest of the package, the test files and exempt
// directories, hidden and ignored ones and nested modules, and those same names where they are not the start
// function's own: a function of that name in another package, another start function's name in this directory,
// and the name one directory below its home.
func TestStartSiteScanSeesEveryWayToNameAStart(t *testing.T) {
	const (
		procImp = `"github.com/attention-span-ai/tego/internal/platform/proc"`
		cgImp   = `"github.com/attention-span-ai/tego/internal/runtime/cgroup"`
	)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		// The ways to name a start.
		"plain/plain.go": "package plain\nimport " + procImp + "\nfunc Plain(c *proc.Cmd) { _, _ = proc.Start(c) }\n",
		"alias/alias.go": "package alias\nimport p " + procImp + "\nvar starter = p.Start\n",
		"closure/c.go":   "package closure\nimport " + procImp + "\nfunc Go(c *proc.Cmd) { go func() { _, _ = proc.Start(c) }() }\n",
		"lit/l.go":       "package lit\nimport " + procImp + "\nfunc E(c *proc.Cmd) any { return struct{ f func(*proc.Cmd) (proc.Identity, error) }{proc.Start} }\n",
		"method/m.go": "package method\nimport rc " + cgImp + "\ntype T struct{}\n" +
			"func (t *T) Run() { _, _ = rc.StartHelperExec(\"/bin/true\") }\n" +
			"func (t T) Both() { _, _ = rc.StartHelper(nil); _, _ = rc.StartHelperExec(\"x\") }\n" +
			"type G[V any] struct{}\nfunc (g *G[V]) Gen() { _, _ = rc.StartHelperExec(\"y\") }\n",
		"internal/runtime/cgroup/own.go": "package cgroup\ntype X struct{}\nfunc (X) StartHelper() {}\n" +
			"func own(x X) { _, _ = StartHelperExec(\"x\"); x.StartHelper() }\n",
		// An unexported function that a row makes a start function is named bare in its own package's directory, in a
		// file of its own as well, and its declaration is no reference: a new caller of startHelperIn,
		// startHelperProcess or startOnKeptThread is a site, though no lint rule could name it.
		"internal/runtime/cgroup/zz_broker.go":      "package cgroup\nfunc broker() { _, _ = startHelperIn(Mount, true, nil, 0, nil) }\n",
		"internal/runtime/cgroup/decl.go":           "package cgroup\nfunc startHelperIn(m string) (string, error) { return m, nil }\n",
		"internal/runtime/enforce/cgroup/zz_arm.go": "package cgroup\nfunc armPath() error { return startHelperProcess(\"/bin/true\") }\n",
		"internal/runtime/enforce/cgroup/decl.go":   "package cgroup\nvar startHelperProcess = func(exe string, args ...string) error { return nil }\n",
		"internal/runtime/launch/zz_start.go":       "package launch\nfunc zzStart(c *proc.Cmd) { _, _ = startOnKeptThread(c) }\n",
		// Not a start.
		"other/o.go":   "package other\nimport proc \"example.com/other/proc\"\nfunc O() { proc.Start() }\n",
		"nonref/n.go":  "package nonref\nimport " + procImp + "\nfunc N() { _ = proc.Command; _ = proc.Arm; _ = proc.ErrArmed }\n",
		"blank/b.go":   "package blank\nimport _ " + procImp + "\n",
		"cgonly/c.go":  "package cgonly\nimport " + cgImp + "\nfunc C() { _ = cgroup.HelperScope }\n",
		"shadow/s.go":  "package shadow\nfunc S(proc struct{ Start func() }) { proc.Start() }\n",
		"method2/m.go": "package method2\nimport " + cgImp + "\ntype V struct{ StartHelper func() }\nfunc (v V) M() { v.StartHelper() }\n",
		// The same names in the wrong place: a function of that name in another package, one start function's name
		// in the directory of another's, and in a directory below its home.
		"other/h.go":                              "package other\nfunc startHelperIn() {}\nfunc o() { startHelperIn(); startHelperProcess(nil); startOnKeptThread(nil) }\n",
		"internal/runtime/cgroup/swap.go":         "package cgroup\nfunc swap() { _ = startHelperProcess(\"x\"); _, _ = startOnKeptThread(nil) }\n",
		"internal/runtime/enforce/cgroup/swap.go": "package cgroup\nfunc swap() { _, _ = startHelperIn(\"x\", true, nil, 0, nil) }\n",
		"internal/runtime/launch/sub/s.go":        "package sub\nfunc s() { _, _ = startOnKeptThread(nil) }\n",
		// Files and directories the scan does not read.
		"plain/plain_test.go":                    "package plain\nimport " + procImp + "\nfunc TestX() { proc.Start(nil) }\n",
		"internal/testutil/h.go":                 "package testutil\nimport " + procImp + "\nfunc H() { proc.Start(nil) }\n",
		"tools/t/t.go":                           "package main\nimport " + procImp + "\nfunc main() { proc.Start(nil) }\n",
		"test/e2e/e.go":                          "package e2e\nimport " + procImp + "\nfunc E() { proc.Start(nil) }\n",
		"internal/platform/proc/own.go":          "package proc\nfunc own() { Start(nil) }\n",
		".hidden/h.go":                           "package hidden\nimport " + procImp + "\nfunc H() { proc.Start(nil) }\n",
		"_skipped/s.go":                          "package skipped\nimport " + procImp + "\nfunc S() { proc.Start(nil) }\n",
		"plain/testdata/t.go":                    "package testdata\nimport " + procImp + "\nfunc T() { proc.Start(nil) }\n",
		"vendor/v/v.go":                          "package v\nimport " + procImp + "\nfunc V() { proc.Start(nil) }\n",
		"othermodule/go.mod":                     "module example.com/other\n",
		"othermodule/o.go":                       "package o\nimport " + procImp + "\nfunc O() { proc.Start(nil) }\n",
		"docs/notes.md":                          "proc.Start(nil)\n",
		"plain/not_go.txt":                       "package x\nimport " + procImp + "\nfunc X() { proc.Start(nil) }\n",
		"internal/runtime/cgroup/own_test.go":    "package cgroup\nfunc TestOwn() { StartHelper(nil) }\n",
		"internal/runtime/cgroup/sub/sub.go":     "package sub\nfunc S() { StartHelper(nil) }\n",
		"internal/runtime/cgroup/sub/ok_test.go": "package sub\n",
	})
	refs, err := scanStartRefs(dir, followedStartFuncs(startSites))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range refs {
		got = append(got, fmt.Sprintf("%s %s %s", r.file, r.fn, r.call))
	}
	slices.Sort(got)
	want := []string{
		"alias/alias.go starter proc.Start",
		"closure/c.go Go proc.Start",
		"internal/runtime/cgroup/own.go own cgroup.StartHelperExec",
		"internal/runtime/cgroup/zz_broker.go broker cgroup.startHelperIn",
		"internal/runtime/enforce/cgroup/zz_arm.go armPath cgroup.startHelperProcess",
		"internal/runtime/launch/zz_start.go zzStart launch.startOnKeptThread",
		"lit/l.go E proc.Start",
		"method/m.go G.Gen cgroup.StartHelperExec",
		"method/m.go T.Both cgroup.StartHelper",
		"method/m.go T.Both cgroup.StartHelperExec",
		"method/m.go T.Run cgroup.StartHelperExec",
		"plain/plain.go Plain proc.Start",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the scan found\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	// A dot import is refused, not read.
	dot := t.TempDir()
	writeTree(t, dot, map[string]string{"d/d.go": "package d\nimport . " + procImp + "\nfunc D(c *Cmd) { _, _ = Start(c) }\n"})
	if _, err := scanStartRefs(dot, followedStartFuncs(startSites)); err == nil || !strings.Contains(err.Error(), "dot-imports") {
		t.Errorf("a dot import of proc was read as %v, want it refused", err)
	}

	// An unreadable file is an error: a scan that skipped a file it could not parse would call the tree clean.
	bad := t.TempDir()
	writeTree(t, bad, map[string]string{"b/b.go": "package b\nimport " + procImp + "\nfunc B( {\n"})
	if _, err := scanStartRefs(bad, followedStartFuncs(startSites)); err == nil {
		t.Error("a Go file that does not parse was passed over")
	}
}

// TestFollowedStartFuncsComeFromTheRows holds followedStartFuncs and startFuncProblems to what they are for, on rows
// of their own. A row whose call is a start lint names makes its function a start function in its own directory: an
// unexported function or package variable by its bare name, an unexported method as the name of a selector on any
// value, and the scan then finds each reference to it there and nowhere else; the starts lint names stay what they
// were, and startFuncs is not altered. A row that cannot be followed is a problem (an exported function that
// startFuncs does not list, an exported method, a declaration with no name), and so is a row that is guarded when
// its function is not followed, or not guarded when it is.
func TestFollowedStartFuncsComeFromTheRows(t *testing.T) {
	row := func(file, fn, call string, rel armRelation) startSite {
		return startSite{file: file, fn: fn, call: call, n: 1, rel: rel, when: "before the stage"}
	}
	rows := []startSite{
		row("a/b/w.go", "wrap", "proc.Start", guarded),
		row("a/b/w.go", "bind", "proc.Start", guarded),
		row("a/b/m.go", "T.begin", "cgroup.StartHelper", guarded),
		row("a/c/x.go", "run", "cgroup.StartHelperExec", guarded),
		row("a/b/use.go", "caller", "b.wrap", beforeArm),
		row("internal/runtime/cgroup/helper.go", "StartHelperExec", "cgroup.StartHelper", guarded),
	}
	before := fmt.Sprintf("%+v", startFuncs)
	type follows struct{ funcs, methods []string }
	got := map[string]follows{}
	for _, sf := range followedStartFuncs(rows) {
		got[sf.home] = follows{sf.funcs, sf.methods}
	}
	for home, want := range map[string]follows{
		"a/b":                     {[]string{"wrap", "bind"}, []string{"begin"}},
		"a/c":                     {[]string{"run"}, nil},
		"internal/runtime/cgroup": {[]string{"StartHelper", "StartHelperExec"}, nil},
		"internal/handoff":        {[]string{"Spawn"}, nil},
		"":                        {[]string{"Start"}, nil},
	} {
		if g := got[home]; !slices.Equal(g.funcs, want.funcs) || !slices.Equal(g.methods, want.methods) {
			t.Errorf("followed in %q: functions %q, methods %q, want %q and %q", home, g.funcs, g.methods, want.funcs, want.methods)
		}
	}
	if len(got) != 5 {
		t.Errorf("followed in %d directories, want the two the rows add and the three startFuncs holds: %v", len(got), got)
	}
	if after := fmt.Sprintf("%+v", startFuncs); after != before {
		t.Errorf("followedStartFuncs changed startFuncs: %s, was %s", after, before)
	}

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"a/b/use.go":   "package b\nfunc caller(t T) { wrap(); t.begin(); _ = bind; _ = t.in.begin }\n",
		"a/b/decl.go":  "package b\nfunc wrap() {}\nvar bind = func() {}\nfunc (T) begin() {}\n",
		"a/c/use.go":   "package c\nfunc other(t T) { run(); wrap(); t.begin(); t.start() }\n",
		"a/d/use.go":   "package d\nfunc other(t T) { wrap(); run(); t.begin() }\n",
		"a/b/sub/s.go": "package sub\nfunc s(t T) { wrap(); t.begin() }\n",
	})
	refs, err := scanStartRefs(dir, followedStartFuncs(rows))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, r := range refs {
		found = append(found, fmt.Sprintf("%s %s %s", r.file, r.fn, r.call))
	}
	slices.Sort(found)
	want := []string{
		"a/b/use.go caller b.begin",
		"a/b/use.go caller b.begin",
		"a/b/use.go caller b.bind",
		"a/b/use.go caller b.wrap",
		"a/c/use.go other c.run",
	}
	if !slices.Equal(found, want) {
		t.Errorf("the scan found\n  %s\nwant\n  %s", strings.Join(found, "\n  "), strings.Join(want, "\n  "))
	}

	for _, tc := range []struct {
		name string
		rows []startSite
		want string // a substring of the one problem; none for rows that are consistent
	}{
		{"consistent", rows, ""},
		{"an exported function startFuncs does not list", []startSite{row("a/b/e.go", "Spawn", "proc.Start", guarded)},
			"a/b/e.go Spawn proc.Start is an exported function that starts a process, which other packages can call: list it in startFuncs"},
		{"an exported method", []startSite{row("a/b/e.go", "T.Spawn", "proc.Start", beforeArm)},
			"a/b/e.go T.Spawn proc.Start is an exported method that starts a process"},
		{"a declaration with no name", []startSite{row("a/b/v.go", "<var>", "proc.Start", beforeArm)},
			"a/b/v.go <var> proc.Start starts a process from a declaration with no name"},
		{"followed and not guarded", []startSite{row("a/b/w.go", "wrap", "proc.Start", beforeArm)},
			`a/b/w.go wrap proc.Start is a function the scan follows, whose callers' rows say when they call it, so its relation is guarded, not "before-arm"`},
		{"a method followed and not guarded", []startSite{row("a/b/m.go", "T.begin", "proc.Start", afterDetach)},
			"a/b/m.go T.begin proc.Start is a function the scan follows"},
		{"guarded and not followed", []startSite{row("a/b/c.go", "decide", "b.wrap", guarded)},
			"a/b/c.go decide b.wrap is guarded, but no row makes decide a function the scan follows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := startFuncProblems(tc.rows)
			switch {
			case tc.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Errorf("problems %q, want the one that says %q", got, tc.want)
			}
		})
	}
}

// TestStartSiteProblemsNameWhatIsWrong: the comparison reports an unlisted site with where it is and what to do,
// a changed count, a row whose site is gone, and a malformed or repeated row, and nothing for a list that is exact.
func TestStartSiteProblemsNameWhatIsWrong(t *testing.T) {
	ref := func(file string, line int, fn, call string) startRef {
		return startRef{file: file, line: line, fn: fn, call: call}
	}
	row := func(file, fn, call string, n int) startSite {
		return startSite{file: file, fn: fn, call: call, n: n, rel: beforeArm, when: "before the stage"}
	}
	refs := []startRef{ref("a/a.go", 10, "F", "proc.Start"), ref("a/a.go", 20, "F", "proc.Start"), ref("b/b.go", 5, "G", "cgroup.StartHelper")}
	for _, tc := range []struct {
		name  string
		refs  []startRef
		sites []startSite
		want  []string // each a substring of exactly one problem, in order; none for an exact list
	}{
		{"exact", refs, []startSite{row("a/a.go", "F", "proc.Start", 2), row("b/b.go", "G", "cgroup.StartHelper", 1)}, nil},
		{"unlisted", refs, []startSite{row("a/a.go", "F", "proc.Start", 2)},
			[]string{"b/b.go:5: G uses cgroup.StartHelper, a process start no row of startSites names"}},
		{"another function of a listed file", refs, []startSite{row("a/a.go", "H", "proc.Start", 2), row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{"a/a.go:10: F uses proc.Start, a process start no row", "startSites lists a/a.go H proc.Start, which the tree no longer has"}},
		{"a second start in a listed function", refs, []startSite{row("a/a.go", "F", "proc.Start", 1), row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{"a/a.go: F uses proc.Start 2 times, its row says 1"}},
		{"another start function", refs, []startSite{row("a/a.go", "F", "cgroup.StartHelperExec", 2), row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{"a/a.go:10: F uses proc.Start, a process start no row", "startSites lists a/a.go F cgroup.StartHelperExec, which the tree no longer has"}},
		{"unlisted, a function lint cannot name", append(slices.Clone(refs), ref("c/c.go", 7, "H", "c.wrap")),
			[]startSite{row("a/a.go", "F", "proc.Start", 2), row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{"c/c.go:7: H uses c.wrap, a function that starts a process and that no row of startSites names: add a row " +
				"saying when it runs against Arm (ADR 0021 (6)); lint cannot name it, so the file needs no exclusion for it"}},
		{"gone", refs[:2], []startSite{row("a/a.go", "F", "proc.Start", 2), row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{"startSites lists b/b.go G cgroup.StartHelper, which the tree no longer has"}},
		{"twice", refs, []startSite{row("a/a.go", "F", "proc.Start", 2), row("a/a.go", "F", "proc.Start", 2), row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{"startSites lists a/a.go F proc.Start twice"}},
		{"no count", refs, []startSite{row("a/a.go", "F", "proc.Start", 2), row("b/b.go", "G", "cgroup.StartHelper", 0)},
			[]string{"b/b.go: G uses cgroup.StartHelper 1 times, its row says 0", "b/b.go G cgroup.StartHelper counts 0 calls"}},
		{"no relation", refs, []startSite{
			{file: "a/a.go", fn: "F", call: "proc.Start", n: 2, when: "x"}, row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{`a/a.go F proc.Start has the relation ""`}},
		{"no sentence", refs, []startSite{
			{file: "a/a.go", fn: "F", call: "proc.Start", n: 2, rel: guarded, when: " "}, row("b/b.go", "G", "cgroup.StartHelper", 1)},
			[]string{"a/a.go F proc.Start says nothing of when it runs against Arm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := startSiteProblems(tc.refs, tc.sites)
			if len(got) != len(tc.want) {
				t.Fatalf("problems %q, want one for each of %q", got, tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d is %q, want it to say %q", i, got[i], w)
				}
			}
		})
	}
}

// lintConfig is the part of .golangci.yml the sites are written into.
type lintConfig struct {
	Linters struct {
		Settings struct {
			Forbidigo struct {
				Forbid []struct {
					Pattern string `yaml:"pattern"`
					Pkg     string `yaml:"pkg"`
					Msg     string `yaml:"msg"`
				} `yaml:"forbid"`
			} `yaml:"forbidigo"`
		} `yaml:"settings"`
		Exclusions struct {
			Paths []string `yaml:"paths"`
			Rules []struct {
				Path       string   `yaml:"path"`
				PathExcept string   `yaml:"path-except"`
				Linters    []string `yaml:"linters"`
				Text       string   `yaml:"text"`
				Source     string   `yaml:"source"`
			} `yaml:"rules"`
		} `yaml:"exclusions"`
	} `yaml:"linters"`
}

// exclusionFileInTree reports whether a start-site exclusion's path, ^<quoted file>$, names a file of this tree.
func exclusionFileInTree(path string) bool {
	file := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(path, "^"), "$"), `\.`, ".")
	_, err := os.Stat(filepath.Join(moduleRoot, filepath.FromSlash(file)))
	return err == nil
}

// TestLintExclusionsAreTheStartSites ties the two guards together: .golangci.yml carries a forbidigo rule for
// every start function lint can name, and one exclusion per file of startSites with a row whose call is one of
// them, each of them for the rule's message alone, so the file stays under every other forbidigo rule, and none for
// a file the list does not hold that way. A file whose starts are all through a function lint cannot name, such as
// enforce/cgroup's rings.go, which calls startHelperProcess, needs no exclusion and gets none. The list can then
// not drift from the lint: a site added to one and not the other, or one removed from the code and left in the
// config, where the exclusion would let the next start in that file through unreviewed, fails here. So does any
// other exclusion that includes forbidigo (one that lists it beside another linter, lists no linter at all, or
// excludes a path from every linter), since it would lift the rule where it applies; the one kind allowed is an
// exclusion for forbidigo alone whose text matches no ADR 0021 rule's message (ADR 0023's descriptor rules, whose
// shrinking list exempts each unmigrated package from them alone), and the blanket exemption is itself scoped to
// "ADR 0021", which must match every ADR 0021 message.
//
// Verified 2026-10-17 (ADR 0023 C3): the exemption without its text, an ADR 0023 exclusion whose text was "ADR 0021"
// or "ADR 00", and the exemption's text narrowed to "ADR 0021 \(3\)" each failed this test; each edit was reverted.
//
// Verified: an exclusion removed from .golangci.yml, one added for a file the list does not hold, the proc.Start
// pattern broken, and the blanket exemption widened to internal/runtime each made this test fail with the
// difference named; so did an exclusion added for rings.go, one for internal/runtime/launch/sub that listed
// forbidigo beside errcheck, one with no linters, one for forbidigo with another message, and a path under
// linters.exclusions.paths. Each edit was reverted.
func TestLintExclusionsAreTheStartSites(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot, ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg lintConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf(".golangci.yml: %v", err)
	}

	for _, sf := range startFuncs {
		for _, name := range sf.funcs {
			var covered bool
			for _, f := range cfg.Linters.Settings.Forbidigo.Forbid {
				if !strings.Contains(f.Msg, siteRuleText) {
					continue
				}
				pat, err := regexp.Compile(f.Pattern)
				if err != nil {
					t.Fatalf("forbidigo pattern %q: %v", f.Pattern, err)
				}
				pkg, err := regexp.Compile(f.Pkg)
				if err != nil {
					t.Fatalf("forbidigo pkg %q: %v", f.Pkg, err)
				}
				if f.Pkg != "" && pat.MatchString(sf.name+"."+name) && pkg.MatchString(sf.pkg) {
					covered = true
				}
			}
			if !covered {
				t.Errorf(".golangci.yml has no forbidigo rule with %q in its message for %s.%s of %s: "+
					"a start through it needs no reviewed site", siteRuleText, sf.name, name, sf.pkg)
			}
		}
	}

	wantFiles := map[string]bool{}
	for _, s := range startSites {
		if lintCall(s.call) {
			wantFiles["^"+regexp.QuoteMeta(s.file)+"$"] = true
		}
	}
	if len(cfg.Linters.Exclusions.Paths) != 0 {
		t.Errorf(".golangci.yml excludes %q from every linter, the start-site rule too: a path leaves forbidigo through "+
			"an exclusion rule of its own, which this test reads", cfg.Linters.Exclusions.Paths)
	}
	// ADR 0021's messages: the exemption's text must match each of them, and an exclusion scoped to another
	// ADR's text (ADR 0023's descriptor rules, one per unmigrated package) must match none, so it lifts no
	// ADR 0021 rule where it applies.
	var adr0021 []string
	for _, f := range cfg.Linters.Settings.Forbidigo.Forbid {
		if strings.Contains(f.Msg, "ADR 0021") {
			adr0021 = append(adr0021, f.Msg)
		}
	}
	matches := func(text string) (all, any bool) {
		re, err := regexp.Compile(text)
		if err != nil {
			t.Fatalf(".golangci.yml exclusion text %q: %v", text, err)
		}
		all = len(adr0021) > 0
		for _, m := range adr0021 {
			hit := re.MatchString(m)
			all, any = all && hit, any || hit
		}
		return all, any
	}
	var exempt int
	for _, r := range cfg.Linters.Exclusions.Rules {
		if len(r.Linters) != 0 && !slices.Contains(r.Linters, "forbidigo") {
			continue // another linter's
		}
		forbidigoOnly := len(r.Linters) == 1 && r.PathExcept == "" && r.Source == ""
		_, liftsADR0021 := matches(r.Text)
		switch {
		case forbidigoOnly && r.Text == lintExemptText && r.Path == lintExemptPath:
			if all, _ := matches(r.Text); !all {
				t.Errorf(".golangci.yml's exemption text %q misses an ADR 0021 rule's message: the scan skips %s for every rule",
					r.Text, lintExemptPath)
			}
			exempt++
		case len(r.Linters) == 1 && r.Source == "" && r.Text != "" && r.Text != siteRuleText && !liftsADR0021:
			// another ADR's rules alone (ADR 0023's, and the dashboard's template and edge rules, one of which
			// names the paths it leaves out with path-except): every ADR 0021 rule still applies to every path.
		case forbidigoOnly && r.Text == siteRuleText && wantFiles[r.Path]:
			delete(wantFiles, r.Path)
		case forbidigoOnly && r.Text == siteRuleText && !exclusionFileInTree(r.Path):
			// A layer this tree does not carry: the exclusion names no file, so it lifts nothing, and a file made at
			// that path with a start in it fails TestEveryProcessStartSiteIsListed for want of a row.
		case forbidigoOnly && r.Text == siteRuleText:
			t.Errorf(".golangci.yml excludes %s from the start-site rule, which startSites does not ask for: an exclusion is for a "+
				"file with a row whose call lint names (proc.Start, cgroup.StartHelper, cgroup.StartHelperExec), once", r.Path)
		default:
			t.Errorf(".golangci.yml has an exclusion that includes forbidigo and is neither the blanket exemption nor a start site's "+
				"(path %q, path-except %q, linters %v, text %q, source %q): it would lift the rule where it applies",
				r.Path, r.PathExcept, r.Linters, r.Text, r.Source)
		}
	}
	for p := range wantFiles {
		t.Errorf("startSites has a row for a start lint names in the file at %s, and .golangci.yml has no start-site exclusion for it", p)
	}
	if exempt != 1 {
		t.Errorf(".golangci.yml has %d forbidigo exclusions with the path %s, want one: this scan skips the same files, "+
			"so an exemption that differs is a start nobody reads", exempt, lintExemptPath)
	}
}
