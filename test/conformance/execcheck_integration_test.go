// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ADR 0032's detector and its never-set regression test (ADR 0017 space 2; tcb-eng C12). Tego does not set
// SECBIT_EXEC_RESTRICT_FILE: an interpreter that honours it would turn SEMANTICS §4's "sh tool.sh needs only
// READ_FILE" into "needs EXECUTE", a semantic change with no kernel guarantee behind it. The condition to revisit
// that, a mainstream interpreter on a matrix row checking scripts with AT_EXECVE_CHECK, is detected here on every row
// the suite runs on rather than remembered.

// executeCheckKernel is the first kernel with AT_EXECVE_CHECK and the securebits that ask for it (6.14).
var executeCheckKernel = [2]int{6, 14}

// adr0032Interpreters are the mainstream interpreters ADR 0032 names, by the program name a row installs them under.
var adr0032Interpreters = []string{"bash", "dash", "python3", "node"}

// checkInterpPath is the actor copy that is an interpreter honouring the bit (cmd/actor's check-interp), the
// detector's self-test, relative to the project.
const checkInterpPath = "bin/check-interp"

// execCheckAxis is one tier the execcheck tests run the actor under.
type execCheckAxis struct {
	tier Tier
	pin  string
}

// execCheckSetup builds what the execcheck tests need: the actor, a tego build and the axes this machine runs:
// tier landlock always (without root, as the caller), tier cgroup on the fanotify listener where root and doctor
// offer it. An axis the environment requires (RequireEnv, which root-suites.sh sets per boot) and the setup cannot
// offer fails the test, as it fails TestConformanceKernel, rather than leave the test green on fewer axes.
func execCheckSetup(t *testing.T) (actor, bin string, uid, gid int, axes []execCheckAxis) {
	t.Helper()
	uid, gid = -1, -1
	root := os.Geteuid() == 0
	required := os.Getenv(RequireEnv)
	if root {
		var ok bool
		if uid, gid, ok = sudoIDs(); !ok {
			t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
		}
	} else if AxisRequired(required, string(TierCgroup)) {
		t.Fatalf("%s names cgroup, which needs root (tier cgroup loads BPF programs); this test runs as uid %d", RequireEnv, os.Geteuid())
	}
	actor = buildActor(t)
	dir := t.TempDir()
	var err error
	haveBPF := false
	if root {
		if os.Getenv(execCheckNoBPFEnv) != "" {
			err = fmt.Errorf("withheld by %s", execCheckNoBPFEnv)
		} else {
			bin, err = buildTego(dir, "tegobpf")
		}
		haveBPF = err == nil
		if !haveBPF && AxisRequired(required, string(TierCgroup)) {
			t.Fatalf("%s names cgroup but the tegobpf build failed: %v", RequireEnv, err)
		}
		if !haveBPF {
			t.Logf("no tegobpf build (%v): tier cgroup is not run", err)
		}
	}
	if !haveBPF {
		if bin, err = buildTego(dir); err != nil {
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
	axes = []execCheckAxis{{tier: TierLandlock}}
	if haveBPF {
		if out, err := doctor(bin, doctorEnv, "--require", "cgroup").CombinedOutput(); err == nil {
			axes = append(axes, execCheckAxis{tier: TierCgroup, pin: string(ModeFanotify)})
		} else if AxisRequired(required, string(TierCgroup)) {
			t.Fatalf("%s names cgroup but tego doctor --require cgroup failed: %v\n%s", RequireEnv, err, out)
		} else {
			t.Logf("no tier cgroup here (tego doctor --require cgroup: %v):\n%s", err, out)
		}
	}
	return actor, bin, uid, gid, axes
}

// actorResult is one line the actor printed.
type actorResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Errno int    `json:"errno"`
	Err   string `json:"err"`
	Value string `json:"value"`
}

// runActor runs fx's cells in one `tego run` at the axis and returns the actor's results by cell ID.
func runActor(t *testing.T, bin, actor string, uid, gid int, fx *Fixture, ax execCheckAxis) map[string]actorResult {
	t.Helper()
	dir, err := os.MkdirTemp("", "eyconf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := materialize(t, dir, fx, actor)
	environ := machineConfig(t, e)
	if uid >= 0 {
		if err := filepath.Walk(e.project, func(p string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, uid, gid)
		}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--tier", string(ax.tier), "agent.yaml")
	cmd.Dir, cmd.Env = e.project, environ
	if ax.pin != "" {
		cmd.Env = append(cmd.Env, "TEGO_TEST_PLANE="+ax.pin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 15 * time.Second
	runErr := cmd.Run()
	out := map[string]actorResult{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		var r actorResult
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.ID != "" {
			out[r.ID] = r
		}
	}
	if len(out) != len(fx.Cells) {
		t.Fatalf("tego run --tier %s: %v, %d of %d actions reported\nstdout:\n%s\nstderr:\n%s", ax.tier, runErr, len(out), len(fx.Cells),
			stdout.String(), stderr.String())
	}
	return out
}

// interpreterVersion names an interpreter's release for the detector's message.
func interpreterVersion(path string) string {
	name := filepath.Base(path)
	if name == "dash" { // dash has no version option; the path is what a row installs
		return path
	}
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return path
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return name + " " + first
}

// TestExecveCheckDetector is ADR 0032's detector. In one governed run at each tier the machine offers, the actor asks
// with execveat(AT_EXECVE_CHECK) whether a script outside exec.allow would exec (the run half), and runs it with each
// interpreter present twice: with SECBIT_EXEC_RESTRICT_FILE set on itself and, as the control, without it (the
// interpreter half). Both scripts are mode 0755, so the file mode answers neither. The run half must be refused,
// EACCES, on every kernel: the supervisor's exec arm refuses the unlisted image's execveat before the kernel's check
// runs (Landlock's EXECUTE floor stands behind it), which is what an interpreter that checks its script would meet.
// The kernel half asks the same of a script exec.allow lists, which the supervisor lets through to the kernel: from
// 6.14 the kernel's check must pass it without an exec, and below 6.14 the kernel must refuse the unknown flag
// (EINVAL), so a kernel whose AT_EXECVE_CHECK is missing or broken is seen. An interpreter that refuses the script
// with the bit and runs it without is checking scripts: the test then fails with "ADR 0032 revisit condition met",
// which is the ADR's condition to make the bit an opt-in contract field. Below 6.14 the interpreter half is logged as
// an explicit n/a, a pass the skip gate sees as one, never a skip.
func TestExecveCheckDetector(t *testing.T) {
	machine, err := CurrentMachine()
	if err != nil {
		t.Fatal(err)
	}
	actor, bin, uid, gid, axes := execCheckSetup(t)
	has := cmpKernel(machine.Kernel, executeCheckKernel) >= 0
	var interps []string
	present := map[string]bool{}
	for _, name := range adr0032Interpreters {
		for _, dir := range []string{"/usr/bin", "/bin"} {
			if p := filepath.Join(dir, name); executable(p) {
				interps, present[name] = append(interps, p), true
				break
			}
		}
	}
	allow := []string{q("{{P}}/bin/actor"), q("{{P}}/" + checkInterpPath), q("{{P}}/check/listed.sh")}
	for _, p := range interps {
		allow = append(allow, q(p))
	}
	fx := Fixture{
		Name: "execcheck",
		Contract: `version: 0
name: conformance
command: ["{{P}}/bin/actor", "run", "{{P}}/script.json"]
exec:
  allow: [` + strings.Join(allow, ", ") + `]
env:
  pass: ["PATH"]
record: full
`,
		Dirs: []string{"check"},
		// 0755, so that neither check is the file mode's EACCES.
		Scripts: map[string]string{"check/empty.sh": "", "check/listed.sh": ""},
		Actors:  []string{checkInterpPath},
		Cells: []Cell{{Name: "run-half", Op: "execve-check", Path: "check/empty.sh"},
			{Name: "kernel-half", Op: "execve-check", Path: "check/listed.sh"}},
	}
	for _, p := range append([]string{checkInterpPath}, interps...) {
		name := filepath.Base(p)
		fx.Cells = append(fx.Cells, Cell{Name: name + "-control", Op: "script-run", Path: p, Dest: "check/empty.sh"},
			Cell{Name: name + "-restricted", Op: "script-check", Path: p, Dest: "check/empty.sh"})
	}
	for _, ax := range axes {
		got := runActor(t, bin, actor, uid, gid, &fx, ax)
		r, k := got[fx.ID(&fx.Cells[0])], got[fx.ID(&fx.Cells[1])]
		if r.OK || r.Errno != int(syscall.EACCES) {
			t.Errorf("tier %s: execveat(AT_EXECVE_CHECK) on a 0755 script outside exec.allow answered ok=%v errno %d (%s), want the run's EACCES",
				ax.tier, r.OK, r.Errno, r.Err)
		} else {
			t.Logf("ADR0032 tier %s: run half refuses the unlisted script (EACCES)", ax.tier)
		}
		switch {
		case has && !k.OK:
			t.Errorf("tier %s, kernel %d.%d: execveat(AT_EXECVE_CHECK) on a 0755 script exec.allow lists answered errno %d (%s), want the kernel's check to pass it",
				ax.tier, machine.Kernel[0], machine.Kernel[1], k.Errno, k.Err)
		case !has && (k.OK || k.Errno != int(syscall.EINVAL)):
			t.Errorf("tier %s, kernel %d.%d: execveat with AT_EXECVE_CHECK on a listed script answered ok=%v errno %d (%s) on a kernel before 6.14, want EINVAL (an unknown flag)",
				ax.tier, machine.Kernel[0], machine.Kernel[1], k.OK, k.Errno, k.Err)
		case !has:
			t.Logf("ADR0032 tier %s: kernel half n/a: kernel %d.%d <6.14 lacks AT_EXECVE_CHECK (EINVAL)", ax.tier, machine.Kernel[0], machine.Kernel[1])
		default:
			t.Logf("ADR0032 tier %s: kernel half: the kernel's check passes a listed script without an exec", ax.tier)
		}
		for _, p := range append([]string{checkInterpPath}, interps...) {
			name := filepath.Base(p)
			ctl, res := got["execcheck/"+name+"-control"], got["execcheck/"+name+"-restricted"]
			honours := ctl.OK && ctl.Value == "runs" && res.OK && strings.HasPrefix(res.Value, "refuses")
			switch {
			case !ctl.OK || ctl.Value != "runs":
				t.Errorf("tier %s: %s does not run the script without the bit (%+v): the detector's fixture is broken", ax.tier, p, ctl)
			case !res.OK:
				t.Errorf("tier %s: %s with SECBIT_EXEC_RESTRICT_FILE did not start: %+v", ax.tier, p, res)
			case !has && res.Value != "bit-refused":
				t.Errorf("tier %s, kernel %d.%d: the stage set SECBIT_EXEC_RESTRICT_FILE (%s %s) on a kernel before 6.14, which has no such bit",
					ax.tier, machine.Kernel[0], machine.Kernel[1], p, res.Value)
			case !has:
				t.Logf("ADR0032 tier %s: %s: n/a: kernel %d.%d <6.14 refuses the bit", ax.tier, p, machine.Kernel[0], machine.Kernel[1])
			case p == checkInterpPath && !honours:
				// The self-test: an interpreter that checks its script must be detected, or the detector is blind.
				t.Errorf("tier %s: the detector's own honouring interpreter %s %s with the bit: the detector cannot see one", ax.tier, p, res.Value)
			case p == checkInterpPath:
				t.Logf("ADR0032 tier %s: self-test: the honouring interpreter is detected (%s)", ax.tier, res.Value)
			case honours:
				t.Errorf("tier %s: ADR 0032 revisit condition met: %s %s with SECBIT_EXEC_RESTRICT_FILE and runs it without (docs/adr/0032)",
					ax.tier, interpreterVersion(p), res.Value)
			case res.Value == "runs":
				t.Logf("ADR0032 tier %s: %s ignores SECBIT_EXEC_RESTRICT_FILE (%s)", ax.tier, p, interpreterVersion(p))
			default:
				t.Errorf("tier %s: %s with the bit: %q", ax.tier, p, res.Value)
			}
		}
	}
	for _, name := range adr0032Interpreters {
		if !present[name] {
			t.Logf("ADR0032: %s absent on this row", name)
		}
	}
}

// TestChildNeverSetsExecRestrictBits holds ADR 0032's decision: the agent tego starts, at each tier the machine
// offers, has securebits 8-11 (SECBIT_EXEC_RESTRICT_FILE, SECBIT_EXEC_DENY_INTERACTIVE and their locks) clear.
func TestChildNeverSetsExecRestrictBits(t *testing.T) {
	actor, bin, uid, gid, axes := execCheckSetup(t)
	fx := Fixture{
		Name: "securebits",
		Contract: `version: 0
name: conformance
command: ["{{P}}/bin/actor", "run", "{{P}}/script.json"]
exec:
  allow: ["{{P}}/bin/actor"]
record: full
`,
		Cells: []Cell{{Name: "agent", Op: "securebits"}},
	}
	for _, ax := range axes {
		r := runActor(t, bin, actor, uid, gid, &fx, ax)["securebits/agent"]
		bits, err := strconv.ParseUint(r.Value, 0, 32)
		if !r.OK || err != nil {
			t.Fatalf("tier %s: PR_GET_SECUREBITS: %+v (%v)", ax.tier, r, err)
		}
		if bits&0xf00 != 0 {
			t.Errorf("tier %s: the agent's securebits are %#x: bits 8-11 are set, which ADR 0032 decides tego never does", ax.tier, bits)
		}
		t.Logf("tier %s: securebits %#x", ax.tier, bits)
	}
}

// executable reports whether path is a regular file some execute bit is set on.
func executable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// execCheckNoBPFEnv withholds the tegobpf build from execCheckSetup, as if it had failed: the seam
// TestExecCheckSetupFailsARequiredAxis drives a missing tier cgroup through under root.
const execCheckNoBPFEnv = "TEGO_CONFORMANCE_TEST_NO_TEGOBPF"

// TestExecCheckSetupFailsARequiredAxis holds execCheckSetup to RequireEnv, as TestConformanceKernel is held: where
// the environment requires tier cgroup (root-suites.sh sets it per boot) and the setup cannot offer it (no root, or
// no tegobpf build), the must-pass execcheck tests fail rather than pass on the tier landlock axis alone.
func TestExecCheckSetupFailsARequiredAxis(t *testing.T) {
	if _, _, ok := sudoIDs(); os.Geteuid() == 0 && !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildNeverSetsExecRestrictBits$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), RequireEnv+"=cgroup", execCheckNoBPFEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("TestChildNeverSetsExecRestrictBits passed with %s=cgroup and no tier cgroup to run:\n%s", RequireEnv, out)
	}
	if !bytes.Contains(out, []byte(RequireEnv+" names cgroup")) {
		t.Fatalf("TestChildNeverSetsExecRestrictBits failed, but not on the missing tier cgroup (%v):\n%s", err, out)
	}
}
