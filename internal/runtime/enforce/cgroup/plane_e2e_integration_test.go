// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// The decision plane in a real `tego run` at tier cgroup (TIER3-PLAN T6; docs/p0/enforce-plane.md R16 to R22):
// a tego built with the objects and the test hooks (TEGO_TEST_PLANE pins the mode doctor selects, as bpf.plane
// in /etc/tego/config.yaml would) runs a contract once per plane mode this machine passes, fmod_ret on every
// kernel the probe admits and lsm where bpf is an active LSM (the guest's lsm=...,bpf boot), and once on the
// fanotify listener for contrast. test/vm/root-suites.sh runs them in the KVM guest on both boots.

// buildPlaneTego builds tego with the objects and the test hooks.
func buildPlaneTego(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "tego")
	cmd := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-trimpath", "-o", out, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the tegobpf,tegotesthooks tego binary: %v: %s", err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// doctorWait bounds planeSelected's `doctor --json`. It is no budget: doctor takes seconds, a minute or two in a loaded
// guest, where its plane probe attaches and closes every plane link of each mode (each close waits for an RCU-tasks
// grace period). It is the point past which a doctor that never answers is described rather than left to the suite's
// own timeout, which says only that the test was still running (2026-10-16, default-lsm boot: 24m50s in this call).
const doctorWait = 5 * time.Minute

// planeSelected is the plane doctor selects for tier cgroup under TEGO_TEST_PLANE=pin: lsm, fmod_ret or fanotify.
func planeSelected(t *testing.T, bin, pin string) string {
	t.Helper()
	return planeDoctor(t, bin, pin).Selected
}

// planeModeAnswer is one mode's line of doctor --json's plane.
type planeModeAnswer struct {
	Mode    string `json:"mode"`
	OK      bool   `json:"ok"`
	Tested  bool   `json:"tested"`
	Faulted bool   `json:"faulted"`
	Detail  string `json:"detail"`
	Fix     string `json:"fix"`
}

// planeDoctorAnswer is doctor --json's plane: what it selected and why, the build and where the answer came from
// (probed, the run-probe cache, or a pinned build's), the kernel's preemption model, and each mode's line.
type planeDoctorAnswer struct {
	Selected    string `json:"selected"`
	SelectedWhy string `json:"selected_why"`
	Build       string `json:"build"`
	BuildWhy    string `json:"build_why"`
	Source      string `json:"source"`
	Env         struct {
		Preempt       string `json:"preempt"`
		PreemptSource string `json:"preempt_source"`
		PreemptWaived bool   `json:"preempt_waived"`
	} `json:"env"`
	Modes []planeModeAnswer `json:"modes"`
}

// mode is mode m's line, false when doctor gave none.
func (a planeDoctorAnswer) mode(m string) (planeModeAnswer, bool) {
	for _, r := range a.Modes {
		if r.Mode == m {
			return r, true
		}
	}
	return planeModeAnswer{}, false
}

// planeDoctor is doctor --json's plane under TEGO_TEST_PLANE=pin. A pinned mode doctor did not select is logged with
// everything doctor said of it: one such answer on GitHub's arm64 runner (2026-11-02) said no more than "doctor
// selects fanotify".
func planeDoctor(t *testing.T, bin, pin string) planeDoctorAnswer {
	t.Helper()
	cmd := isolatedTego(t, bin, "doctor", "--json")
	cmd.Env = append(cmd.Env, "TEGO_TEST_PLANE="+pin, "GOTRACEBACK=all")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("tego doctor --json: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }() // a finding exits non-zero with the report on stdout
	select {
	case <-done:
	case <-time.After(doctorWait):
		// What doctor and its probe children were doing, read before anything is signalled, then doctor's
		// goroutines (SIGQUIT under GOTRACEBACK=all).
		state := stuckLaunch(t, cmd.Process.Pid, filepath.Dir(bin))
		_ = cmd.Process.Signal(syscall.SIGQUIT)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		t.Fatalf("tego doctor --json under TEGO_TEST_PLANE=%s had not answered after %v\n%s\ndoctor stderr:\n%s", pin,
			doctorWait, state, stderr.String())
	}
	out := stdout.Bytes()
	var rep struct {
		Plane *planeDoctorAnswer `json:"plane"`
	}
	if err := json.Unmarshal(out, &rep); err != nil || rep.Plane == nil {
		t.Fatalf("tego doctor --json under TEGO_TEST_PLANE=%s: %v\n%s", pin, err, out)
	}
	a := *rep.Plane
	if m, ok := a.mode(pin); ok && a.Selected != pin {
		t.Logf("doctor under TEGO_TEST_PLANE=%s selects %s (%s; build %q: %s; answer %s; preemption %q from %s, waived %v): "+
			"%s mode ok=%v tested=%v faulted=%v: %s (fix: %s)", pin, a.Selected, a.SelectedWhy, a.Build, a.BuildWhy, a.Source,
			a.Env.Preempt, a.Env.PreemptSource, a.Env.PreemptWaived, m.Mode, m.OK, m.Tested, m.Faulted, m.Detail, m.Fix)
	}
	return a
}

// planeModesHere are the plane modes this machine passes, each selected when pinned. A mode doctor ruled out before
// any load (a precondition: bpf in no active LSM list, Clang LTO, a kernel that preempts kernel code for fmod_ret
// mode, ADR 0024 (16)) is one this machine does not offer, and is logged; a mode doctor loaded and probed and that
// then failed or faulted is this kernel deciding a probe cell wrongly, or a probe that could not finish, and fails
// the test rather than leave it to skip the mode.
func planeModesHere(t *testing.T, bin string) []string {
	t.Helper()
	var modes []string
	for _, m := range []string{"lsm", "fmod_ret"} {
		a := planeDoctor(t, bin, m)
		if a.Selected == m {
			modes = append(modes, m)
			if m == "fmod_ret" && a.Env.PreemptWaived {
				planeWaivedModes.Store(m, true)
				t.Logf("plane mode %s is admitted here only by the test builds' waiver of its preemption precondition "+
					"(preemption %q from %s): a run in it can meet a skipped plane program, whose hook proceeds undecided "+
					"(plane_waiver_integration_test.go)", m, a.Env.Preempt, a.Env.PreemptSource)
			}
			continue
		}
		r, ok := a.mode(m)
		switch {
		case !ok:
			t.Errorf("doctor under TEGO_TEST_PLANE=%s selects %s and gives no line for the mode", m, a.Selected)
		case !r.Tested && !r.Faulted:
			t.Logf("plane mode %s is ruled out here before any load: %s", m, r.Detail)
		case r.Faulted:
			t.Errorf("doctor's probe of plane mode %s could not finish here: %s", m, r.Detail)
		default:
			t.Errorf("plane mode %s failed doctor's probe on this kernel: %s", m, r.Detail)
		}
	}
	if got := planeSelected(t, bin, PlaneFanotify); got != PlaneFanotify {
		t.Fatalf("TEGO_TEST_PLANE=fanotify selects %q, want the listener", got)
	}
	return modes
}

// planeAnswersFirst reports whether the plane answers an action before every other LSM that refuses it, refusers:
// Landlock for a write outside every entry, Landlock and Yama (planeAttachRefusers) for a ptrace attach to a process
// that is not the agent's descendant. A fmod_ret program runs before the whole security_ function, so before every
// LSM; an lsm program runs in the chain's order, which /sys/kernel/security/lsm lists, and the first LSM that refuses
// ends it. The lsm=...,bpf boot appends bpf after landlock; a kernel's own list can put yama before bpf and bpf before
// landlock (Fedora 7.0's lockdown,capability,yama,selinux,bpf,landlock,...).
func planeAnswersFirst(mode string, refusers ...string) bool {
	if mode == "fmod_ret" {
		return true
	}
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	order := strings.Split(strings.TrimSpace(string(b)), ",")
	bpf := slices.Index(order, "bpf")
	if bpf < 0 {
		return false
	}
	for _, l := range refusers {
		if i := slices.Index(order, l); i >= 0 && i < bpf {
			return false
		}
	}
	return true
}

// planeAttachRefusers are the LSMs besides the plane that refuse the agent's ptrace attach to a process that is not
// its descendant: Landlock's scope, which confines the agent's domain, and Yama, whose ptrace_scope of 1 or more
// admits only a descendant (/proc/sys/kernel/yama/ptrace_scope; 0, or no Yama, refuses nothing).
func planeAttachRefusers() []string {
	refusers := []string{"landlock"}
	if b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n >= 1 {
			refusers = append(refusers, "yama")
		}
	}
	return refusers
}

// planeProject is one run's directory: the project the sudo caller owns, and root's ledger, config and hooks'
// files beside it.
type planeProject struct {
	base, project, ledger, cfg string
}

// newPlaneProject lays out a project with the given files (mode 0644, or 0755 for a name under bin/ and out/'s
// binaries), directories and contract, owned by uid:gid.
func newPlaneProject(t *testing.T, uid, gid int, files map[string]string, dirs []string, links map[string]string) *planeProject {
	t.Helper()
	base, err := os.MkdirTemp("", "tego-plane-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	// tego's own files (ledger, config, chain anchor, own log) sit in a directory of their own, outside the
	// project's: a write entry inside tego's own directory is a contradiction compile refuses.
	state, err := os.MkdirTemp("", "tego-plane-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	p := &planeProject{base: state, project: filepath.Join(base, "project"), ledger: filepath.Join(state, "ledger"),
		cfg: filepath.Join(state, "config.yaml")}
	for _, d := range append([]string{"."}, dirs...) {
		if err := os.MkdirAll(filepath.Join(p.project, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		mode := os.FileMode(0o644)
		if strings.HasPrefix(body, "\x7fELF") || strings.HasPrefix(body, "#!") {
			mode = 0o755
		}
		path := filepath.Join(p.project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range links {
		if err := os.Link(filepath.Join(p.project, target), filepath.Join(p.project, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := filepath.Walk(p.project, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: [\"127.0.0.2\"]\n", p.ledger)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// run starts `tego run --tier cgroup <contract>` in the project under the plane pin.
func (p *planeProject) run(ctx context.Context, bin, contract, pin string, stdout io.Writer) *exec.Cmd {
	return p.runAt(ctx, bin, "cgroup", contract, pin, stdout)
}

// runAt starts `tego run --tier <tier> <contract>` in the project under the plane pin, with no --tier when tier is
// "" (the machine's auto selection).
func (p *planeProject) runAt(ctx context.Context, bin, tier, contract, pin string, stdout io.Writer) *exec.Cmd {
	args := []string{"run"}
	if tier != "" {
		args = append(args, "--tier", tier)
	}
	cmd := exec.CommandContext(ctx, bin, append(args, contract)...)
	cmd.Dir = p.project
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+p.cfg, "TEGO_TEST_PLANE="+pin,
		"TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(p.base, "chain.log"), "TEGO_TEST_OWN_LOG_HOME="+filepath.Join(p.base, "home"),
		"GOTRACEBACK=all", "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdout, cmd.Stderr = stdout, stdout
	cmd.WaitDelay = 15 * time.Second
	return cmd
}

// waitFile waits for path to exist, or fails once d has passed or the run behind it (a process whose output is
// out) ended.
func waitFile(t *testing.T, path string, d time.Duration, cmd *exec.Cmd, out *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if cmd != nil && cmd.Process != nil {
			if !processLive(cmd.Process.Pid) {
				time.Sleep(200 * time.Millisecond)
				t.Fatalf("the run ended before %s appeared:\n%s", path, out.String())
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if out != nil {
		t.Fatalf("%s did not appear within %s; the run said:\n%s\n%s", path, d, out.String(), stalledRun())
	}
	t.Fatalf("%s did not appear within %s", path, d)
}

// processLive reports whether pid is a process that has not exited (a zombie has).
func processLive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(b, ')')
	return i > 0 && len(b) > i+2 && b[i+2] != 'Z'
}

// hasFanotifyGroup reports whether a process holds a fanotify group.
func hasFanotifyGroup(pid int) bool {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if l, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil && l == "anon_inode:[fanotify]" {
			return true
		}
	}
	return false
}

// planeRowCount counts the rows every slot of this build's plane in mode m holds, fs and exec, and the slots.
func planeRowCount(t *testing.T, mode string) (rows int, slots int) {
	t.Helper()
	hash, err := ebpfbindings.Hash()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(DefaultBPFFS, pinRoot, hash+"-"+mode, pinMaps)
	for _, name := range []string{ebpfbindings.MapPlaneRows, ebpfbindings.MapPlaneExecRows} {
		outer, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
		if err != nil {
			t.Fatalf("open the plane's %s: %v", name, err)
		}
		var key, id uint32
		it := outer.Iterate()
		for it.Next(&key, &id) {
			slots++
			inner, err := ebpf.NewMapFromID(ebpf.MapID(id))
			if err != nil {
				continue
			}
			var k, next uint64
			for err := inner.NextKey(nil, &next); err == nil; err = inner.NextKey(&k, &next) {
				k = next
				rows++
			}
			_ = inner.Close()
		}
		_ = outer.Close()
	}
	return rows, slots / 2
}

// planeLiveHeaders counts the build's slot headers in mode that name a run (gen not 0), and how many of those say
// the run's contract decides exec (enforce-plane R6).
func planeLiveHeaders(t *testing.T, mode string) (live, execs int) {
	t.Helper()
	hash, err := ebpfbindings.Hash()
	if err != nil {
		t.Fatal(err)
	}
	slots, err := ebpf.LoadPinnedMap(filepath.Join(DefaultBPFFS, pinRoot, hash+"-"+mode, pinMaps, ebpfbindings.MapPlaneSlots), nil)
	if err != nil {
		t.Fatalf("open the plane's %s: %v", ebpfbindings.MapPlaneSlots, err)
	}
	defer slots.Close()
	var (
		key uint32
		h   ebpfbindings.PlaneSlot
	)
	it := slots.Iterate()
	for it.Next(&key, &h) {
		if h.Gen == 0 {
			continue
		}
		live++
		if h.Flags&ebpfbindings.PlaneSlotExecDecides != 0 {
			execs++
		}
	}
	if err := it.Err(); err != nil {
		t.Fatalf("read %s: %v", ebpfbindings.MapPlaneSlots, err)
	}
	return live, execs
}

// planeContract is the end-to-end contract: a write directory with a deny_read entry and a git repository in it,
// one binary of the project's own beside python3, and no network, under record: full: the filter leaves the plane
// every mutation it decides but the open family, which record: full keeps notified (TIER3-PLAN T16; enforce-plane
// §2.15). TestPlaneRunDropsAndNamesByPath runs it under record: summary.
const planeContract = `version: 0
name: plane-e2e
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  deny_read: ["./out/secret/"]
exec:
  allow: ["python3", "./bin/tool"]
net:
  allow: []
env:
  pass: ["PATH", "HOME", "PYTHONDONTWRITEBYTECODE"]
record: full
`

// planeAgent reports each action as "RESULT <name> <outcome>", then says it is ready and waits for go.
const planeAgent = `import os, subprocess, time

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def attempt(name, fn):
    try:
        fn()
        result(name, "ok")
    except OSError as e:
        result(name, "refused errno=%d" % e.errno)

def write(p):
    with open(p, "w") as f:
        f.write("x")

def read(p):
    with open(p) as f:
        f.read()

def run(p):
    r = subprocess.run([p])
    if r.returncode != 0:
        raise OSError(0, "exit status %d" % r.returncode)

attempt("write-inside", lambda: write("out/ok.txt"))
attempt("write-outside", lambda: write("forbidden.txt"))
attempt("read-unmatched", lambda: read("notes.txt"))
attempt("deny-read", lambda: read("out/secret/key"))
attempt("rename-out-of-deny-read", lambda: os.rename("out/secret/key2", "out/key2"))
attempt("link-out-of-deny-read", lambda: os.link("out/secret/key3", "out/key3"))
attempt("mv-git", lambda: os.rename("out/repo/.git", "out/repo/.git.old"))
attempt("touch-in-repo", lambda: write("out/repo/file.txt"))
attempt("exec-allowed", lambda: run("./bin/tool"))
attempt("exec-unlisted", lambda: run("./out/other"))
attempt("exec-hardlink-other-name", lambda: run("./out/alias"))
# Step B (TIER3-PLAN T13): creates under the nested deny_read, and attribute changes of the built-in deny_write
# target .git; a POSIX ACL equivalent to mode 0644, as setfacl writes it.
ACL = bytes([2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 4, 0, 4, 0, 255, 255, 255, 255, 0x20, 0, 4, 0, 255, 255, 255, 255])
attempt("mkdir-in-deny-read", lambda: os.mkdir("out/secret/sub"))
attempt("create-in-deny-read", lambda: write("out/secret/new"))
attempt("chmod-git-config", lambda: os.chmod("out/repo/.git/config", 0o600))
attempt("setfacl-git-config", lambda: os.setxattr("out/repo/.git/config", "system.posix_acl_access", ACL))
attempt("chmod-in-repo", lambda: os.chmod("out/repo/file.txt", 0o600))
write("out/ready")
while not os.path.exists("out/go"):
    time.sleep(0.02)
attempt("deny-read-later", lambda: read("out/secret/key"))
`

// planeFiles is the project the end-to-end contract governs.
func planeFiles(t *testing.T) (map[string]string, []string, map[string]string) {
	t.Helper()
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("the project's binary is a copy of /bin/true: %v", err)
	}
	return map[string]string{
			"agent.py": planeAgent, "agent.yaml": planeContract, "notes.txt": "n\n",
			"out/secret/key": "k\n", "out/secret/key2": "k2\n", "out/secret/key3": "k3\n",
			"out/repo/.git/HEAD": "ref: refs/heads/main\n", "out/repo/.git/config": "[core]\n",
			"out/repo/.git/hooks/pre-commit": "#!/bin/sh\n",
			"bin/tool":                       string(tool), "out/other": string(tool),
		}, []string{"out/repo/.git/hooks"},
		map[string]string{"out/alias": "bin/tool"}
}

// TestPlaneRunEndToEnd is TIER3-PLAN T6's acceptance: in each plane mode this machine passes, an ordinary run at
// tier cgroup is decided by the plane: a deny_read under a write entry refused with EACCES, a write outside every
// entry refused, an exec that is not allowed refused, and so is one of an allowed binary's hard link under another
// name; a rename or a hard link that carries a deny_read file out of its tree refused (REFER), and `mv .git
// .git.old` (the directory above the built-in deny_write targets) refused, while a write beside it in the repository
// goes ahead. The launcher holds no fanotify group while the run is live, the slot's rows are in the plane's maps
// meanwhile and gone after the run, and the ledger carries a refused line with the plane's reason for each refusal
// the kernel's record sees. The same run on the fanotify listener is the contrast: a group, EPERM for the
// deny_read, the repository's rename refused by the supervisor best effort and run_start's best_effort naming
// deny_write/default; under fs.assurance: kernel that listener run is refused before the agent starts instead
// (ADR 0041 D1 (a)).
func TestPlaneRunEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the plane needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	dir := t.TempDir()
	bin := buildPlaneTego(t, dir)
	requireTier(t, bin, "cgroup")
	modes := planeModesHere(t, bin)
	if len(modes) == 0 {
		t.Skip("no plane mode passes doctor's probe here")
	}
	for _, mode := range append(modes, PlaneFanotify) {
		t.Run(mode, func(t *testing.T) { planeRunCell(t, bin, uid, gid, mode) })
	}
}

func planeRunCell(t *testing.T, bin string, uid, gid int, mode string) {
	planeRunCellAt(t, bin, uid, gid, mode, "cgroup", "cgroup")
}

// planeRunCellAt is planeRunCell for `tego run --tier <tier>` (no --tier when tier is ""), whose run_start must name
// tier want.
func planeRunCellAt(t *testing.T, bin string, uid, gid int, mode, tier, want string) {
	files, dirs, links := planeFiles(t)
	p := newPlaneProject(t, uid, gid, files, dirs, links)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	if mode == PlaneFanotify {
		// fs.assurance: kernel refuses the listener run before any process of it exists.
		kernel := strings.Replace(planeContract, "  deny_read: [\"./out/secret/\"]\n", "  deny_read: [\"./out/secret/\"]\n  assurance: kernel\n", 1)
		if kernel == planeContract {
			t.Fatal("the plane contract has no deny_read line to add fs.assurance beside")
		}
		if err := os.WriteFile(filepath.Join(p.project, "agent-kernel.yaml"), []byte(kernel), 0o644); err != nil {
			t.Fatal(err)
		}
		var kout bytes.Buffer
		err := p.runAt(ctx, bin, tier, "agent-kernel.yaml", mode, &kout).Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 125 ||
			!strings.Contains(kout.String(), "protected write targets require a kernel decision plane") ||
			!strings.Contains(kout.String(), "fs.assurance: kernel") {
			t.Fatalf("fs.assurance: kernel on the listener: %v\n%s", err, kout.String())
		}
		if _, err := os.Stat(filepath.Join(p.project, "out", "ready")); !os.IsNotExist(err) {
			t.Fatalf("the agent ran under fs.assurance: kernel with no plane to decide its deny_write targets: %v", err)
		}
	}
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waitFile(t, filepath.Join(p.project, "out", "ready"), time.Minute, cmd, &out)

	group := hasFanotifyGroup(cmd.Process.Pid)
	rows, slots, headers, execHeaders := 0, 0, 0, 0
	execOutcomes := false
	if mode != PlaneFanotify {
		rows, slots = planeRowCount(t, mode)
		headers, execHeaders = planeLiveHeaders(t, mode)
		execOutcomes = pinnedExecOutcomes(t)
	}
	if err := os.WriteFile(filepath.Join(p.project, "out", "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	runErr := <-done
	t.Logf("tego run (%s): %v\n%s", mode, runErr, out.String())
	if runErr != nil {
		t.Fatalf("the run did not complete: %v", runErr)
	}
	res := agentResults(t, out.String())
	refused := func(name string) {
		t.Helper()
		if !strings.HasPrefix(res[name], "refused") {
			t.Errorf("%s: %q, want refused", name, res[name])
		}
	}
	allowed := func(name string) {
		t.Helper()
		if res[name] != "ok" {
			t.Errorf("%s: %q, want ok", name, res[name])
		}
	}
	allowed("write-inside")
	allowed("read-unmatched")
	allowed("touch-in-repo")
	allowed("exec-allowed")
	refused("write-outside")
	refused("deny-read")
	refused("deny-read-later")
	refused("exec-unlisted")
	refused("mv-git")
	events := runEvents(t, p.ledger)
	// run_start names what decided (enforce-plane R19, I7): the plane's mode, or fanotify on the listener.
	start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" })
	if start == nil || start["tier"] != want || start["decision_plane"] != mode {
		t.Errorf("run_start %v, want tier %s decision_plane %s", start, want, mode)
	}
	if bestEffort, _ := start["best_effort"].([]any); slices.Contains(bestEffort, any("deny_write/default")) != (mode == PlaneFanotify) {
		t.Errorf("run_start best_effort %v: deny_write/default belongs there exactly when no plane decides (%s)", start["best_effort"], mode)
	}
	if mode == PlaneFanotify {
		if !group {
			t.Error("the fanotify run's launcher holds no fanotify group")
		}
		// The repository's rename is the supervisor's refusal (R15c), best effort below a plane.
		if findEvent(events, func(e map[string]any) bool {
			return e["kind"] == "fs" && e["verdict"] == "refused" && e["source"] == "seccomp" &&
				strings.HasSuffix(fmt.Sprint(e["path"]), "/out/repo/.git") &&
				strings.HasPrefix(fmt.Sprint(e["rule"]), "fs.deny_write[")
		}) == nil {
			t.Error("no refused seccomp line for the repository's rename on the listener")
		}
		if res["deny-read"] != "refused errno=1" {
			t.Errorf("deny-read on the listener: %q, want EPERM", res["deny-read"])
		}
		// The contrast where the plane decides (the deny_read nested in the write entry): the listener's lines are
		// its own (source fanotify, no mechanism, no decision_plane), the plane's are source kernel, mechanism plane.
		n := 0
		for _, e := range events {
			if e["kind"] == "fs" && e["verdict"] == "refused" && e["op"] == "open" &&
				e["path"] == filepath.Join(p.project, "out", "secret", "key") {
				n++
				if e["source"] != "fanotify" || e["mechanism"] != nil || e["decision_plane"] != nil ||
					e["rule"] != "fs.deny_read[./out/secret/]" || e["reason"] != "read-denied" {
					t.Errorf("the listener's deny_read line: %v, want source fanotify, no mechanism or decision_plane", e)
				}
			}
		}
		if n != 2 {
			t.Errorf("%d refused deny_read open lines on the listener, want 2 (one per action)", n)
		}
		return
	}
	// The plane's own cells.
	if group {
		t.Errorf("the %s run's launcher holds a fanotify group: a plane mode places no mark and makes no group", mode)
	}
	if res["deny-read"] != "refused errno=13" {
		t.Errorf("deny-read under the plane: %q, want EACCES", res["deny-read"])
	}
	refused("rename-out-of-deny-read")
	refused("link-out-of-deny-read")
	refused("exec-hardlink-other-name")
	if _, err := os.Stat(filepath.Join(p.project, "out", "repo", ".git")); err != nil {
		t.Errorf("out/repo/.git after the refused rename: %v", err)
	}
	if rows == 0 || slots == 0 {
		t.Errorf("the plane's maps held %d rows in %d slots while the run was live, want its rows", rows, slots)
	}
	if after, _ := planeRowCount(t, mode); after != 0 {
		t.Errorf("the plane's maps hold %d rows after the run: Detach clears its slot", after)
	}
	// The slot's header (R6): written with the run's gen and its exec: section while the run is live, zeroed by
	// Detach's clear.
	if headers == 0 || execHeaders == 0 {
		t.Errorf("%d live slot headers (%d deciding exec) while the run was live, want the run's", headers, execHeaders)
	}
	if after, _ := planeLiveHeaders(t, mode); after != 0 {
		t.Errorf("%d slot headers name a run after it: Detach zeroes its slot's header", after)
	}
	pin := filepath.Join(DefaultBPFFS, pinRoot, mustHash(t)+"-"+mode, planeAnswerName)
	if _, err := os.Stat(pin); err != nil {
		t.Errorf("the plane's probe answer is not pinned: %v", err)
	}
	for path, reason := range map[string]string{
		filepath.Join(p.project, "out", "secret", "key"): "read-denied",
		filepath.Join(p.project, "forbidden.txt"):        "write-outside-contract",
	} {
		if findEvent(events, func(e map[string]any) bool {
			return e["kind"] == "fs" && e["verdict"] == "refused" && e["reason"] == reason && e["path"] == path &&
				e["source"] == "kernel"
		}) == nil {
			t.Errorf("no refused source=kernel fs line with reason %s for %s", reason, path)
		}
	}
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["verdict"] == "refused" && e["reason"] == "rename-outside-contract" &&
			strings.HasSuffix(fmt.Sprint(e["path"]), "key2")
	}) == nil {
		t.Error("no refused rename line for the rename out of the deny_read tree")
	}
	if findEvent(events, func(e map[string]any) bool { return e["source"] == "fanotify" }) != nil {
		t.Error("a source=fanotify line in a plane run")
	}
	// One line per action (enforce-plane R22, R27; TIER3-PLAN T16), named by its path: the repository's rename and the
	// unlisted and hard-linked execs are refused once each. T16 uses terminal kernel outcomes when complete
	// persistent coverage exists, and otherwise retains supervisor ownership.
	var refusedLines []map[string]any
	for _, e := range events {
		if e["verdict"] == "refused" {
			refusedLines = append(refusedLines, e)
		}
	}
	for _, c := range []struct{ kind, suffix, source string }{
		{"fs", "/out/repo/.git", ""}, {"exec", "/out/other", ""}, {"exec", "/out/alias", ""},
	} {
		var lines []map[string]any
		for _, e := range refusedLines {
			if e["kind"] == c.kind && strings.HasSuffix(fmt.Sprint(e["path"]), c.suffix) {
				lines = append(lines, e)
			}
		}
		if len(lines) != 1 || (c.source != "" && lines[0]["source"] != c.source) {
			t.Errorf("refused %s lines for %s: %v, want one (source %q); every refused line: %v", c.kind, c.suffix,
				lines, c.source, refusedLines)
		}
	}
	planeStepBRunCells(t, p, res, events)
	planeRefusalLines(t, p, events, mode, want, execOutcomes)
}

// Verify actual persistent result links while the launcher is live. A loaded tracepoint program or
// doctor's successful temporary attach alone does not prove the pinned outcome coverage T16 needs.
func pinnedExecOutcomes(t *testing.T) bool {
	t.Helper()
	for name := range ebpfbindings.ExecResultTracepoints {
		path := filepath.Join(DefaultBPFFS, pinRoot, mustHash(t), pinLinks, name)
		l, err := link.LoadPinnedLink(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err != nil {
			t.Fatalf("load pinned exec outcome link %s: %v", path, err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return true
}

// refusedWant is one refused action's expected ledger line: the lines whose kind, op ("" for any) and path suffix
// match must number n, each with these fields (an empty field is unchecked). A line the plane decides has source
// kernel, mechanism plane and decision_plane the mode; one the supervisor still decides (T16 removes those: the
// filter then leaves the plane every action it decides) has source seccomp and neither.
type refusedWant struct {
	kind, op, suffix                     string
	n                                    int
	source, mechanism, rule, reason, why string // why is plane_reason
}

// planeRefusalLines asserts each refused action of the agent is exactly one verdict line, and no other line is
// refused: its source, mechanism, decision_plane, rule, reason and plane_reason (the rule and reason are what
// decide.PlaneEvaluator, compile --test's bpflsm column, names for the action: observe's
// TestIntegrationPlaneRefusalIsOneLine checks that equality per line). Exec ownership follows the actual pinned
// failure-result coverage; attributes retain supervisor naming when the kernel recorder cannot name the path.
func planeRefusalLines(t *testing.T, p *planeProject, events []map[string]any, mode, tier string, execOutcomes bool) {
	t.Helper()
	const deny = "fs.deny_read[./out/secret/]"
	config := filepath.Join(p.project, "out", "repo", ".git", "config")
	kernel := func(op, suffix string, n int, rule, reason, why string) refusedWant {
		return refusedWant{"fs", op, suffix, n, "kernel", "plane", rule, reason, why}
	}
	super := func(kind, op, suffix, rule, reason string) refusedWant {
		return refusedWant{kind, op, suffix, 1, "seccomp", "", rule, reason, ""}
	}
	unlisted := super("exec", "", "/out/other", "unmatched", "exec-not-allowed")
	alias := super("exec", "", "/out/alias", "unmatched", "exec-not-allowed")
	if execOutcomes {
		// Landlock rejects the unlisted image's execute-open before bprm; the named hard link passes
		// that inode floor and is rejected by the plane's name rule. Both have one kernel outcome.
		unlisted.source = "kernel"
		alias.source, alias.mechanism = "kernel", "plane"
	}
	// A write outside every entry: where Landlock comes before bpf in the LSM order (the lsm=...,bpf boot appends bpf)
	// Landlock refuses it first in lsm mode: the line is the kernel record's, its verdict the chain's, and it names no
	// mechanism or decision_plane. In fmod_ret mode the plane's hook runs before the whole chain, and a kernel whose own
	// list puts bpf first (Fedora's: ...,selinux,bpf,landlock,...) runs the plane's lsm program first: the plane
	// decides it.
	forbidden := refusedWant{"fs", "open", "/forbidden.txt", 1, "kernel", "", "unmatched", "write-outside-contract", ""}
	if planeAnswersFirst(mode, "landlock") {
		forbidden.mechanism = "plane"
	}
	// A rename or a link out of the deny_read tree is the plane's at both tiers: step E's fs half hands the filter's
	// notification of a path hook the plane decides to the plane (enforce-plane R27, §2.13).
	rename := kernel("rename", "/out/secret/key2", 1, deny, "rename-outside-contract", "")
	link := kernel("link", "/out/secret/key3", 1, deny, "write-outside-contract", "refer")
	want := []refusedWant{
		forbidden,
		kernel("open", "/out/secret/key", 2, deny, "read-denied", ""), // before and after `go`: two actions
		rename,
		link,
		kernel("mkdir", "/out/secret/sub", 1, deny, "mkdir-outside-contract", ""),
		kernel("open", "/out/secret/new", 1, deny, "write-outside-contract", ""),
		// The .git rename is the plane's too (step E); the exec source follows T16's outcome coverage. A chmod
		// of the deny_write target and the plane's setfacl are two distinct actions, each refused once.
		kernel("rename", "/out/repo/.git", 1, "fs.deny_write["+filepath.Join(p.project, "out", "repo", ".git", "hooks")+"]",
			"rename-outside-contract", "deny-write-ancestor"),
		unlisted,
		alias,
		super("fs", "chmod", "/out/repo/.git/config", "fs.deny_write["+config+"]", "write-outside-contract"),
		// op chmod, or xattr on 6.1, where setfacl writes the ACL through setxattr (§2.17).
		kernel("", "config", 1, "fs.deny_write["+config+"]", "write-outside-contract", ""),
	}
	matched := make([]bool, len(events))
	for _, w := range want {
		var lines []map[string]any
		for i, e := range events {
			if e["verdict"] == "refused" && e["kind"] == w.kind && (w.op == "" || e["op"] == w.op) &&
				(w.source == "" || e["source"] == w.source) &&
				strings.HasSuffix(fmt.Sprint(e["path"]), w.suffix) && !matched[i] {
				lines = append(lines, e)
				matched[i] = true
			}
		}
		if len(lines) != w.n {
			t.Errorf("refused %s %s lines for %s: %d, want %d: %v", w.kind, w.op, w.suffix, len(lines), w.n, lines)
		}
		for _, e := range lines {
			field := func(name, want string) {
				if want != "" && fmt.Sprint(e[name]) != want {
					t.Errorf("refused %s %s line for %s: %s = %v, want %q: %v", w.kind, w.op, w.suffix, name, e[name], want, e)
				}
			}
			field("source", w.source)
			if w.mechanism == "" && e["mechanism"] != nil {
				t.Errorf("a line the plane did not decide names mechanism %v: %v", e["mechanism"], e)
			}
			field("mechanism", w.mechanism)
			field("rule", w.rule)
			field("reason", w.reason)
			field("plane_reason", w.why)
			if w.mechanism == "plane" {
				field("decision_plane", mode)
			} else if e["decision_plane"] != nil {
				t.Errorf("a line the plane did not decide names decision_plane %v: %v", e["decision_plane"], e)
			}
		}
	}
	for i, e := range events {
		if e["verdict"] == "refused" && !matched[i] {
			t.Errorf("a refused line no agent action accounts for: %v", e)
		}
		if e["verdict"] == "refused" {
			t.Logf("refused %v %v %v -> %v: source=%v mechanism=%v plane=%v rule=%v reason=%v plane_reason=%v", e["kind"], e["op"],
				e["path"], e["path2"], e["source"], e["mechanism"], e["decision_plane"], e["rule"], e["reason"], e["plane_reason"])
		}
	}
}

// planeStepBRunCells is TIER3-PLAN T13's acceptance in a real run (enforce-plane R12, R13): a mkdir and a create
// under the deny_read nested in the write entry are refused and leave nothing; a chmod and a setfacl of the built-in
// deny_write target .git are refused and change nothing, while a chmod beside it in the repository goes ahead; and
// each refusal is one ledger line: the plane's (source kernel, mechanism plane) for the mkdir and the setfacl, and
// the supervisor's for the chmod it refuses first under record: full (supervisor Options.PlaneAttrs).
func planeStepBRunCells(t *testing.T, p *planeProject, res map[string]string, events []map[string]any) {
	t.Helper()
	for _, name := range []string{"mkdir-in-deny-read", "create-in-deny-read", "chmod-git-config"} {
		if res[name] != "refused errno=13" {
			t.Errorf("%s under the plane: %q, want EACCES", name, res[name])
		}
	}
	if r := res["setfacl-git-config"]; r != "refused errno=13" {
		t.Errorf("setfacl-git-config under the plane: %q, want EACCES", r)
	}
	if res["chmod-in-repo"] != "ok" {
		t.Errorf("chmod-in-repo: %q, want ok", res["chmod-in-repo"])
	}
	for _, f := range []string{"out/secret/sub", "out/secret/new"} {
		if _, err := os.Lstat(filepath.Join(p.project, f)); !os.IsNotExist(err) {
			t.Errorf("%s exists after the refused create (%v): a refused create leaves nothing (R13)", f, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(p.project, "out", "repo", ".git", "config")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf(".git/config after the refused chmod and setfacl: %v, %v", fi.Mode(), err)
	}
	secret := filepath.Join(p.project, "out", "secret")
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["verdict"] == "refused" && e["op"] == "mkdir" && e["path"] == filepath.Join(secret, "sub") &&
			e["source"] == "kernel" && e["mechanism"] == "plane" && e["rule"] == "fs.deny_read[./out/secret/]"
	}) == nil {
		t.Error("no refused source=kernel mechanism=plane mkdir line under the deny_read")
	}
	config := filepath.Join(p.project, "out", "repo", ".git", "config")
	// The plane names the file by its directory's (dev, ino) and final component, which the recorder resolves
	// through the rule table's directory index; .git is no fs entry's directory, so the line may carry the raw
	// identifier ending in the name (enforce-plane §2.10). Below 6.2 (AL2023's 6.1) an ACL is an xattr write, which
	// inode_setxattr refuses (op xattr); from 6.2 inode_set_acl does (op chmod, §2.12).
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["verdict"] == "refused" && (e["op"] == "chmod" || e["op"] == "xattr") &&
			strings.HasSuffix(fmt.Sprint(e["path"]), "config") && e["source"] == "kernel" && e["mechanism"] == "plane" &&
			strings.HasPrefix(fmt.Sprint(e["rule"]), "fs.deny_write[")
	}) == nil {
		t.Error("no refused source=kernel mechanism=plane line naming the deny_write target for the setfacl of .git/config")
		for _, e := range events {
			if e["mechanism"] == "plane" {
				t.Logf("plane line: %v", e)
			}
		}
	}
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["verdict"] == "refused" && e["op"] == "chmod" && e["path"] == config &&
			e["source"] == "seccomp"
	}) == nil {
		t.Error("no refused chmod line of the supervisor's for the chmod of .git/config")
	}
	if t.Failed() {
		for _, e := range events {
			if strings.Contains(fmt.Sprint(e["path"]), ".git") || strings.Contains(fmt.Sprint(e["path"]), "secret") {
				t.Logf("ledger: %v", e)
			}
		}
	}
	n := 0
	for _, e := range events {
		if e["kind"] == "fs" && e["op"] == "mkdir" && e["path"] == filepath.Join(secret, "sub") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d lines for the refused mkdir, want one (I8)", n)
	}
}

// TestPlaneRunRefusesIOUring holds ADR 0113's immutable identity boundary:
// no plane mode may admit rings that bypass the Unix inode relay.
func TestPlaneRunRefusesIOUring(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range append(modes, PlaneFanotify) {
		t.Run(mode, func(t *testing.T) {
			p := newPlaneProject(t, uid, gid, map[string]string{"agent.yaml": `version: 0
name: builtin-ring-refusal
command: ["/bin/true"]
tier: cgroup
io_uring: true
`}, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var out bytes.Buffer
			if err := p.run(ctx, bin, "agent.yaml", mode, &out).Run(); err == nil || !strings.Contains(out.String(), "builtin.host_ipc") {
				t.Fatalf("ring opt-in bypassed immutable boundary: %v\n%s", err, out.String())
			}
		})
	}
}

// mustHash is this build's bpf_hash, which the tego under test shares (both carry the same objects).
func mustHash(t *testing.T) string {
	t.Helper()
	h, err := ebpfbindings.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// planeWaitAgent reads data/f, says ready, waits for its go, and reads again, each answer a RESULT line on its
// stdout: a write-open of a file of its own would ask the supervisor, which is gone once its launcher is killed.
const planeWaitAgent = `import os, sys, time
name = sys.argv[1]
def read():
    try:
        with open("data/f") as f:
            f.read()
        return "ok"
    except OSError as e:
        return "refused errno=%d" % e.errno
print("RESULT first", read(), flush=True)
with open("out/ready-" + name, "w") as f:
    f.write("ready")
while not os.path.exists("out/go-" + name):
    time.sleep(0.02)
print("RESULT second", read(), flush=True)
`

// planeOrphanAgent is planeWaitAgent in a descendant of its own session, which the launcher's PDEATHSIG does not
// reach (reapAgent's shape): it outlives a killed launcher, and so does the run.
const planeOrphanAgent = `import os, sys, time
name = sys.argv[1]
def read():
    try:
        with open("data/f") as f:
            f.read()
        return "ok"
    except OSError as e:
        return "refused errno=%d" % e.errno
pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork() == 0:
        print("RESULT first", read(), flush=True)
        with open("out/ready-" + name, "w") as f:
            f.write("ready")
        while not os.path.exists("out/go-" + name):
            time.sleep(0.02)
        print("RESULT second", read(), flush=True)
        os._exit(0)
    os._exit(0)
os.waitpid(pid, 0)
time.sleep(600)
`

func planeWaitContract(name string, deny bool) string {
	fs := `  write: ["./out/"]
`
	if deny {
		fs += `  deny_read: ["./data/"]
`
	}
	return fmt.Sprintf(`version: 0
name: plane-%s
command: ["python3", "./wait.py", "%s"]
fs:
%sexec:
  allow: ["python3"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`, name, name, fs)
}

// startPiped starts cmd with its stdout and stderr on a pipe this test reads into out: no copying goroutine of
// cmd's own, so Wait returns with the launcher even while its orphaned agent still holds the pipe.
func startPiped(t *testing.T, cmd *exec.Cmd, out *lockedBuffer) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	go func() {
		_, _ = io.Copy(out, r)
		_ = r.Close()
	}()
}

// planeAnswer waits for an agent's RESULT line of one step.
func planeAnswer(t *testing.T, out *lockedBuffer, step string) string {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		if got := agentResults(t, out.String())[step]; got != "" {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no RESULT %s within a minute; the run said:\n%s", step, out.String())
	return ""
}

// TestPlaneConcurrentRunsOfOneBuildAreIsolated is enforce-plane §6 E1: two runs of one build live at once, one whose
// contract denies data/ and one whose contract does not, on the same files. Each sees only its own rows (the outer
// maps are keyed by run_idx), before and after the other started.
func TestPlaneConcurrentRunsOfOneBuildAreIsolated(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			p := newPlaneProject(t, uid, gid, map[string]string{
				"wait.py": planeWaitAgent, "deny.yaml": planeWaitContract("deny", true),
				"open.yaml": planeWaitContract("open", false), "data/f": "f\n",
			}, []string{"out"}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var outA, outB lockedBuffer
			a := p.run(ctx, bin, "deny.yaml", mode, nil)
			startPiped(t, a, &outA)
			d1 := planeAnswer(t, &outA, "first")
			pb := newPlaneProjectConfig(t, p)
			b := pb.run(ctx, bin, "open.yaml", mode, nil)
			startPiped(t, b, &outB)
			o1 := planeAnswer(t, &outB, "first")
			waitFile(t, filepath.Join(p.project, "out", "ready-open"), time.Minute, nil, nil)
			if rows, slots := planeRowCount(t, mode); slots < 2 || rows == 0 {
				t.Errorf("two live runs: %d rows in %d slots, want a slot each", rows, slots)
			}
			if err := os.WriteFile(filepath.Join(p.project, "out", "go-deny"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			d2 := planeAnswer(t, &outA, "second")
			if err := os.WriteFile(filepath.Join(p.project, "out", "go-open"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			o2 := planeAnswer(t, &outB, "second")
			errA, errB := a.Wait(), b.Wait()
			t.Logf("run deny: %v\n%s\nrun open: %v\n%s", errA, outA.String(), errB, outB.String())
			if !strings.HasPrefix(d1, "refused") || !strings.HasPrefix(d2, "refused") {
				t.Errorf("the denying run read data/f: %q then %q, want refused both times", d1, d2)
			}
			if o1 != "ok" || o2 != "ok" {
				t.Errorf("the other run read data/f: %q then %q, want ok both times: it has no row there", o1, o2)
			}
			if errA != nil || errB != nil {
				t.Errorf("the runs ended %v and %v, want both to complete", errA, errB)
			}
		})
	}
}

// newPlaneProjectConfig is a second run's own ledger root and config over the same project.
func newPlaneProjectConfig(t *testing.T, p *planeProject) *planeProject {
	t.Helper()
	q := *p
	q.ledger = filepath.Join(p.base, "ledger-2")
	q.cfg = filepath.Join(p.base, "config-2.yaml")
	if err := os.Mkdir(q.ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(q.cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: [\"127.0.0.2\"]\n", q.ledger)), 0o644); err != nil {
		t.Fatal(err)
	}
	return &q
}

// planePreconditions skips where the plane cannot run and returns the binary, the sudo caller and the modes.
func planePreconditions(t *testing.T) (string, int, int, []string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the plane needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	bin := buildPlaneTego(t, t.TempDir())
	requireTier(t, bin, "cgroup")
	modes := planeModesHere(t, bin)
	if len(modes) == 0 {
		t.Skip("no plane mode passes doctor's probe here")
	}
	return bin, uid, gid, modes
}

// TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges is ADR 0020 with the plane (enforce-plane §6 E11,
// R20; TIER3-PLAN §9's "SIGKILL of the launcher with drop_caches still refuses"): SIGKILL of the launcher changes
// nothing the plane decides, since the rows, the run-set row and the links are pinned and the run's Landlock domain
// holds every keyed inode (a deny_read read by the orphaned agent after the kill and a drop of the dentry and inode
// caches is still refused), and the run's reaper, held meanwhile by the test hook, then ends the orphan and purges
// its slot, the plane's rows with the rest (PurgeRun's clear).
func TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			p := newPlaneProject(t, uid, gid, map[string]string{
				"wait.py": planeOrphanAgent, "deny.yaml": planeWaitContract("deny", true), "data/f": "f\n",
			}, []string{"out"}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var out lockedBuffer
			hold := filepath.Join(p.base, "reap-hold")
			t.Cleanup(func() { _ = os.WriteFile(hold, nil, 0o600) })
			cmd := p.run(ctx, bin, "deny.yaml", mode, nil)
			cmd.Env = append(cmd.Env, "TEGO_TEST_REAP_HOLD="+hold)
			startPiped(t, cmd, &out)
			first := planeAnswer(t, &out, "first")
			waitFile(t, filepath.Join(p.project, "out", "ready-deny"), time.Minute, nil, nil)
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0o200); err != nil {
				t.Logf("drop_caches: %v", err)
			}
			if rows, _ := planeRowCount(t, mode); rows == 0 {
				t.Error("the launcher's death took the run's plane rows with it")
			}
			if err := os.WriteFile(filepath.Join(p.project, "out", "go-deny"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			second := planeAnswer(t, &out, "second")
			if !strings.HasPrefix(first, "refused") || !strings.HasPrefix(second, "refused") {
				t.Errorf("the orphaned agent read data/f: %q before the kill, %q after it; want refused both times", first, second)
			}
			if err := os.WriteFile(hold, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Minute)
			for {
				rows, _ := planeRowCount(t, mode)
				if rows == 0 {
					break
				}
				if time.Now().After(deadline) {
					res, err := PurgeRun(PurgeOptions{Hash: mustHash(t)})
					t.Fatalf("the plane still holds %d rows a minute after the orphan ended: no reaper purged its slot "+
						"(a purge from here: %+v, %v; the plane's pins: %v)", rows, res, err, pinTree(filepath.Join(DefaultBPFFS, pinRoot, mustHash(t)+"-"+mode)))
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}

// TestPlaneSecondRunAdoptsThePlane is enforce-plane R18's adopt half, found missing by TIER3-PLAN T11's kill test 4:
// a run after another of its build, while the build lingers, runs the plane's pinned programs rather than loading
// and verifying its own copies. The plane's unpinned task storage (tego_plane_path_buf) made adoption refuse, so
// every run loaded the six programs again, about 100 ms of a root run's 200 in the 6.12 guest. The pinned programs
// keep their ids across the second run, and no plane program newer than the first run's exists after it.
func TestPlaneSecondRunAdoptsThePlane(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			p := newPlaneProject(t, uid, gid, map[string]string{
				"wait.py": planeWaitAgent, "adopt.yaml": planeWaitContract("adopt", true), "data/f": "f\n",
				"out/go-adopt": "",
			}, []string{"out"}, nil)
			progs := filepath.Join(DefaultBPFFS, pinRoot, mustHash(t)+"-"+mode, "progs")
			run := func(step string) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				if err := p.run(ctx, bin, "adopt.yaml", mode, &out).Run(); err != nil {
					t.Fatalf("%s run: %v\n%s", step, err, out.String())
				}
			}
			pinned := func() map[string]ebpf.ProgramID {
				ids := map[string]ebpf.ProgramID{}
				ents, err := os.ReadDir(progs)
				if err != nil {
					t.Fatalf("the plane's pinned programs: %v (the build must linger between the runs)", err)
				}
				for _, e := range ents {
					prog, err := ebpf.LoadPinnedProgram(filepath.Join(progs, e.Name()), nil)
					if err != nil {
						t.Fatal(err)
					}
					info, err := prog.Info()
					_ = prog.Close()
					if err != nil {
						t.Fatal(err)
					}
					id, _ := info.ID()
					ids[e.Name()] = id
				}
				return ids
			}
			run("first")
			first := pinned()
			if len(first) == 0 {
				t.Fatalf("no plane program pinned under %s", progs)
			}
			var newest ebpf.ProgramID
			for id := ebpf.ProgramID(0); ; {
				next, err := ebpf.ProgramGetNextID(id)
				if err != nil {
					break
				}
				newest, id = next, next
			}
			run("second")
			second := pinned()
			for name, id := range first {
				if second[name] != id {
					t.Errorf("%s: pinned program %d after the first run, %d after the second: it was loaded again", name, id, second[name])
				}
			}
			for id := newest; ; {
				next, err := ebpf.ProgramGetNextID(id)
				if err != nil {
					break
				}
				id = next
				prog, err := ebpf.NewProgramFromID(next)
				if err != nil {
					continue
				}
				info, err := prog.Info()
				_ = prog.Close()
				if err != nil {
					continue
				}
				for name := range first {
					if len(info.Name) >= 8 && strings.HasPrefix(name, info.Name) {
						t.Errorf("the second run loaded program %d (%s), a copy of the plane's %s", next, info.Name, name)
					}
				}
			}
		})
	}
}

// pinTree lists every path under dir, for a failure's message.
func pinTree(dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			out = append(out, strings.TrimPrefix(p, dir))
		}
		return nil
	})
	return out
}

// ledgerDump is every run's ledger under root, for a failure's message.
func ledgerDump(root string) string {
	runs, _ := filepath.Glob(filepath.Join(root, "*", "events.jsonl"))
	var b strings.Builder
	for _, r := range runs {
		data, _ := os.ReadFile(r)
		b.Write(data)
	}
	return b.String()
}
