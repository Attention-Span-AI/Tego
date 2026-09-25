// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// daemonizing is the agent both cross-owner cases run: it starts a descendant that writes its pid and sleeps,
// then becomes a sleep itself. PDEATHSIG ends the agent's own process with its launcher, never the descendant,
// which only a sweep's kill of the run's cgroup can end.
const daemonizing = `/bin/sh -c 'echo $$ > out/daemon.pid; exec /bin/sleep 300' & exec /bin/sleep 120`

// crossOwner is the environment of one cross-owner case: a fixture whose project, ledger root and chain
// anchor are the invoking user's, as on a real `sudo tego ...` of that user's project.
type crossOwner struct {
	f        *fixture
	bin      string
	uid, gid int
	cfg      string
	anchor   string
	logHome  string
}

// newCrossOwner prepares the case. It needs root and the invoking user sudo names.
func newCrossOwner(t *testing.T, name string) *crossOwner {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root only: a sweep of another account's run, and a launcher of another uid, need root")
	}
	uid, gid, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBinary(t)
	agentReaches(t, bin)
	f := newFixture(t, contractFor(name, []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep"}))
	if err := os.Chmod(f.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(f.dir, "agent.yaml"), f.root)
	agentReaches(t, filepath.Join(f.root, "x"))
	cfg := filepath.Join(f.dir, "config.yaml")
	body := fmt.Sprintf("version: 0\nledger_root: %s\nstop_grace: 2s\n", f.root)
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	logHome := filepath.Join(state, "home")
	if err := os.Mkdir(logHome, 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, state, logHome)
	agentReaches(t, filepath.Join(state, "x"))
	// The user's own launcher builds its Landlock ruleset from the directories around the contract's entries,
	// listing them, where a root launcher's agent only passes through: the test's 0700 temporary directories
	// are opened to it as a user's own project tree would be.
	for _, p := range []string{f.out, f.root, logHome} {
		userLists(t, p)
	}
	return &crossOwner{f: f, bin: bin, uid: uid, gid: gid, cfg: cfg,
		anchor: filepath.Join(state, ledger.ChainLogFile), logHome: logHome}
}

// userLists adds o+rx to path and each directory between it and this package's temporary parent.
func userLists(t *testing.T, path string) {
	t.Helper()
	top := filepath.Clean(os.TempDir())
	for dir := filepath.Clean(path); strings.HasPrefix(dir+"/", top+"/"); dir = filepath.Dir(dir) {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if err := os.Chmod(dir, st.Mode().Perm()|0o005); err != nil {
			t.Fatalf("chmod o+rx %s: %v", dir, err)
		}
		if dir == top {
			return
		}
	}
}

// env is the environment of a tego the case starts: the fixture's config, anchor and own log, and for the
// user's own processes none of sudo's variables, as the user's own shell would have.
func (c *crossOwner) env(asUser bool) []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "TEGO_") || name == "HOME" || (asUser && strings.HasPrefix(name, "SUDO_")) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "HOME="+c.logHome, "TEGO_CONFIG="+c.cfg, "TEGO_TEST_CHAIN_ANCHOR="+c.anchor,
		"TEGO_TEST_OWN_LOG_HOME="+c.logHome)
}

// command is bin with args, run as the invoking user when asUser, with its output in files: a pipe would be
// held open by the descendant and keep Wait from returning.
func (c *crossOwner) command(t *testing.T, asUser bool, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(c.bin, args...)
	cmd.Dir = c.f.dir
	cmd.Env = c.env(asUser)
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	cmd.Stdout, cmd.Stderr = out, out
	if asUser {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: uint32(c.uid), Gid: uint32(c.gid), Groups: []uint32{}}}
	}
	return cmd
}

// output is what a command started by command wrote.
func output(cmd *exec.Cmd) string {
	if f, ok := cmd.Stdout.(*os.File); ok {
		return readFileString(f.Name())
	}
	return ""
}

// userLeaf is a cgroup the invoking user's launcher starts in, inside the subtree systemd delegates to that
// user (user@<uid>.service, where an unprivileged launcher makes its runs' scopes and a root sweep looks for
// them). A subtree that is not there — a KVM guest without the chain, a CI runner whose user manager is not
// running — is made as systemd would make it: owned by the user, the cpu, memory and pids controllers enabled
// down to it. Everything the test made is removed when it ends. The returned descriptor places a child there
// (CLONE_INTO_CGROUP).
func userLeaf(t *testing.T, uid, gid int) int {
	t.Helper()
	sub := cgroup.UserSubtree(uid)
	rel, err := filepath.Rel(cgroup.Mount, sub)
	if err != nil {
		t.Fatal(err)
	}
	var made []string
	t.Cleanup(func() {
		for i := len(made) - 1; i >= 0; i-- {
			removeCgroupTree(made[i])
		}
	})
	dir := cgroup.Mount
	for _, name := range strings.Split(rel, "/") {
		enableControllers(dir)
		dir = filepath.Join(dir, name)
		if err := os.Mkdir(dir, 0o755); err == nil {
			made = append(made, dir)
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatalf("make %s: %v", dir, err)
		}
	}
	if len(made) > 0 && made[len(made)-1] == sub {
		delegate(t, sub, uid, gid, "cgroup.procs", "cgroup.subtree_control", "cgroup.threads")
	}
	if st, err := os.Stat(sub); err != nil || int(st.Sys().(*syscall.Stat_t).Uid) != uid {
		t.Fatalf("%s is not delegated to uid %d: %v", sub, uid, err)
	}
	enableControllers(sub)
	leaf := filepath.Join(sub, fmt.Sprintf("tego-itest-%d.scope", os.Getpid()))
	if err := os.Mkdir(leaf, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeCgroupTree(leaf) })
	delegate(t, leaf, uid, gid, "cgroup.procs", "cgroup.threads")
	fd, err := syscall.Open(leaf, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

// enableControllers asks for the cpu, memory and pids controllers in dir's children, each on its own: one the
// hierarchy does not offer must not cost the others.
func enableControllers(dir string) {
	for _, c := range []string{"+cpu", "+memory", "+pids"} {
		_ = os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(c), 0)
	}
}

// delegate hands the cgroup dir and the named files in it to uid, as systemd delegates a subtree.
func delegate(t *testing.T, dir string, uid, gid int, files ...string) {
	t.Helper()
	for _, p := range append([]string{dir}, files...) {
		if p != dir {
			p = filepath.Join(dir, p)
		}
		if err := os.Chown(p, uid, gid); err != nil {
			t.Fatalf("delegate %s to %d: %v", p, uid, err)
		}
	}
}

// removeCgroupTree removes the cgroup directories under dir, and dir, deepest first; a cgroup still holding a
// process stays.
func removeCgroupTree(dir string) {
	var dirs []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = syscall.Rmdir(dirs[i])
	}
}

// daemonPID waits for the descendant's pid in the project's out/daemon.pid, and then for the descendant to be
// the sleep it execs. sh writes $$ before its exec, and that execve is held by the launcher's seccomp notifier
// until the launcher answers it: a launcher killed in between left the exec failed and sh exited, so the
// descendant was gone before any sweep and the test failed now and then.
func (c *crossOwner) daemonPID(t *testing.T, launcher *exec.Cmd) int {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	pid := 0
	for time.Now().Before(deadline) {
		if pid == 0 {
			if p, err := strconv.Atoi(strings.TrimSpace(readFileString(filepath.Join(c.f.out, "daemon.pid")))); err == nil && p > 0 {
				pid = p
				t.Cleanup(func() { _ = syscall.Kill(p, syscall.SIGKILL) })
			}
		}
		if pid != 0 && strings.TrimSpace(readFileString(fmt.Sprintf("/proc/%d/comm", pid))) == "sleep" {
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid != 0 {
		t.Fatalf("the agent's descendant %d never became sleep; the launcher said:\n%s", pid, output(launcher))
	}
	t.Fatalf("the agent's descendant never wrote its pid; the launcher said:\n%s", output(launcher))
	return 0
}

// killLauncher SIGKILLs the launcher, waits for its lock to come free, and checks that the descendant
// outlived it: otherwise the sweep has nothing to prove.
func (c *crossOwner) killLauncher(t *testing.T, launcher *exec.Cmd, dir string, pid int) {
	t.Helper()
	if err := launcher.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill launcher: %v", err)
	}
	_ = launcher.Wait()
	waitLockFree(t, dir)
	if lastKind(t, dir) == record.KindRunEnd {
		t.Fatal("a killed launcher cannot have written run_end")
	}
	if !alive(pid) {
		t.Fatalf("the descendant %d did not outlive its launcher; the test proves nothing", pid)
	}
}

// rootSweep is `sudo tego run`'s sweep of the ledger root, in this process, and the checks every
// cross-owner case ends with: the descendant is gone, the run ended orphaned, everything in its directory is
// the user's, and the user's own `events --verify` passes against the user's anchor.
func (c *crossOwner) rootSweep(t *testing.T, dir string, pid int) {
	t.Helper()
	res, err := SweepLive(context.Background(), c.f.root, WithSweepAnchor(c.anchor))
	if err != nil || res.Orphaned != 1 {
		t.Fatalf("the root sweep: %+v %v, want the run orphaned", res, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("the descendant %d survived the root sweep", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := lastReason(t, dir); got != record.RunEndOrphaned {
		t.Fatalf("run ended with %q, want orphaned", got)
	}
	t.Logf("the root sweep ended %s and killed its descendant %d", filepath.Base(dir), pid)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if owner := int(info.Sys().(*syscall.Stat_t).Uid); owner != c.uid {
			return fmt.Errorf("%s is uid %d's, not the user's %d", p, owner, c.uid)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	verify := c.command(t, true, "events", filepath.Base(dir), "--verify")
	if err := verify.Run(); err != nil {
		t.Fatalf("the user's events --verify: %v\n%s", err, output(verify))
	}
}

// TestIntegrationRootSweepEndsAUsersKilledLauncher covers the user's side: the invoking
// user's own launcher is SIGKILLed while its agent's descendant runs on, and `sudo tego`'s sweep ends the
// run. The descendant lives in the scope the user's launcher made under user@<uid>.service, which a root sweep
// found only once it looked beyond its own cgroup root; the swept run stays
// the user's and verifies against the user's anchor.
func TestIntegrationRootSweepEndsAUsersKilledLauncher(t *testing.T) {
	c := newCrossOwner(t, "ixuser")
	leaf := userLeaf(t, c.uid, c.gid)
	launcher := c.command(t, true, "run", filepath.Join(c.f.dir, "agent.yaml"), "--", "/bin/sh", "-c", daemonizing)
	launcher.SysProcAttr.UseCgroupFD, launcher.SysProcAttr.CgroupFD = true, leaf
	if err := launcher.Start(); err != nil {
		t.Fatalf("start the user's launcher: %v", err)
	}
	t.Cleanup(func() { _ = launcher.Process.Kill() })
	pid := c.daemonPID(t, launcher)
	dir := waitForStartedRun(t, c.f.root, 20*time.Second)
	c.killLauncher(t, launcher, dir, pid)
	c.rootSweep(t, dir, pid)
}

// TestIntegrationRootSweepEndsARootLauncherTheUserCannot is M3's reverse: `sudo tego run` of the user's
// project is SIGKILLed. Its run directory is root's until a Close hands it over and its scope is under the
// cgroup root, so the user's own sweep can neither read the run nor kill its tree, and leaves it as it is;
// `sudo tego`'s sweep ends it, and the run directory is then the user's and verifies against the user's
// anchor.
func TestIntegrationRootSweepEndsARootLauncherTheUserCannot(t *testing.T) {
	c := newCrossOwner(t, "ixroot")
	launcher := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"), "--", "/bin/sh", "-c", daemonizing)
	if err := launcher.Start(); err != nil {
		t.Fatalf("start the root launcher: %v", err)
	}
	t.Cleanup(func() { _ = launcher.Process.Kill() })
	pid := c.daemonPID(t, launcher)
	dir := waitForStartedRun(t, c.f.root, 20*time.Second)
	c.killLauncher(t, launcher, dir, pid)

	gc := c.command(t, true, "gc")
	_ = gc.Run()
	if lastKind(t, dir) == record.KindRunEnd {
		t.Fatalf("the user's gc wrote run_end to a root launcher's run:\n%s", output(gc))
	}
	if !alive(pid) {
		t.Fatalf("the root launcher's descendant %d is dead after the user's gc:\n%s", pid, output(gc))
	}
	c.rootSweep(t, dir, pid)
}
