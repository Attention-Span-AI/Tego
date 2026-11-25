// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var (
	attackerPath string
	attackerErr  error
)

// ledgerAttackerBinary builds test/workloads/ledger-attacker once per run, where the dropped agent can run it.
func ledgerAttackerBinary(t *testing.T) string {
	t.Helper()
	if attackerPath == "" && attackerErr == nil {
		dir, err := os.MkdirTemp("", "tego-ledger-attacker-")
		if err != nil {
			t.Fatal(err)
		}
		attackerPath = filepath.Join(dir, "ledger-attacker")
		cmd := exec.Command("go", "build", "-o", attackerPath, "github.com/attention-span-ai/tego/test/workloads/ledger-attacker")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			attackerErr = fmt.Errorf("go build ledger-attacker: %v: %s", err, out)
		}
	}
	if attackerErr != nil {
		t.Fatal(attackerErr)
	}
	agentReaches(t, attackerPath)
	return attackerPath
}

// fileDigest is the sha256 of a file's bytes, and its mode.
func fileDigest(t *testing.T, path string) (string, os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), st.Mode().Perm()
}

// windowGapCounts is the count each window gap of a run's ledger carries, by its why.
func windowGapCounts(t *testing.T, evs []*record.Event) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, e := range evs {
		if e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.What == record.GapLimits && strings.HasPrefix(p.Why, "window-") {
			out[p.Why] += p.Count
		}
	}
	return out
}

// TestIntegrationAWindowHoldsAgainstItsOwnAgent is the kernel half of limits.window (ADR 0165): the count is read from the
// agent's own earlier ledgers, so a held agent that can remove, rename, truncate or edit one, or edit chain.log, could
// lower its own count. At each tier a launcher can hold a run at, and for the launcher an ordinary user and root, an
// agent runs that tries each of those on the earlier run of its own contract; every attempt is denied, the events file is
// byte for byte what it was and chain.log's earlier lines are (the agent's own run adds its one line), nothing was made in the ledger root, and the next start still counts the earlier spend and
// is ended at the window's ceiling. A second start while a run of the agent is live is refused (125 [budget-window]).
// Taking the file's mode and dates is not denied by any tier: the mode is put back by the next start of a user's launcher
// and the count never reads a date, so the restart is ended all the same.
func TestIntegrationAWindowHoldsAgainstItsOwnAgent(t *testing.T) {
	for _, v := range []struct {
		name   string
		asUser bool
		tier   string
	}{
		{"user-landlock", true, "landlock"},
		{"root-landlock", false, "landlock"},
		{"root-cgroup", false, "cgroup"},
		{"root-bpflsm", false, "bpflsm"},
	} {
		t.Run(v.name, func(t *testing.T) { windowHeldCase(t, v.asUser, v.tier) })
	}
}

func windowHeldCase(t *testing.T, asUser bool, tier string) {
	c := newCrossOwner(t, "iwheld")
	if tier != "landlock" {
		// A root tier needs the build with the BPF objects, and the machine to offer the tier: skipped only on doctor's
		// answer that it does not (a hosted runner has no BPF LSM); any other end of the probe fails.
		c.bin = tegoBPFBinary(t)
		agentReaches(t, c.bin)
		testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
	}
	agentBin := modelAgentBinary(t)
	attacker := ledgerAttackerBinary(t)
	agentReaches(t, agentBin)
	host, port, caFile := modelUpstream(t)
	if err := os.Chmod(caFile, 0o644); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, caFile)
	// tokens: 150 over a day; the model-agent answers 60 tokens a call.
	yaml := modelContract("iwheld", agentBin, host, port, "\n  tokens: 150\n  window: 24h")
	yaml = strings.Replace(yaml, "tier: landlock", "tier: "+tier, 1)
	yaml = strings.Replace(yaml, `"MODEL_DIRECT"]`, `"MODEL_DIRECT", "ATTACK_EVENTS", "ATTACK_CHAIN_LOG", "ATTACK_WINDOW_LOCK"]`, 1)
	contract := filepath.Join(c.f.dir, "agent.yaml")
	if err := os.WriteFile(contract, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, contract)
	cfg, err := os.OpenFile(c.cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(cfg, "prices: %s\n", filepath.Join(t.TempDir(), "no-prices.yaml")); err != nil {
		t.Fatal(err)
	}
	_ = cfg.Close()
	var leaf int
	if asUser {
		leaf = userLeaf(t, c.uid, c.gid)
	}

	// tegoRun starts `tego run <contract> -- <argv>` as the case's launcher and returns it, started, with its output file.
	tegoRun := func(extraEnv []string, argv ...string) *exec.Cmd {
		t.Helper()
		cmd := c.command(t, asUser, append([]string{"run", contract, "--"}, argv...)...)
		cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+caFile)
		cmd.Env = append(cmd.Env, extraEnv...)
		if asUser {
			cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, leaf
		}
		return cmd
	}
	// wait runs cmd to its end within a bound.
	wait := func(cmd *exec.Cmd, bound time.Duration) (int, string) {
		t.Helper()
		if err := cmd.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			return exitCodeOf(t, err), output(cmd)
		case <-time.After(bound):
			_ = cmd.Process.Kill()
			<-done
			t.Fatalf("a tego run did not end within %s:\n%s", bound, output(cmd))
			return -1, ""
		}
	}
	planted := ""
	runDir := func(n int) string {
		t.Helper()
		var dirs []string
		for _, d := range runDirs(t, c.f.root) {
			if filepath.Base(d) != planted {
				dirs = append(dirs, d)
			}
		}
		if len(dirs) != n {
			t.Fatalf("run directories %v, want %d", dirs, n)
		}
		return dirs[len(dirs)-1]
	}

	// 1. The first run: two calls, 120 tokens, under the ceiling.
	code, out := wait(tegoRun([]string{"MODEL_CALLS=2"}, agentBin), 5*time.Minute)
	if code != 0 {
		t.Fatalf("the first run exited %d, want 0\n%s", code, out)
	}
	firstDir := runDir(1)
	eventsPath := filepath.Join(firstDir, ledger.EventsFile)
	evSum, _ := fileDigest(t, eventsPath)
	chainBefore, err := os.ReadFile(c.anchor)
	if err != nil {
		t.Fatal(err)
	}

	// A run directory another account owns, which this launcher cannot open, must not stand in the way of the agent's
	// start: it is left out and the run says so. Only the user's launcher meets one it cannot read (root reads all).
	// Its name is a run id this host minted (the first run's, with another random tail): the count leaves out the runs
	// another host minted without opening them, so a made-up host would never be met.
	if asUser {
		first := filepath.Base(firstDir)
		planted = first[:len(first)-6] + "zzzzzz"
		if planted == first || !ledger.IsRunID(planted) || foreignRun(planted) {
			t.Fatalf("the planted name %q is not a run id this host minted (the first run's is %q): the count would never open it", planted, first)
		}
		pd := filepath.Join(c.f.root, planted)
		if err := os.Mkdir(pd, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pd, ledger.EventsFile), []byte("{\"not\":\"a run_start of anyone's\"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Both stay root's. The control: the launcher's own credential, outside tego, cannot read the file, and the
		// directory is root's, so the refusal is another account's and not this account's own.
		ctl := exec.Command("/bin/cat", filepath.Join(pd, ledger.EventsFile))
		ctl.SysProcAttr = c.command(t, true).SysProcAttr
		if cout, err := ctl.CombinedOutput(); err == nil || !strings.Contains(string(cout), "Permission denied") {
			t.Fatalf("control: the user's credential reading the planted run's events file: err %v, %q; want permission denied", err, cout)
		}
		var st unix.Stat_t
		if err := unix.Lstat(pd, &st); err != nil || st.Uid != 0 {
			t.Fatalf("control: the planted directory is owned by uid %d (%v), want root's", st.Uid, err)
		}
	}

	// 2. The agent attacks that run's record and chain.log, and takes the mode of its own window lock, whose name follows
	// from its identity.
	locks, _ := filepath.Glob(filepath.Join(c.f.root, ".window-*.lock"))
	if len(locks) != 1 {
		t.Fatalf("window locks %v after the first run, want the agent's one", locks)
	}
	lockPath := locks[0]
	code, out = wait(tegoRun([]string{"ATTACK_EVENTS=" + eventsPath, "ATTACK_CHAIN_LOG=" + c.anchor, "ATTACK_WINDOW_LOCK=" + lockPath}, attacker), 5*time.Minute)
	if code != 0 {
		t.Fatalf("the attacker's run exited %d, want 0\n%s", code, out)
	}
	if asUser {
		if g := windowGapCounts(t, events(t, runDir(2))); g["window-unattributed"] != 1 {
			t.Fatalf("the run that started beside another account's unreadable run directory says %v, want one window-unattributed", g)
		}
	}
	attempts := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) == 3 && f[0] == "ATTEMPT":
			attempts[f[1]] = f[2]
		case len(f) == 3 && f[0] == "CONTROL":
			if f[2] != "OK" {
				t.Fatalf("control %s = %s: the attack did not reach what it attacks, or could not write where it may\n%s", f[1], f[2], out)
			}
			attempts["control:"+f[1]] = f[2]
		}
	}
	for _, name := range []string{"control:write-out", "control:stat-events", "control:stat-chain", "control:stat-lock", "control:allowed-unlink", "control:allowed-rename",
		"control:allowed-truncate", "control:allowed-open-trunc", "control:allowed-append"} {
		if attempts[name] != "OK" {
			t.Fatalf("no passing %s in the attacker's output:\n%s", name, out)
		}
	}
	for _, name := range []string{"unlink-events", "rename-events", "rename-run-dir", "rmdir-run-dir", "truncate-events", "open-trunc-events",
		"append-events", "unlink-chain", "rename-chain", "truncate-chain", "append-chain", "create-in-root", "mkdir-decoy-run"} {
		switch got := attempts[name]; got {
		case "EACCES", "EPERM", "EROFS":
		default:
			t.Errorf("tier %s as %s: %s answered %q, want a denial\n%s", tier, map[bool]string{true: "user", false: "root"}[asUser], name, got, out)
		}
	}
	t.Logf("attempts: tier=%s launcher=%s %v", tier, map[bool]string{true: "user", false: "root"}[asUser], attempts)
	t.Logf("tier %s: chmod-events %s, utimes-events %s (not denied by a tier; the count reads neither)", tier, attempts["chmod-events"], attempts["utimes-events"])
	if got, _ := fileDigest(t, eventsPath); got != evSum {
		t.Fatalf("the earlier run's events.jsonl changed under the attack")
	}
	// The user's agent owns its lock and no tier denies chmod: the mode is taken (the control that the attack landed),
	// and the next start of that agent, which must open the lock, restores it and starts. Root reads any mode.
	lockSt, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("the window lock after the attack: %v", err)
	}
	if asUser && (attempts["chmod-window-lock"] != "OK" || lockSt.Mode().Perm() != 0) {
		t.Fatalf("the user's agent took its window lock's mode: chmod answered %q, the lock is now %o, want OK and 0",
			attempts["chmod-window-lock"], lockSt.Mode().Perm())
	}
	t.Logf("tier %s: chmod-window-lock %s, the lock is %o", tier, attempts["chmod-window-lock"], lockSt.Mode().Perm())
	// chain.log is not byte for byte what it was: the attacker's own run ended and appended its line, as every run does.
	// What the attack could have changed is what was there: those bytes are the same, and what follows is that one line.
	chainAfter, err := os.ReadFile(c.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(chainAfter, chainBefore) {
		t.Fatalf("chain.log's earlier lines changed under the attack:\nbefore %q\nafter  %q", chainBefore, chainAfter)
	}
	if added := strings.Fields(string(chainAfter[len(chainBefore):])); len(added) != 2 || added[0] != filepath.Base(runDir(2)) {
		t.Fatalf("chain.log gained %q after the attacker's run, want one line, that run's (%s)", chainAfter[len(chainBefore):], filepath.Base(runDir(2)))
	}
	var names []string
	ents, err := os.ReadDir(c.f.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		if strings.Contains(n, "decoy") || strings.HasSuffix(n, ".moved") {
			t.Fatalf("the attack left %q in the ledger root: %v", n, names)
		}
	}
	if _, err := os.Stat(eventsPath + ".moved"); err == nil {
		t.Fatal("the events file was moved")
	}

	// 3. A restart is ended at its first response: the earlier spend is counted, the attack changed nothing, and a mode
	// the attack took is no way to a fresh budget.
	code, out = wait(tegoRun([]string{"MODEL_CALLS=" + strconv.Itoa(loopCalls)}, agentBin), 5*time.Minute)
	dir := runDir(3)
	evs := events(t, dir)
	lim := assertStoppedBy(t, code, out, evs, record.LimitTokens)
	if lim.Ceiling != 150 || lim.Value < 180 {
		t.Fatalf("limit %+v, want tokens at 180 or more over 150: the earlier run was not counted after the attack", lim)
	}
	if n := responsesBeforeLimit(evs); n > 2 {
		t.Fatalf("%d responses were recorded before the restart's limit: without the carried spend it would have taken three to cross", n)
	}
	if _, mode := fileDigest(t, lockPath); asUser && mode&0o600 != 0o600 {
		t.Fatalf("the window lock is %o after the restart: the user's start puts the owner's rights back, or it was refused", mode)
	}
	if g := windowGapCounts(t, evs); g["window-carried"] < 1 {
		t.Fatalf("the restart's ledger says nothing of the runs it counted: %v", g)
	}
	if _, mode := fileDigest(t, eventsPath); asUser && mode&0o600 != 0o600 {
		t.Fatalf("the user's launcher left the events file at mode %o after counting it: its start puts the owner's rights back", mode)
	}

	// 4. A second start while a run of the agent is live is refused. A run of /bin/sleep holds the agent's window.
	live := tegoRun(nil, "/bin/sleep", "120")
	if err := live.Start(); err != nil {
		t.Fatalf("start the live run: %v", err)
	}
	liveDone := make(chan struct{})
	go func() { _ = live.Wait(); close(liveDone) }()
	t.Cleanup(func() {
		_ = live.Process.Kill()
		<-liveDone
	})
	held := false
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline) && !held; time.Sleep(200 * time.Millisecond) {
		locks, _ := filepath.Glob(filepath.Join(c.f.root, ".window-*.lock"))
		for _, l := range locks {
			f, err := os.OpenFile(l, os.O_RDWR, 0)
			if err != nil {
				continue
			}
			if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) {
				held = true
			} else if err == nil {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			}
			_ = f.Close()
		}
	}
	if !held {
		t.Fatalf("the live run never took the agent's window lock:\n%s", output(live))
	}
	code, out = wait(tegoRun([]string{"MODEL_CALLS=1"}, agentBin), 5*time.Minute)
	if code != identity.ExitLauncher || !strings.Contains(out, "budget-window") {
		t.Fatalf("a second start of the agent exited %d, want %d [budget-window]\n%s", code, identity.ExitLauncher, out)
	}
	_ = live.Process.Signal(syscall.SIGTERM)
	select {
	case <-liveDone:
	case <-time.After(60 * time.Second):
		t.Fatalf("the live run did not stop on SIGTERM:\n%s", output(live))
	}
}
