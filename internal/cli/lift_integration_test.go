// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// envTestLiveAnyTier is internal/runtime's EnvTestLiveAnyTier, which only a tegotesthooks build of that package
// declares while this file builds with integration alone. Misspelled, the launcher refuses the Adjustable start at
// tier landlock and the test fails; it cannot pass without it.
const envTestLiveAnyTier = "TEGO_TEST_LIVE_ANY_TIER"

// TestIntegrationLiftGrantRestoreOnALiveLauncher holds ADR 0125's terminal commands to the launcher that applies
// them, both the built binary: an Adjustable run at tier landlock (TEGO_TEST_LIVE_ANY_TIER, a test build's hook; the
// product keeps Adjustable to the root tiers) loops over a read of a folder its contract refuses and a run of a
// program its contract does not grant, its fence listing both, and `tego lift --for 1m`, `tego grant` and `tego
// restore` change them while it runs. Each command takes its answer from the launcher's own line for its change, so
// its first line says lifted, granted or restored, never asked, and a timed lift says the limit the launcher took;
// the agent's next read or run follows each change; and the run's ledger holds the launcher's live-rule-lifted and
// live-rule-restored lines for the CLI's changes, numbered by their overlay serials, under the fence entries' rules.
// A change outside the fence is refused before it is asked. The unit tests (lift_test.go) hold the CLI to stand-in
// lines, and internal/runtime's TestIntegrationAdjustableFenceLiftAndRestore holds the launcher to overlay writes of
// its own; only here does the CLI meet the launcher.
func TestIntegrationLiftGrantRestoreOnALiveLauncher(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root (sudo) the agent runs as the invoking user, who cannot reach the test's private directories; " +
			"the unprivileged integration step runs it")
	}
	bin := buildTegoBinary(t)
	w, err := filepath.EvalSymlinks(t.TempDir()) // the fence names resolved paths; a link would fail compile
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(w, 0o700); err != nil { // the machine config's directory must not be group-writable (umask 002)
		t.Fatal(err)
	}
	// The ledger root is a directory of its own, outside the project, HOME and every write entry: compile read-denies
	// it, which an Adjustable run needs before it starts, since its run directory holds the run's key (runDirDenied).
	root, home, proj := filepath.Join(w, "runs"), filepath.Join(w, "home"), filepath.Join(w, "proj")
	vault, tools := filepath.Join(w, "vault"), filepath.Join(w, "tools")
	out := filepath.Join(proj, "out")
	for _, d := range []string{root, home, out, vault, tools} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret, tool := filepath.Join(vault, "token"), filepath.Join(tools, "hello")
	if err := os.WriteFile(secret, []byte("lifted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(w, "machine.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", root)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.TegoEnv(t, w, "TEGO_CONFIG="+cfg, "HOME="+home, envTestLiveAnyTier+"=1")
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")

	allow := []string{`"/bin/sh"`}
	progs := map[string]string{}
	for _, name := range []string{"sh", "cat", "sleep"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("no %s: %v", name, err)
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{fmt.Sprintf("%q", p), fmt.Sprintf("%q", real)} {
			if !slices.Contains(allow, q) {
				allow = append(allow, q)
			}
		}
		progs[name] = p
	}
	// No tier: line, since compile refuses Adjustable under a pinned landlock; as a user the run lands there by itself,
	// where only the hook lets it start. The read entry is one of the contract's refusals (lift), the exec entry access
	// the contract does not have (grant).
	contract := fmt.Sprintf(`version: 0
name: ilift
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/"]
  deny_read: [%q]
exec:
  allow: [%s]
net: {}
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
live:
  mode: adjustable
  fence:
    read: [%q]
    exec: [%q]
`, vault, strings.Join(allow, ", "), vault, tool)
	if err := os.WriteFile(filepath.Join(proj, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	// The agent says after each try whether its read of the secret and its run of the tool went through. It stops on
	// out/stop, and after 3000 rounds (five minutes at least) should the test not get to write that.
	script := "#!/bin/sh\nn=0\n" +
		"while [ ! -e out/stop ] && [ \"$n\" -lt 3000 ]; do\n" +
		"  n=$((n + 1))\n" +
		"  if \"" + progs["cat"] + "\" \"" + secret + "\" >out/got 2>out/err; then echo ok >out/read; else echo refused >out/read; fi\n" +
		"  if \"" + tool + "\" >out/xout 2>&1; then echo ok >out/exec; else echo refused >out/exec; fi\n" +
		"  \"" + progs["sleep"] + "\" 0.1\n" +
		"done\n"
	if err := os.WriteFile(filepath.Join(proj, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	said := &lockedBuffer{}
	run := exec.Command(bin, "run", "agent.yaml", "--", "/bin/sh", "./agent.sh")
	run.Dir, run.Env = proj, env
	run.Stdout, run.Stderr = said, said
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	var runErr error
	go func() { runErr = run.Wait(); close(ended) }()
	t.Cleanup(func() {
		select {
		case <-ended:
		default:
			_ = os.WriteFile(filepath.Join(out, "stop"), nil, 0o600) // best effort: the loop ends at its next round
			select {
			case <-ended:
			case <-time.After(30 * time.Second):
				_ = run.Process.Kill() // the process is ours; its error says only that it already ended
				<-ended
			}
		}
		if t.Failed() {
			t.Logf("tego run said:\n%s", said.String())
		}
	})
	dir := awaitAdjustableRun(t, root, ended)
	id := filepath.Base(dir)
	if start, _ := runStartIn(dir); start.Tier != "landlock" || start.LiveFence == nil || len(start.LiveFence.Entries) != 2 {
		t.Fatalf("run_start tier %q, live_fence %+v: want an Adjustable run at tier landlock fencing two entries", start.Tier, start.LiveFence)
	}

	// says waits until the agent's file says want, read twice 300 ms apart: a try already under way when a change
	// landed may still write the state from before it.
	says := func(name, want string) {
		t.Helper()
		read := func() string {
			b, _ := os.ReadFile(filepath.Join(out, name)) // not written yet reads as "", which is no state
			return strings.TrimSpace(string(b))
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			select {
			case <-ended:
				t.Fatalf("the run ended (%v) while its agent's %s was to say %q", runErr, name, want)
			default:
			}
			if read() == want {
				time.Sleep(300 * time.Millisecond)
				if read() == want {
					return
				}
			}
		}
		t.Fatalf("the agent's %s never said %q (it says %q)", name, want, read())
	}
	tego := func(args ...string) (code int, stdout, stderr string) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		var o, e strings.Builder
		cmd.Stdout, cmd.Stderr = &o, &e
		err := cmd.Run()
		var exit *exec.ExitError
		switch {
		case errors.As(err, &exit):
			code = exit.ExitCode()
		case err != nil:
			t.Fatalf("tego %v: %v", args, err)
		}
		return code, o.String(), e.String()
	}
	// answer is the two lines lift, grant and restore end with: "<run>: <word> live.fence[<kind>:<value>]" and what
	// holds from now on.
	answer := func(stdout string) (first, second string) {
		lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
		if len(lines) < 2 {
			return stdout, ""
		}
		return lines[len(lines)-2], lines[len(lines)-1]
	}
	// serial is the serial of the overlay's last change, 0 while no change made one.
	serial := func() uint64 {
		t.Helper()
		o, err := liveblock.Read(dir, id)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return 0
		case err != nil:
			t.Fatalf("the run's overlay: %v", err)
		}
		return o.Serial
	}
	var serials []uint64 // the serial of each change the CLI asked, in order
	asked := func() {
		t.Helper()
		s := serial()
		if len(serials) > 0 && s <= serials[len(serials)-1] {
			t.Fatalf("the overlay's serial %d after a change, %d before it", s, serials[len(serials)-1])
		}
		serials = append(serials, s)
	}
	says("read", "refused")
	says("exec", "refused")

	// Outside the fence: refused before anything is asked.
	was := serial()
	code, stdout, stderr := tego("grant", id, "net", "evil.example:443", "--yes")
	if code != identity.ExitFinding || stdout != "" || !strings.Contains(stderr, "is outside "+id+"'s fence") ||
		!strings.Contains(stderr, "[outside-fence]") {
		t.Errorf("grant outside the fence: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if now := serial(); now != was {
		t.Errorf("a change outside the fence was written to the overlay: serial %d, %d before", now, was)
	}

	rule := liveblock.FenceRule(liveblock.KindRead, vault)
	before := time.Now()
	code, stdout, stderr = tego("lift", id, "read", vault, "--for", "1m", "--yes")
	after := time.Now()
	first, second := answer(stdout)
	if code != identity.ExitOK || stderr != "" ||
		!strings.HasPrefix(stdout, "Lift "+rule+" on run "+id+" (one of the contract's refusals, which its fence lets you lift)\n") ||
		first != id+": lifted "+rule || !strings.HasPrefix(second, "In force now, until ") ||
		!strings.HasSuffix(second, "; then it is refused again (live-lift-expired).") {
		t.Fatalf("lift --for 1m: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	asked()
	says("read", "ok")
	// Each round truncates out/got before cat writes it, so one look can fall between the two: poll for the secret.
	gave := ""
	for deadline := time.Now().Add(5 * time.Second); gave != "lifted\n" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		b, _ := os.ReadFile(filepath.Join(out, "got")) // "" between the truncation and cat's write
		gave = string(b)
	}
	if gave != "lifted\n" {
		t.Errorf("the lifted read gave %q", gave)
	}
	says("exec", "refused") // a lift is of its one entry

	const refusedAgain = "Refused again from the agent's next action; what it already read or opened stays.\n"
	code, stdout, stderr = tego("restore", id, "read", vault)
	if want := id + ": restored " + rule + "\n" + refusedAgain; code != identity.ExitOK || stdout != want || stderr != "" {
		t.Fatalf("restore of the lift: exit %d stdout %q stderr %q, want stdout %q", code, stdout, stderr, want)
	}
	asked()
	says("read", "refused")

	xrule := liveblock.FenceRule(liveblock.KindExec, tool)
	code, stdout, stderr = tego("grant", id, "exec", tool, "--yes")
	first, second = answer(stdout)
	if code != identity.ExitOK || stderr != "" ||
		!strings.HasPrefix(stdout, "Grant "+xrule+" on run "+id+" (access the contract does not have, which its fence lets you grant)\n") ||
		first != id+": granted "+xrule || second != "In force now, for the rest of the run (tego restore "+id+" exec "+tool+" refuses it again)." {
		t.Fatalf("grant: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	asked()
	says("exec", "ok")
	says("read", "refused")

	code, stdout, stderr = tego("restore", id, "exec", tool)
	if want := id + ": restored " + xrule + "\n" + refusedAgain; code != identity.ExitOK || stdout != want || stderr != "" {
		t.Fatalf("restore of the grant: exit %d stdout %q stderr %q, want stdout %q", code, stdout, stderr, want)
	}
	asked()
	says("exec", "refused")

	if err := os.WriteFile(filepath.Join(out, "stop"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(60 * time.Second):
		t.Fatal("the run did not end once its agent was told to stop")
	}
	if runErr != nil {
		t.Fatalf("tego run: %v", runErr)
	}

	// The launcher's lines, one per change, in the order asked: each numbered by its change's serial, by the CLI, under
	// the fence entry's rule; the timed lift's with the limit the CLI asked, a minute from when it asked.
	want := []struct {
		why, op, rule string
		kind          liveblock.Kind
		value         string
	}{
		{record.GapLiveRuleLifted, record.LiveOpLift, rule, liveblock.KindRead, vault},
		{record.GapLiveRuleRestored, record.LiveOpRestore, rule, liveblock.KindRead, vault},
		{record.GapLiveRuleLifted, record.LiveOpLift, xrule, liveblock.KindExec, tool},
		{record.GapLiveRuleRestored, record.LiveOpRestore, xrule, liveblock.KindExec, tool},
	}
	got := liveLines(t, dir)
	if len(got) != len(want) {
		t.Fatalf("the launcher's live lines %+v, want %d: lifted and restored, twice", got, len(want))
	}
	for i, exp := range want {
		g := got[i]
		c := g.LiveBlock
		if g.What != record.GapEnforce || g.Why != exp.why || c.Op != exp.op || c.Kind != string(exp.kind) ||
			c.Value != exp.value || c.Rule != exp.rule || c.Serial != serials[i] ||
			!strings.HasPrefix(c.By, fmt.Sprintf("uid:%d ", os.Getuid())) || !strings.HasSuffix(c.By, " cli") || c.Refused != "" {
			t.Errorf("live line %d: %s %s %+v, want %s %s %s:%s under %s, serial %d, by the cli", i, g.What, g.Why, *c,
				exp.why, exp.op, exp.kind, exp.value, exp.rule, serials[i])
		}
		switch {
		case i == 0 && (c.Until.Before(before.Add(time.Minute-time.Second)) || c.Until.After(after.Add(time.Minute+time.Second))):
			t.Errorf("the timed lift's line ends %s, want a minute after %s to %s", c.Until, before, after)
		case i > 0 && !c.Until.IsZero():
			t.Errorf("live line %d ends %s, want no limit", i, c.Until)
		}
	}
}

// awaitAdjustableRun is the directory of the run under root once its launcher holds the run's lock and its ledger
// starts with run_start in Adjustable mode. The test fails when the launcher ends first (ended is closed) or no run
// starts within a minute.
func awaitAdjustableRun(t *testing.T, root string, ended <-chan struct{}) string {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		select {
		case <-ended:
			t.Fatalf("tego run ended before an Adjustable run started under %s", root)
		default:
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			dir := filepath.Join(root, e.Name())
			if !e.IsDir() || !ledger.IsRunID(e.Name()) {
				continue
			}
			if held, _, err := runlock.ProbeLock(dir); err != nil || !held {
				continue
			}
			if start, ok := runStartIn(dir); ok {
				if start.LiveMode != record.LiveModeAdjustable {
					t.Fatalf("run %s started with live_mode %q, want %q", e.Name(), start.LiveMode, record.LiveModeAdjustable)
				}
				return dir
			}
		}
	}
	t.Fatalf("no run started under %s within a minute", root)
	return ""
}

// runStartIn is the run_start payload the ledger in dir starts with; ok false while there is none.
func runStartIn(dir string) (p record.RunStartPayload, ok bool) {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return p, false
	}
	defer func() { _ = rd.Close() }() // read-only
	for e, err := range rd.Iter() {
		if err != nil || e.Kind != record.KindRunStart || e.DecodePayload(&p) != nil {
			return record.RunStartPayload{}, false
		}
		return p, true
	}
	return p, false
}

// liveLines are the gap lines of the run's ledger in dir that carry a live block change, in order.
func liveLines(t *testing.T, dir string) []record.GapPayload {
	t.Helper()
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }() // read-only
	var lines []record.GapPayload
	for e, err := range rd.Iter() {
		if err != nil {
			t.Fatalf("the run's ledger: %v", err)
		}
		var p record.GapPayload
		if e.Kind != record.KindGap || e.DecodePayload(&p) != nil || p.LiveBlock == nil {
			continue
		}
		lines = append(lines, p)
	}
	return lines
}
