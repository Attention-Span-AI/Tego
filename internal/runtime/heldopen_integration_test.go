// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationHeldCompletionAtLandlock is ADR 0041 Stage B through the real binary at tier landlock, unprivileged:
// a contract whose gate scores `fs.read matches "*.env"` and chose gate.completion: held runs with the open deputy.
// The child stage execs it in the run's Landlock domain (the exec: section restricts EXECUTE, so this needs the
// deputy's runtime exec grant), the agent's read of a benign file is held and delivered, its read of the secret is
// refused by the gate on the pinned object, the read's line carries gate_facts held_object at record_minor 10, and
// run_start's best_effort no longer lists gate.fs.read/open, the cell the deputy closed, but gate.fs.read/o_path.
func TestIntegrationHeldCompletionAtLandlock(t *testing.T) {
	bin := tegoBinary(t)
	contract := contractFor("iheld", []string{"/bin/sh", "-c",
		"cat out/benign > out/copy; cat out/secret.env > out/leak; echo done > out/done"}, []string{"/bin/sh", "/bin/cat"}) +
		"gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n"
	f := newFixture(t, contract)
	for name, body := range map[string]string{"benign": "benign-bytes", "secret.env": "TOKEN=1"} {
		if err := os.WriteFile(filepath.Join(f.out, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agentOwns(t, f.out)
	cfg := writeMachineConfig(t, f)
	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "open deputy did not start") {
		t.Fatalf("the deputy did not start:\n%s", out)
	}
	if b, err := os.ReadFile(filepath.Join(f.out, "copy")); err != nil || string(b) != "benign-bytes" {
		t.Fatalf("the held read of the benign file gave %q, %v\n%s", b, err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(f.out, "leak")); len(b) != 0 {
		t.Fatalf("the agent read the secret through a held open: %q", b)
	}
	if _, err := os.Stat(filepath.Join(f.out, "done")); err != nil {
		t.Fatalf("the agent did not run to its end: %v\n%s", err, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", f.root, dirs)
	}
	evs := events(t, dirs[0])
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.RecordMinor < record.MinorHeldObject {
		t.Errorf("run_start.record_minor = %d, want at least %d", start.RecordMinor, record.MinorHeldObject)
	}
	// With no net: section the unix-only state's datagram cell follows the gate's (ADR 0070).
	if want := []string{agent.BestEffortGateFSReadOPath, agent.BestEffortGateFSReadMove,
		agent.BestEffortHostSocketsDatagram}; !slices.Equal(start.BestEffort, want) {
		t.Errorf("run_start.best_effort = %v, want %v", start.BestEffort, want)
	}
	// The capability line says so too (ADR 0041 D7's gate fs open completion row): this run's deputy completes its
	// gate's opens on the object scored, which the row's static cell names as conditional on it.
	if !start.Capabilities[string(backend.CapGateFSOpenCompletion)] {
		t.Errorf("capabilities[%s] = false under held completion with the deputy up", backend.CapGateFSOpenCompletion)
	}
	var heldRead, refusedSecret bool
	for _, ev := range evs {
		if ev.Kind != record.KindFS {
			continue
		}
		var p struct {
			Path      string `json:"path"`
			GateFacts string `json:"gate_facts"`
		}
		_ = json.Unmarshal(ev.Payload, &p)
		switch {
		case strings.HasSuffix(p.Path, "/out/benign") && p.GateFacts == "held_object" && ev.Verdict == record.VerdictAllow:
			heldRead = true
		case strings.HasSuffix(p.Path, "/out/secret.env") && ev.Verdict == record.VerdictRefused && ev.Authority == record.AuthorityGate:
			refusedSecret = true
		}
	}
	if !heldRead || !refusedSecret {
		var lines []string
		for _, ev := range evs {
			if ev.Kind == record.KindFS {
				lines = append(lines, string(ev.Verdict)+" "+ev.Rule+" "+string(ev.Payload))
			}
		}
		t.Fatalf("held read line %t, gate refusal of the secret %t; fs lines:\n%s", heldRead, refusedSecret, strings.Join(lines, "\n"))
	}
}

// renamedEntryRun is one run of TestIntegrationHeldOpenNeverExceedsLandlock under completion: the agent waits for
// out/go, then creates new in the write entry by name; the test moves the entry's parent away and makes a new
// directory under the entry's name first, then approves the gate's ask. It returns the agent's status, the error it
// printed, whether the file appeared under the name, and the run's ledger.
func renamedEntryRun(t *testing.T, completion string) (rc, stderr string, created bool, evs []*record.Event, entry string) {
	t.Helper()
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(elsewhere, "a")
	entry = filepath.Join(parent, "w")
	if err := os.MkdirAll(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, entry)
	agentOwns(t, parent, entry)
	contract := fmt.Sprintf(`version: 0
name: iheldll
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/", %q]
exec:
  allow: ["/bin/sh", "/bin/echo", "/bin/sleep"]
net: {}
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 30s
limits:
  pids: 64
record: summary
gate:
  completion: %s
  rules:
    - fs.write outside worktree: 60
`, entry+"/", completion)
	s := &askReadScene{bin: tegoBinary(t)}
	s.f = newFixture(t, contract)
	script := "#!/bin/sh\nwhile [ ! -e out/go ]; do sleep 0.05; done\necho approved 2> out/err > \"" + entry + "/new\"; echo $? > out/rc\n"
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"))
	s.env = isolatedEnv(t, s.f)
	run, dir := s.start(t)
	// The entry's parent moves away while the run holds its agent, as any process outside the run may move it, and a
	// new directory takes the entry's name: the run's Landlock rule stays with the inode it was given (now under
	// a-old), this loop's floor with the name.
	if err := os.Rename(parent, parent+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, parent, entry)
	if err := os.WriteFile(filepath.Join(s.f.out, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	req := s.pending(t, filepath.Base(dir))
	if req["target"] != filepath.Join(entry, "new") {
		t.Fatalf("the held request %v: want the create of %s", req, filepath.Join(entry, "new"))
	}
	s.answer(t, "approve", filepath.Base(dir), req["ask_id"].(string))
	evs = s.finish(t, run, dir)
	_, err = os.Lstat(filepath.Join(entry, "new"))
	return strings.TrimSpace(s.out("rc")), s.out("err"), err == nil, evs, entry
}

// TestIntegrationHeldOpenNeverExceedsLandlock is ADR 0041 Step 8's Landlock-equivalence after a rename of a write
// entry's ancestor, through the real binary at tier landlock: the parent of a write entry moves away during the run
// and a new directory takes the entry's name. This loop's floor checks names, so the create of a file there by name is
// allowed and its gate asks a person, who approves; the run's Landlock rule followed the old inode, so the kernel
// refuses the create. Under gate.completion: held the approved open is the deputy's, in the run's domain: the agent
// gets the kernel's EACCES, no file appears, and the line is the person's allow with syscall_ret -13 and gate_facts
// held_object. Under the default the approved open runs on a supervisor thread outside the domain and creates the
// file (ADR 0041's TCB residual of ADR 0008 completions); that run is logged as the pre-fix outcome.
func TestIntegrationHeldOpenNeverExceedsLandlock(t *testing.T) {
	rc, stderr, created, _, _ := renamedEntryRun(t, "copied")
	t.Logf("completion copied (pre-fix): status %q, created %t, %q", rc, created, strings.TrimSpace(stderr))
	rc, stderr, created, evs, entry := renamedEntryRun(t, "held")
	if rc == "0" || created {
		t.Fatalf("held: the approved create under the renamed entry's name succeeded (status %q, created %t): the deputy exceeded the run's Landlock domain", rc, created)
	}
	if !strings.Contains(stderr, "Permission denied") {
		t.Errorf("held: the agent's error %q, want the kernel's EACCES", stderr)
	}
	found := false
	for _, ev := range evs {
		if ev.Kind != record.KindFS {
			continue
		}
		var p struct {
			Path       string `json:"path"`
			Flags      int    `json:"flags"`
			GateFacts  string `json:"gate_facts"`
			SyscallRet *int64 `json:"syscall_ret"`
			Completed  *bool  `json:"operation_completed"`
		}
		_ = json.Unmarshal(ev.Payload, &p)
		if p.Path != filepath.Join(entry, "new") {
			continue
		}
		if p.Flags&syscall.O_CREAT == 0 {
			// RHEL's bash is built for AFS: a redirection whose create fails EACCES is opened once more without
			// O_CREAT (bash-5.1.8-9.el9, AlmaLinux 9.8), which finds no file. That open is the shell's own, answered
			// with its own ENOENT, and must have done nothing.
			if p.SyscallRet == nil || *p.SyscallRet != -int64(syscall.ENOENT) || p.Completed == nil || *p.Completed {
				t.Errorf("held: an open of the create's path without O_CREAT %s %s %s: want the task's own ENOENT, "+
					"nothing performed", ev.Verdict, ev.Authority, ev.Payload)
			}
			t.Logf("held: the shell opened the path again without O_CREAT: %s", ev.Payload)
			continue
		}
		found = true
		if ev.Authority != record.AuthorityHuman || ev.Verdict != record.VerdictAllow || p.GateFacts != "held_object" || p.SyscallRet == nil || *p.SyscallRet != -13 {
			t.Errorf("held: the create's line %s %s %s: want the person's allow, held_object, syscall_ret -13", ev.Verdict, ev.Authority, ev.Payload)
		}
	}
	if !found {
		t.Error("held: no line for the approved create")
	}
}

// TestIntegrationKilledDeputyKeepsItsPid is findings GD-1 and F1 through the real binary at tier landlock: the agent
// (here the test, which shares its uid) can end the open deputy, a child of the launcher in the run cgroup. The run's
// reaper reaped its zombie, which freed the pid, and the kernel recorder kept dropping every record of that pid for the
// rest of the run, so a later process of the run given it would have had its records left out. Now the zombie holds
// the pid until the run reaps it at its end (launch.Child.KeepUnreaped), and the recorder names the deputy by its pid
// and start time (observe's TestRecorderKeepsARecordOfTheDeputysPidFromAnotherProcess). The agent goes on without the
// deputy (its writes are not held; a held read fails closed), and the run ends with the agent's own status.
func TestIntegrationKilledDeputyKeepsItsPid(t *testing.T) {
	bin := tegoBinary(t)
	contract := contractFor("ikilled", []string{"/bin/sh", "-c",
		"echo up > out/up; while [ ! -e out/go ]; do :; done; echo done > out/done"}, []string{"/bin/sh"}) +
		"gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n"
	f := newFixture(t, contract)
	agentOwns(t, f.out)
	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
	run.Dir = f.dir
	run.Env = isolatedEnv(t, f)
	var out strings.Builder
	run.Stdout, run.Stderr = &out, &out
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run.Wait() }()
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(f.out, "go"), nil, 0o644)
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = run.Process.Kill()
		}
	})
	waitForFile(t, filepath.Join(f.out, "up"), 20*time.Second)
	pid, start := findDeputy(t, run.Process.Pid)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill the deputy %d: %v", pid, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, st, ok := procStateStart(pid)
		if ok && state == 'Z' && st == start {
			break
		}
		if !ok || st != start || time.Now().After(deadline) {
			t.Fatalf("the killed deputy %d: state %c start %d (was %d), present %t: want its zombie, unreaped", pid, state, st, start, ok)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Four of the reaper's sweeps (launch.reapInterval, 250 ms) and its SIGCHLD wake-up: the zombie stays.
	time.Sleep(time.Second)
	if state, st, ok := procStateStart(pid); !ok || state != 'Z' || st != start {
		t.Fatalf("the killed deputy %d was reaped during the run (state %c start %d, present %t): its pid was free for a later process of the run", pid, state, st, ok)
	}
	if err := os.WriteFile(filepath.Join(f.out, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("tego run: %v\n%s", err, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the run did not end after its agent did\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(f.out, "done")); err != nil {
		t.Fatalf("the agent did not run to its end without its deputy: %v\n%s", err, out.String())
	}
	if _, st, ok := procStateStart(pid); ok && st == start {
		t.Fatalf("the deputy %d is still unreaped after its run ended", pid)
	}
}

// findDeputy returns the pid and start ticks of launcher's child running `tego __open-deputy`.
func findDeputy(t *testing.T, launcher int) (int, uint64) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || !strings.Contains(string(cmdline), deputy.Command) {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		st, err := proc.ParseStat(b)
		if err != nil || st.PPID != launcher {
			continue
		}
		return pid, st.StartTicks
	}
	t.Fatalf("no open deputy among launcher %d's children", launcher)
	return 0, 0
}

// procStateStart reads a process's state and start ticks; ok is false when it has no /proc entry.
func procStateStart(pid int) (byte, uint64, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	st, err := proc.ParseStat(b)
	if err != nil {
		return 0, 0, false
	}
	return st.State, st.StartTicks, true
}
