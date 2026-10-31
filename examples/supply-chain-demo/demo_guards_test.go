// SPDX-License-Identifier: Apache-2.0

//go:build integration

package supplychain

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestResetRefusesWhileARunRuns: with a take's run still going, reset used to move the ledger under it, so the
// run kept writing into the moved ledger and the dashboard showed nothing. Now reset and check name the run and
// refuse; DEMO_FORCE=1 resets anyway.
func TestResetRefusesWhileARunRuns(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")

	log, err := os.Create(filepath.Join(w.base, "watch.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	cmd := exec.Command(w.bin, "watch", "--", "sleep", "60")
	cmd.Dir = filepath.Join(w.stage, "without", "proj")
	// w.envList is newWorld's testutil.TegoEnv(...): the chain anchor and tego's own log stay in the test's folder.
	cmd.Env = append(append([]string{}, w.envList...), "TEGO_CONFIG="+w.cfg)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }() // the exit status is not the test's concern, only that it ends
	// Registered after newWorld's reset --stop, so it runs first: the run ends before the world is torn down.
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) // the group may be gone already
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	})

	run := waitLiveWatch(t, w, done)
	before := dirNames(t, w.ledger)

	out, code := w.demo("reset")
	if code == 0 {
		t.Fatalf("reset went ahead with %s still running:\n%s", run, out)
	}
	mustContain(t, "reset while running", out, "still running: "+run, "1 run(s) of this demo are still running", "DEMO_FORCE=1")
	if olds, _ := filepath.Glob(w.ledger + ".old-*"); len(olds) != 0 {
		t.Errorf("the refused reset moved the ledger: %v", olds)
	}
	if after := dirNames(t, w.ledger); strings.Join(after, " ") != strings.Join(before, " ") {
		t.Errorf("the refused reset changed the ledger: %v, was %v", after, before)
	}

	out, code = w.demo("check")
	if code == 0 || strings.Contains(out, "READY") {
		t.Errorf("check passed with %s still running: exit %d\n%s", run, code, out)
	}
	mustContain(t, "check while running", out, "1 run(s) of this demo are still running ("+run+")", "fix: quit both Codex windows (/quit), then: ./demo.sh reset")

	out, code = w.demoEnv([]string{"DEMO_FORCE=1"}, "reset")
	if code != 0 {
		t.Fatalf("DEMO_FORCE=1 reset: exit %d\n%s", code, out)
	}
	mustContain(t, "forced reset", out, "warning: 1 run(s) of this demo are still running ("+run+")")
	if olds, _ := filepath.Glob(w.ledger + ".old-*"); len(olds) != 1 {
		t.Errorf("the forced reset did not move the ledger: %v", olds)
	}
}

// waitLiveWatch waits until `tego status --all --json` shows a watch-* run whose launcher holds it and returns its
// id. It fails the test when the launcher ends first or 30 s pass.
func waitLiveWatch(t *testing.T, w *world, done <-chan struct{}) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatalf("tego watch ended before it held its run:\n%s", readFile(t, filepath.Join(w.base, "watch.log")))
		default:
		}
		st := exec.Command(w.bin, "status", "--all", "--json")
		st.Env = append(append([]string{}, w.envList...), "TEGO_CONFIG="+w.cfg)
		if b, err := st.Output(); err == nil {
			var list struct {
				Runs []struct {
					Run      string `json:"run"`
					Agent    string `json:"agent"`
					LockHeld bool   `json:"lock_held"`
				} `json:"runs"`
			}
			if json.Unmarshal(b, &list) == nil {
				for _, r := range list.Runs {
					if r.LockHeld && strings.HasPrefix(r.Agent, "watch-") {
						return r.Run
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no live watch run after 30 s:\n%s", readFile(t, filepath.Join(w.base, "watch.log")))
	return ""
}

// dirNames lists a folder's entries by name, sorted (os.ReadDir's order).
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	names := make([]string, 0, len(es))
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

// TestRightRefusesAChangedContract: after a take's Never allow, right used to start on the edited contract, so
// the token read was refused without asking and the 0:15 approval never came; Codex's screen wiped any warning. Now
// right refuses before Codex starts, and DEMO_FORCE=1 starts it anyway.
func TestRightRefusesAChangedContract(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	original := readFile(t, w.filled())
	with := filepath.Join(w.stage, "with")
	token := with + "/home/.config/telemetry/"
	// what Never allow does to the file, as in TestRetakeRestoresContract
	edited := strings.Replace(original, `ask_read: ["`+token+`", `, `ask_read: [`, 1)
	edited = strings.Replace(edited, `deny_read: ["`+with+`/home/.ssh/"]`, `deny_read: ["`+with+`/home/.ssh/", "`+token+`"]`, 1)
	if edited == original {
		t.Fatalf("the test could not apply the Never allow edit to:\n%s", original)
	}
	if err := os.WriteFile(w.filled(), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := w.demo("right")
	if code == 0 {
		t.Errorf("right started on the changed contract:\n%s", out)
	}
	mustContain(t, "right on a changed contract", out, "the contract was changed (by Never allow?)", "Run ./demo.sh reset first")
	if strings.Contains(out, "stub codex ran") {
		t.Errorf("right refused but Codex ran:\n%s", out)
	}

	out, code = w.demoEnv([]string{"DEMO_FORCE=1"}, "right")
	if code != 0 {
		t.Errorf("DEMO_FORCE=1 right: exit %d\n%s", code, out)
	}
	mustContain(t, "forced right", out, "stub codex ran")
}

// TestCheckSkipsCompileOnAnUntrustedConfig: with the config's folder group-writable, check used to add "the
// filled contract does not compile: " with no reason and a reset that fixes nothing. Now it fails on the config only
// and says the contract was not compiled.
func TestCheckSkipsCompileOnAnUntrustedConfig(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	if err := os.Chmod(w.base, 0o775); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(w.base, 0o755) }()
	out, code := w.demo("check")
	if code != 1 {
		t.Errorf("check exited %d, want 1\n%s", code, out)
	}
	mustContain(t, "untrusted config", out, "is untrusted", "(the filled contract was not compiled: fix the config above first)")
	if strings.Contains(out, "does not compile") {
		t.Errorf("check blamed the contract for the config:\n%s", out)
	}
}
