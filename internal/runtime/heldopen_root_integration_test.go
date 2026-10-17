// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationHeldCompletionAtRootTier is ADR 0041 Stage B at the root tiers from a root launcher, the agent
// dropped to the invoking user, at tier cgroup and, where the kernel offers it, tier bpflsm: the open deputy is
// exec'd with the agent's uid, gid and groups in the run cgroup; its held read of the user's benign file is delivered
// and the secret refused on the pinned object; a read the gate asks about is held for a person, approved with `tego
// approve`, then opened by the deputy; and while the run holds its agent, `tego status` and `tego stop` work on it.
// The commands run as root, the owner of a root launcher's run until its Close hands the directory to the user (the
// user's own cannot read a live root run, TestIntegrationRootSweepEndsARootLauncherTheUserCannot). Before Stage B an
// approved held open ran on a supervisor thread that took the agent's credentials (sys.RunAs), which leaves the whole
// root launcher not dumpable; the deputy makes no such change in the launcher. Each action is one line (supervisor
// R7a): the kernel recorder writes none for the deputy's opens.
func TestIntegrationHeldCompletionAtRootTier(t *testing.T) {
	c := newCrossOwner(t, "irootheld")
	// The root tiers load the embedded BPF objects: this case's tego is built with them (the guest's go shim serves
	// that variant for the tegobpf tag), not tegoBinary's product-only build.
	bin := filepath.Join(t.TempDir(), "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build tego with the BPF objects: %v\n%s", err, out)
	}
	agentReaches(t, bin)
	c.bin = bin
	// The probe takes the case's own isolation (its machine config and anchors), as every command of the case does:
	// a test build of tego refuses a machine config that reaches the invoking user's ~/.tego.
	// Skipped only on doctor's answer that the machine lacks the tier; any other end of the probe fails the test.
	testutil.RequireTier(t, c.doctorRequire(t, "cgroup"), "cgroup")
	t.Run("cgroup", func(t *testing.T) { heldAtRootTier(t, c, "cgroup") })
	t.Run("bpflsm", func(t *testing.T) {
		testutil.RequireTier(t, c.doctorRequire(t, "bpflsm"), "bpflsm")
		heldAtRootTier(t, c, "bpflsm")
	})
}

// doctorRequire is the case's `tego doctor --require tier`, with the case's isolation and its output left for
// testutil.RequireTier to collect.
func (c *crossOwner) doctorRequire(t *testing.T, tier string) *exec.Cmd {
	t.Helper()
	cmd := c.command(t, false, "doctor", "--require", tier)
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd
}

// heldAtRootTier is one tier's run of TestIntegrationHeldCompletionAtRootTier, in a ledger root of its own.
func heldAtRootTier(t *testing.T, c *crossOwner, tier string) {
	t.Helper()
	before := len(runDirs(t, c.f.root))
	out := filepath.Join(c.f.out, tier)
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	sub := "out/" + tier + "/"
	contract := strings.Replace(contractFor("irootheld", []string{"/bin/sh", "-c",
		"cat " + sub + "benign > " + sub + "copy; cat " + sub + "secret.env > " + sub + "leak; cat " + sub + "asked.txt > " + sub +
			"answer; touch " + sub + "ready; sleep 30"},
		[]string{"/bin/sh", "/bin/cat", "/bin/sleep", "/bin/touch"}), "tier: landlock\n", "tier: "+tier+"\n", 1) +
		"ask:\n  timeout: 60s\n" +
		"gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n    - 'fs.read matches \"asked.txt\"': 60\n"
	if err := os.WriteFile(filepath.Join(c.f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"benign": "benign-bytes", "secret.env": "TOKEN=1", "asked.txt": "asked-bytes"} {
		p := filepath.Join(out, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, p)
	}
	agentOwns(t, out)
	run := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"))
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	// done is closed once the run has been waited for, so every receive below and the cleanup's see it.
	var runErr error
	done := make(chan struct{})
	go func() { runErr = run.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = run.Process.Kill()
		<-done
	})
	ended := func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	// The run's directory, then the one request it holds: the read of asked.txt, which is approved with
	// tego approve.
	var dir string
	for deadline := time.Now().Add(60 * time.Second); dir == ""; time.Sleep(50 * time.Millisecond) {
		if dirs := runDirs(t, c.f.root); len(dirs) > before {
			dir = dirs[len(dirs)-1]
		}
		if ended() {
			t.Fatalf("the run ended before it started: %v\n%s", runErr, output(run))
		}
		if time.Now().After(deadline) {
			t.Fatalf("no run directory within 60 s:\n%s", output(run))
		}
	}
	id := filepath.Base(dir)
	askID := ""
	for deadline := time.Now().Add(60 * time.Second); askID == ""; time.Sleep(100 * time.Millisecond) {
		list := c.command(t, false, "ask", id, "--json")
		if list.Run() == nil {
			var l struct {
				Pending []struct {
					AskID  string `json:"ask_id"`
					Target string `json:"target"`
				} `json:"pending"`
			}
			if json.Unmarshal([]byte(output(list)), &l) == nil && len(l.Pending) == 1 {
				askID = l.Pending[0].AskID
			}
		}
		if ended() {
			t.Fatalf("the run ended before its ask was held: %v\n%s", runErr, output(run))
		}
		if time.Now().After(deadline) {
			t.Fatalf("no request held within 60 s (tego ask said %q):\n%s", output(list), output(run))
		}
	}
	approve := c.command(t, false, "approve", id, askID)
	if err := approve.Run(); err != nil {
		t.Fatalf("tego approve of a held-completion run: %v\n%s", err, output(approve))
	}
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(out, "ready")); err == nil {
			break
		}
		if ended() {
			t.Fatalf("the run ended before the agent was ready: %v\n%s", runErr, output(run))
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent was not ready within 60 s:\n%s", output(run))
		}
	}
	status := c.command(t, false, "status", id, "--json")
	if err := status.Run(); err != nil {
		t.Fatalf("tego status of a held-completion run: %v\n%s", err, output(status))
	}
	var snap struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(output(status)), &snap); err != nil || snap.State != "running" {
		t.Fatalf("status %q (%v), want the running run", output(status), err)
	}
	stop := c.command(t, false, "stop", id)
	if err := stop.Run(); err != nil {
		t.Fatalf("tego stop: %v\n%s", err, output(stop))
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("the run did not end within 60 s of tego stop:\n%s", output(run))
	}
	if b, err := os.ReadFile(filepath.Join(out, "copy")); err != nil || string(b) != "benign-bytes" {
		t.Fatalf("held read at tier %s gave %q, %v\n%s", tier, b, err, output(run))
	}
	if b, _ := os.ReadFile(filepath.Join(out, "leak")); len(b) != 0 {
		t.Fatalf("the agent read the secret: %q", b)
	}
	if b, err := os.ReadFile(filepath.Join(out, "answer")); err != nil || string(b) != "asked-bytes" {
		t.Fatalf("the approved read at tier %s gave %q, %v\n%s", tier, b, err, output(run))
	}
	// One line per action at a root tier (supervisor R7a): the benign read's is the supervisor's held_object line,
	// the approved read's the person's, and the kernel recorder writes none for the deputy's opens of them.
	held, approved, benignLines, askedLines := false, false, 0, 0
	for _, ev := range events(t, dir) {
		if ev.Kind != record.KindFS {
			continue
		}
		var p struct {
			Path      string `json:"path"`
			GateFacts string `json:"gate_facts"`
		}
		_ = json.Unmarshal(ev.Payload, &p)
		switch {
		case strings.HasSuffix(p.Path, "/"+sub+"benign"):
			benignLines++
			held = held || ev.Verdict == record.VerdictAllow && p.GateFacts == "held_object" && ev.Source == record.SourceSeccomp
		case strings.HasSuffix(p.Path, "/"+sub+"asked.txt"):
			askedLines++
			approved = approved || ev.Verdict == record.VerdictAllow && ev.Authority == record.AuthorityHuman && p.GateFacts == "held_object"
		}
	}
	if !held || benignLines != 1 || !approved || askedLines != 1 {
		t.Fatalf("tier %s: benign read held_object line %t of %d lines, approved read human line %t of %d lines; want one each:\n%s",
			tier, held, benignLines, approved, askedLines, output(run))
	}
}
