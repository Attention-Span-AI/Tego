// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationHeldReadsAtRootTier is ADR 0069's fs.reads: held at the root tiers from a root launcher, the agent
// dropped to the invoking user, at tier cgroup and, where the kernel offers it, tier bpflsm: the root tiers' kernel
// refuses a nested target itself, but no ruleset row or plane row names a file made during the run, so a contract that
// asks for held reads gets the open deputy there too. A .env.local a process outside the run makes once the run has
// started is refused by the built-in name rule on the object the deputy reached, a benign file reads, and run_start
// says held by the contract with the created_later capability row true.
func TestIntegrationHeldReadsAtRootTier(t *testing.T) {
	c := newCrossOwner(t, "irootheldreads")
	// The root tiers load the embedded BPF objects (TestIntegrationHeldCompletionAtRootTier's build).
	bin := filepath.Join(t.TempDir(), "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build tego with the BPF objects: %v\n%s", err, out)
	}
	agentReaches(t, bin)
	c.bin = bin
	testutil.RequireTier(t, c.doctorRequire(t, "cgroup"), "cgroup")
	t.Run("cgroup", func(t *testing.T) {
		heldReadsAtRootTier(t, c, "cgroup")
		heldReadsOPathAtRootTier(t, c, "cgroup")
	})
	t.Run("bpflsm", func(t *testing.T) {
		testutil.RequireTier(t, c.doctorRequire(t, "bpflsm"), "bpflsm")
		heldReadsAtRootTier(t, c, "bpflsm")
		heldReadsOPathAtRootTier(t, c, "bpflsm")
	})
}

// heldReadsOPathAtRootTier on the kernel, in out/<tier>-opath/: under fs.reads: held and record: full
// the filter notifies an O_PATH open, which no hook of the tier sees (the plane's file_open, fanotify's permission
// event and the kernel recorder's fexit/security_file_open all run after do_dentry_open's O_PATH return). The open of
// a file and of the directory beneath a deny_read nested in the write entry succeeds, and each has exactly one line,
// this loop's: allow by the entry with the O_PATH marker, from seccomp. Before, the line said refused, or, with the
// kernel recorder reading, was handed to a recorder that never wrote it. A cat of the file is still refused.
func heldReadsOPathAtRootTier(t *testing.T, c *crossOwner, tier string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3 to make an O_PATH open: %v", err)
	}
	pyReal, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	before := len(runDirs(t, c.f.root))
	out := filepath.Join(c.f.out, tier+"-opath")
	secret := filepath.Join(out, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(secret, "key")
	if err := os.WriteFile(key, []byte(heldReadsSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, out, secret, key)
	sub := "out/" + tier + "-opath/"
	script := python + " -c 'import os; os.open(\"" + sub + "secret/key\", os.O_PATH); os.open(\"" + sub +
		"secret\", os.O_PATH | os.O_DIRECTORY)' 2> " + sub + "perr; echo $? > " + sub + "prc; cat " + sub + "secret/key > " +
		sub + "leak 2> " + sub + "err; touch " + sub + "done"
	allow := []string{"/bin/sh", "/bin/cat", "/bin/touch", python}
	if pyReal != python {
		allow = append(allow, pyReal)
	}
	contract := strings.Replace(contractFor("irootheldopath", []string{"/bin/sh", "-c", script}, allow), "tier: landlock\n", "tier: "+tier+"\n", 1)
	contract = strings.Replace(contract, "  write: [\"./out/\"]\n", "  write: [\"./out/\"]\n  reads: held\n  deny_read: [\"./"+sub+"secret/\"]\n", 1)
	contract = strings.Replace(contract, "record: summary\n", "record: full\n", 1)
	if err := os.WriteFile(filepath.Join(c.f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	run := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"))
	runErr := run.Run()
	if _, err := os.Stat(filepath.Join(out, "done")); err != nil {
		t.Fatalf("tier %s: the agent did not run to its end (%v): %v\n%s", tier, runErr, err, output(run))
	}
	if b, _ := os.ReadFile(filepath.Join(out, "prc")); strings.TrimSpace(string(b)) != "0" {
		perr, _ := os.ReadFile(filepath.Join(out, "perr"))
		t.Fatalf("tier %s: the O_PATH opens exited %q: %s", tier, b, perr)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "leak")); len(b) != 0 {
		t.Fatalf("tier %s: the agent read the nested deny_read: %q", tier, b)
	}
	dirs := runDirs(t, c.f.root)
	if len(dirs) <= before {
		t.Fatalf("tier %s: no run directory\n%s", tier, output(run))
	}
	evs := events(t, dirs[len(dirs)-1])
	rule := "fs.deny_read[./" + sub + "secret/]"
	for _, p := range []string{key, secret} {
		var lines []*record.Event
		for _, ev := range evs {
			var fp record.FSPayload
			if ev.Kind == record.KindFS && ev.DecodePayload(&fp) == nil && fp.Op == record.FSOpen && fp.Path == p && fp.Flags&unix.O_PATH != 0 {
				lines = append(lines, ev)
			}
		}
		if len(lines) != 1 {
			t.Errorf("tier %s: %d lines for the O_PATH open of %s, want one", tier, len(lines), p)
			continue
		}
		if ev := lines[0]; ev.Verdict != record.VerdictAllow || ev.Rule != rule+agent.OPathSuffix || ev.Source != record.SourceSeccomp {
			t.Errorf("tier %s: the O_PATH open of %s: %s by %q from %s, want allow by %q from seccomp", tier, p, ev.Verdict, ev.Rule,
				ev.Source, rule+agent.OPathSuffix)
		}
	}
}

// heldReadsAtRootTier is one tier's run of TestIntegrationHeldReadsAtRootTier, in out/<tier>/ of the case's project.
func heldReadsAtRootTier(t *testing.T, c *crossOwner, tier string) {
	t.Helper()
	before := len(runDirs(t, c.f.root))
	out := filepath.Join(c.f.out, tier)
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	sub := "out/" + tier + "/"
	script := "while [ ! -e " + sub + "go ]; do sleep 0.05; done; cat " + sub + ".env.local > " + sub + "leak 2> " + sub +
		"err; cat " + sub + "benign > " + sub + "copy; touch " + sub + "done"
	contract := strings.Replace(contractFor("irootheldreads", []string{"/bin/sh", "-c", script},
		[]string{"/bin/sh", "/bin/cat", "/bin/sleep", "/bin/touch"}), "tier: landlock\n", "tier: "+tier+"\n", 1)
	contract = strings.Replace(contract, "  write: [\"./out/\"]\n", "  write: [\"./out/\"]\n  reads: held\n", 1)
	if err := os.WriteFile(filepath.Join(c.f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	benign := filepath.Join(out, "benign")
	if err := os.WriteFile(benign, []byte("benign-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, out, benign)
	run := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"))
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	var runErr error
	done := make(chan struct{})
	go func() { runErr = run.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = run.Process.Kill()
		<-done
	})
	var dir string
	for deadline := time.Now().Add(60 * time.Second); dir == ""; time.Sleep(50 * time.Millisecond) {
		if dirs := runDirs(t, c.f.root); len(dirs) > before {
			dir = dirs[len(dirs)-1]
		}
		select {
		case <-done:
			t.Fatalf("the run ended before it started: %v\n%s", runErr, output(run))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no run directory within 60 s:\n%s", output(run))
		}
	}
	// A process outside the run, this one, makes a file the built-in name rule covers after compile and launch.
	local := filepath.Join(out, ".env.local")
	if err := os.WriteFile(local, []byte("LOCAL="+heldReadsSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, local)
	if err := os.WriteFile(filepath.Join(out, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("the run did not end within 60 s:\n%s", output(run))
	}
	if _, err := os.Stat(filepath.Join(out, "done")); err != nil {
		t.Fatalf("the agent did not run to its end (%v): %v\n%s", runErr, err, output(run))
	}
	if b, _ := os.ReadFile(filepath.Join(out, "leak")); len(b) != 0 {
		t.Fatalf("tier %s: the agent read the .env.local made during the run: %q", tier, b)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "err")); !strings.Contains(string(b), "Permission denied") {
		t.Errorf("tier %s: cat .env.local said %q, want EACCES", tier, b)
	}
	if b, err := os.ReadFile(filepath.Join(out, "copy")); err != nil || string(b) != "benign-bytes" {
		t.Fatalf("tier %s: the held read of the benign file gave %q, %v\n%s", tier, b, err, output(run))
	}
	evs := events(t, dir)
	start := heldReadsStart(t, evs)
	if start.FSReads == nil || start.FSReads.Reads != record.FSReadsHeld || start.FSReads.Why != agent.ReadsWhyContract {
		t.Errorf("tier %s: run_start.fs_reads = %+v, want held by the contract", tier, start.FSReads)
	}
	if !start.Capabilities[string(backend.CapReadDenyCreatedLater)] {
		t.Errorf("tier %s: capabilities[%s] false in a run that held its reads", tier, backend.CapReadDenyCreatedLater)
	}
	refused := false
	for _, ev := range evs {
		var p record.FSPayload
		if ev.Kind == record.KindFS && ev.DecodePayload(&p) == nil && p.Path == local {
			refused = ev.Verdict == record.VerdictRefused && ev.Reason == record.ReasonReadDenied &&
				strings.HasSuffix(ev.Rule, "/**/.env.*]") && ev.Source == record.SourceSeccomp
			if !refused {
				t.Errorf("tier %s: the .env.local's line %s %s %s from %s, want read-denied by the name rule from seccomp",
					tier, ev.Verdict, ev.Reason, ev.Rule, ev.Source)
			}
		}
	}
	if !refused {
		t.Errorf("tier %s: no refused line for %s\n%s", tier, local, output(run))
	}
}
