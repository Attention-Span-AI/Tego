// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationReasonReadsAtTierCgroup is ADR 0077 at tier cgroup from a root launcher, the agent dropped to the
// invoking user, on the fanotify fallback and in the plane mode the machine selects: reason.reads: on never applies at
// a root tier (run_start.reads_notified says kernel, and HoldsFSNotifications is unchanged, so the filter notifies no read
// open and no decision leaves the kernel plane). A read Landlock refuses first (a deny_read outside every write entry)
// and a read only tier 2 refuses (a deny_read nested in the write entry, which the ruleset leaves unenforced) each have
// exactly one line, refused read-denied: never a second from the fanotify listener or the supervisor.
func TestIntegrationReasonReadsAtTierCgroup(t *testing.T) {
	c := newCrossOwner(t, "ireasonreadscg")
	bin := filepath.Join(t.TempDir(), "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build tego with the BPF objects: %v\n%s", err, out)
	}
	agentReaches(t, bin)
	c.bin = bin
	testutil.RequireTier(t, c.doctorRequire(t, "cgroup"), "cgroup")
	for _, plane := range []string{"fanotify", ""} {
		name := plane
		if name == "" {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) { reasonReadsAtTierCgroup(t, c, name, plane) })
	}
}

func reasonReadsAtTierCgroup(t *testing.T, c *crossOwner, name, plane string) {
	t.Helper()
	before := len(runDirs(t, c.f.root))
	out := filepath.Join(c.f.out, name)
	outer := filepath.Join(c.f.dir, "secret-"+name)
	for _, d := range []string{filepath.Join(out, "vault"), outer} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	nested, key := filepath.Join(out, "vault", "token"), filepath.Join(outer, "key")
	for _, f := range []string{nested, key} {
		if err := os.WriteFile(f, []byte(heldReadsSecret), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agentOwns(t, out, filepath.Join(out, "vault"), nested, outer, key)
	sub := "out/" + name + "/"
	script := "cat " + key + " > " + sub + "k.out 2> " + sub + "k.err; cat " + nested + " > " + sub + "n.out 2> " + sub +
		"n.err; touch " + sub + "done"
	contract := strings.Replace(contractFor("ireasonreadscg", []string{"/bin/sh", "-c", script},
		[]string{"/bin/sh", "/bin/cat", "/bin/touch"}), "tier: landlock\n", "tier: cgroup\n", 1)
	contract = strings.Replace(contract, "  write: [\"./out/\"]\n",
		"  write: [\"./out/\"]\n  deny_read: [\""+outer+"\", \""+filepath.Join(out, "vault")+"\"]\n  reads: direct\n", 1)
	contract += "reason:\n  reads: on\n"
	if err := os.WriteFile(filepath.Join(c.f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	run := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"))
	if plane != "" {
		run.Env = append(run.Env, "TEGO_TEST_PLANE="+plane)
	}
	if err := run.Run(); err != nil {
		t.Logf("tego run: %v (the agent's cats are refused)", err)
	}
	if _, err := os.Stat(filepath.Join(out, "done")); err != nil {
		t.Fatalf("the agent did not run to its end: %v\n%s", err, output(run))
	}
	for _, f := range []string{"k", "n"} {
		if b, _ := os.ReadFile(filepath.Join(out, f+".out")); len(b) != 0 {
			t.Fatalf("%s: the agent read a deny_read file: %q", f, b)
		}
	}
	dirs := runDirs(t, c.f.root)
	if len(dirs) <= before {
		t.Fatalf("no run directory:\n%s", output(run))
	}
	evs := events(t, dirs[len(dirs)-1])
	start := reasonReadsStart(t, evs)
	if start.ReadsNotified.Notified || start.ReadsNotified.Why != record.ReadsNotifiedWhyKernel {
		t.Errorf("reads_notified %+v, want not notified, kernel", start.ReadsNotified)
	}
	for _, p := range []string{key, nested} {
		lines := keyLines(t, evs, p)
		if len(lines) != 1 || lines[0].Verdict != record.VerdictRefused || lines[0].Reason != record.ReasonReadDenied {
			for _, e := range lines {
				t.Logf("%s: %s %s %s from %s: %s", p, e.Verdict, e.Reason, e.Rule, e.Source, e.Payload)
			}
			t.Errorf("%d fs lines for %s, want exactly one read-denied refusal", len(lines), p)
		}
	}
}
