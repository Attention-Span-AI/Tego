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

// TestIntegrationDenyReadSnapshotAtRootTiers is GAPS A12: the root tiers (cgroup, bpflsm) install the
// same tier-1 Landlock ruleset as tier landlock, with the same frozen deny_read enumeration, so a name made beside an
// enumerated ancestor after the run started is unreadable to the agent there too. At tier landlock the supervisor
// refuses such a read itself, with the kernel's EACCES, and records it refused, read-denied, rule deny-read-snapshot
// (TestIntegrationDenyReadSnapshotIsRecordedRefused). The root tiers' handle was not wired to that snapshot, so the
// open was continued, the kernel refused it, and the line said allow or, from the kernel recorder, observed by other.
// This is the same scene from a root launcher, at both root tiers, on the fanotify fallback and in the plane mode the
// machine selects, with every read-notifying record mode: record: full (the loop continues every open), and fs.reads:
// held (the open deputy completes it in the run's own domain).
//
// The agent is dropped to the invoking user, as in a real `sudo tego run`. A new file in a sibling that existed at
// launch and a listing of the new directory stay readable and are never refused; the deny_read target itself is
// refused by the ruleset as before.
func TestIntegrationDenyReadSnapshotAtRootTiers(t *testing.T) {
	c := newCrossOwner(t, "irootsnap")
	// The root tiers load the embedded BPF objects: this case's tego is built with them.
	bin := filepath.Join(t.TempDir(), "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build tego with the BPF objects: %v\n%s", err, out)
	}
	agentReaches(t, bin)
	c.bin = bin
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
			for _, plane := range []string{"fanotify", ""} {
				name := plane
				if name == "" {
					name = "selected"
				}
				for _, tc := range []struct{ mode, reads, record string }{
					{"continued", "direct", "full"},
					{"held", "held", "summary"},
					{"kernel", "direct", "summary"},
					{"exec", "direct", "summary"},
				} {
					t.Run(name+"/"+tc.mode, func(t *testing.T) {
						rootSnapshotScene(t, c, tier, plane, tc.mode, tc.reads, tc.record)
					})
				}
			}
		})
	}
}

// rootSnapshotScene runs one case: an agent under fs.write ["./out/"] and deny_read ["./secret/"] at tier, with
// old/g.txt made before the run. Once the agent waits, the test, a process outside the run, makes late/f.txt and
// late.txt beside the target's parent's children and old/late.txt inside a sibling that existed at launch; then the
// agent reads each, and secret/token, and lists late/.
func rootSnapshotScene(t *testing.T, c *crossOwner, tier, plane, name, reads, mode string) {
	t.Helper()
	project := c.f.dir
	before := len(runDirs(t, c.f.root))
	dirName := tier + "-" + plane + "-" + name
	out := filepath.Join(c.f.out, dirName)
	res := filepath.Join(out, "res")
	if err := os.MkdirAll(res, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(project, "secret"), filepath.Join(project, "old_"+dirName)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old, secret := "old_"+dirName, "secret"
	for p, body := range map[string]string{
		filepath.Join(project, secret, "token"): "s3cr3t", filepath.Join(project, old, "g.txt"): "old"} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	late := "late_" + dirName
	lateTop := "late_" + dirName + ".txt"
	agentOwns(t, out, res)
	// The exec cell runs an executable made after launch beside the deny_read ancestor, under a contract with no exec:
	// section (every image allowed on the contract's paths), so the only thing that can refuse it is the ruleset.
	execStep := ""
	if name == "exec" {
		execStep = "t exe " + project + "/" + late + "/tool\n"
	}
	script := "t() { n=$1; shift; \"$@\" > " + res + "/$n.out 2> " + res + "/$n.err; echo $? > " + res + "/$n.rc; }\n" +
		"echo ready > " + res + "/ready\n" +
		"while [ ! -e " + out + "/go ]; do sleep 0.05; done\n" +
		"t late cat " + project + "/" + late + "/f.txt\n" +
		"t top cat " + project + "/" + lateTop + "\n" +
		"t early cat " + project + "/" + old + "/late.txt\n" +
		"t secret cat " + project + "/" + secret + "/token\n" +
		execStep +
		"echo " + project + "/" + late + "/* > " + res + "/list.out\n" +
		"echo done > " + res + "/done\n"
	contract := strings.Replace(contractFor("irootsnap", []string{"/bin/sh", "-c", script},
		[]string{"/bin/sh", "/bin/cat", "/bin/sleep"}), "tier: landlock\n", "tier: "+tier+"\n", 1)
	contract = strings.Replace(contract, "  write: [\"./out/\"]\n",
		"  write: [\"./out/\"]\n  deny_read: [\""+filepath.Join(project, secret)+"/\"]\n  reads: "+reads+"\n", 1)
	contract = strings.Replace(contract, "record: summary\n", "record: "+mode+"\n", 1)
	if name == "exec" {
		contract = strings.Replace(contract, "exec:\n  allow: [\"/bin/sh\", \"/bin/cat\", \"/bin/sleep\"]\n", "", 1)
		if strings.Contains(contract, "exec:") {
			t.Fatalf("the exec cell's contract still restricts exec:\n%s", contract)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	run := c.command(t, false, "run", filepath.Join(project, "agent.yaml"))
	if plane != "" {
		run.Env = append(run.Env, "TEGO_TEST_PLANE="+plane)
	}
	if w := os.Getenv("TEGO_TEST_PLANE_PREEMPT"); w != "" {
		run.Env = append(run.Env, "TEGO_TEST_PLANE_PREEMPT="+w)
	}
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
	readOut := func(n string) string {
		b, _ := os.ReadFile(filepath.Join(res, n))
		return string(b)
	}
	for deadline := time.Now().Add(60 * time.Second); readOut("ready") == ""; time.Sleep(20 * time.Millisecond) {
		select {
		case <-done:
			t.Fatalf("the run ended before the agent reached its wait: %v\n%s", runErr, output(run))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent never reached its wait\n%s", output(run))
		}
	}
	// Made after the ruleset's one listing of each ancestor, by a process outside the run.
	if err := os.Mkdir(filepath.Join(project, late), 0o755); err != nil {
		t.Fatal(err)
	}
	for n, body := range map[string]string{late + "/f.txt": "late", lateTop: "top", old + "/late.txt": "early"} {
		if err := os.WriteFile(filepath.Join(project, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wantList := project + "/" + late + "/f.txt"
	if name == "exec" {
		if err := os.WriteFile(filepath.Join(project, late, "tool"), []byte("#!/bin/sh\necho ran\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		wantList += " " + project + "/" + late + "/tool"
	}
	if err := os.WriteFile(filepath.Join(out, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatalf("the run did not end within 90 s:\n%s", output(run))
	}
	if readOut("done") == "" {
		t.Fatalf("the agent did not run to its end (%v)\n%s", runErr, output(run))
	}
	for _, n := range []string{"late", "top", "secret"} {
		if rc := strings.TrimSpace(readOut(n + ".rc")); rc == "0" || rc == "" {
			t.Errorf("%s: status %q, want a refusal (%q)", n, rc, readOut(n+".err"))
		}
		if e := readOut(n + ".err"); !strings.Contains(e, "Permission denied") {
			t.Errorf("%s: error %q, want EACCES", n, e)
		}
	}
	if got := readOut("early.out"); got != "early" {
		t.Errorf("a new file in a sibling that existed at launch read %q (%q), want early", got, readOut("early.err"))
	}
	if got := strings.TrimSpace(readOut("list.out")); got != wantList {
		t.Errorf("listing the new directory gave %q, want %q", got, wantList)
	}
	dirs := runDirs(t, c.f.root)
	if len(dirs) <= before {
		t.Fatalf("no run directory:\n%s", output(run))
	}
	evs := events(t, dirs[len(dirs)-1])
	var start record.RunStartPayload
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart || evs[0].DecodePayload(&start) != nil {
		t.Fatal("the ledger does not open with run_start")
	}
	if start.RecordMinor < record.MinorDenyReadFrozen {
		t.Errorf("run_start record_minor %d", start.RecordMinor)
	}
	if start.DenyReadFrozen == nil {
		t.Errorf("run_start names no frozen directory at tier %s", tier)
	}
	lines := map[string][]*record.Event{}
	for _, e := range evs {
		var p record.FSPayload
		if e.Kind != record.KindFS || e.DecodePayload(&p) != nil || p.Op != record.FSOpen || !strings.HasPrefix(p.Path, project+"/") {
			continue
		}
		rel := strings.TrimPrefix(p.Path, project+"/")
		lines[rel] = append(lines[rel], e)
		if name == "kernel" || name == "exec" {
			// Under summary with reads direct no read open reaches the supervisor: the tier's kernel recorder writes
			// the line, from the LSM chain's return. It names the refusal it saw and no rule that explains it:
			// observed, by other, with the errno. It is never allow, and never refused for a reason it cannot know.
			if rel == late+"/f.txt" || rel == lateTop {
				var q struct {
					By    string `json:"by"`
					Errno int    `json:"errno"`
				}
				if e.Verdict != record.VerdictObserved || json.Unmarshal(e.Payload, &q) != nil || q.By != record.FSByOther || q.Errno != 13 {
					t.Errorf("kernel-recorded %s: %s %s (%s), want observed by other with errno 13", rel, e.Verdict, e.Reason, e.Payload)
				}
			}
			continue
		}
		switch rel {
		case late + "/f.txt", lateTop:
			if e.Verdict != record.VerdictRefused || e.Reason != record.ReasonReadDenied || e.Rule != "deny-read-snapshot" ||
				e.Authority != record.AuthorityRule || p.Mechanism != "" {
				t.Errorf("%s: %s %s %s by %s (mechanism %q, %s), want refused read-denied deny-read-snapshot by rule, as at tier landlock",
					rel, e.Verdict, e.Reason, e.Rule, e.Authority, p.Mechanism, e.Payload)
			}
		case old + "/late.txt", late:
			if e.Verdict == record.VerdictRefused {
				t.Errorf("%s: refused %s %s, want it readable", rel, e.Reason, e.Rule)
			}
		}
	}
	if name == "exec" {
		rootSnapshotExec(t, evs, readOut("exe.rc"), readOut("exe.err"), readOut("exe.out"), project+"/"+late+"/tool")
	}
	for _, rel := range []string{late + "/f.txt", lateTop} {
		if len(lines[rel]) != 1 {
			for _, e := range lines[rel] {
				b, _ := json.Marshal(e)
				t.Logf("%s: %s", rel, b)
			}
			t.Errorf("%d lines for %s, want exactly one", len(lines[rel]), rel)
		}
	}
}

// rootSnapshotExec holds the exec cell: an executable made after launch beside a deny_read ancestor is refused by the
// ruleset's file_open, so the agent's exec fails with EACCES, and the one line for it is the supervisor's, refused,
// read-denied, rule deny-read-snapshot, as at tier landlock, even where the kernel plane decides execs (the supervisor
// does not hand such an exec over). The tool is never run.
func rootSnapshotExec(t *testing.T, evs []*record.Event, rc, errText, out, tool string) {
	t.Helper()
	if rc = strings.TrimSpace(rc); rc == "0" || rc == "" || !strings.Contains(errText, "Permission denied") || out != "" {
		t.Errorf("exec of %s: status %q, stderr %q, stdout %q, want EACCES and no output", tool, rc, errText, out)
	}
	var lines []*record.Event
	for _, e := range evs {
		var p record.ExecPayload
		if e.Kind != record.KindExec || e.DecodePayload(&p) != nil {
			continue
		}
		if p.Path == tool || p.Script == tool || p.AttemptPath == tool {
			lines = append(lines, e)
		}
	}
	if len(lines) != 1 {
		for _, e := range lines {
			t.Logf("exec line: %s %s %s %s", e.Verdict, e.Reason, e.Rule, e.Payload)
		}
		t.Fatalf("%d exec lines for %s, want exactly one", len(lines), tool)
	}
	e := lines[0]
	if e.Verdict != record.VerdictRefused || e.Reason != record.ReasonReadDenied || e.Rule != "deny-read-snapshot" || e.Authority != record.AuthorityRule {
		t.Errorf("exec of %s: %s %s %s by %s (%s), want refused read-denied deny-read-snapshot by rule, as at tier landlock",
			tool, e.Verdict, e.Reason, e.Rule, e.Authority, e.Payload)
	}
}
