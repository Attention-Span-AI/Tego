// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// execRaceAttempts is how many raced execs each run makes: enough that a descriptor flipped by a second thread is
// seen by the kernel's own lookup on both sides.
const execRaceAttempts = 400

// raceReport is one run of the exec race: how the raced execs ended.
type raceReport struct {
	granted, other, refused, failed int
	// exit is the child's exit status of each attempt, by its pid: 0 granted-image ran, 1 other-image, 126 EACCES.
	exit map[int]int
	// plainGranted and plainOther are the exit statuses of one exec of each file with no race (-1 when not reported).
	plainGranted, plainOther int
}

// execPath is one exec line's verdict and path.
type execPath struct {
	verdict record.Verdict
	path    string
	rule    string
	pid     int
	reason  string
}

// execPaths reads every exec line of the one run under root.
func execPaths(t *testing.T, root string) []execPath {
	t.Helper()
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", root, dirs)
	}
	var out []execPath
	for _, e := range events(t, dirs[0]) {
		if e.Kind != record.KindExec {
			continue
		}
		var p record.ExecPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		out = append(out, execPath{e.Verdict, p.Path, e.Rule, e.PID, string(e.Reason)})
	}
	return out
}

// String is the outcome counts, without the per-attempt statuses.
func (r raceReport) String() string {
	return fmt.Sprintf("granted %d, other %d, refused %d, failed %d", r.granted, r.other, r.refused, r.failed)
}

// execRaceRun runs the exec race at tier landlock under a contract whose exec: body is execBody: granted is true(1)'s
// copy and other false(1)'s, and each of execRaceAttempts execs races a descriptor between them. It returns the
// outcomes the agent counted and the exec lines' paths of the run.
func execRaceRun(t *testing.T, execBody func(granted, other string) string) (raceReport, []execPath) {
	t.Helper()
	dir := t.TempDir()
	images := filepath.Join(dir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	copyOf := func(src, name string) string {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Skipf("no %s: %v", src, err)
		}
		p := filepath.Join(images, name)
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	granted := copyOf("/bin/true", "granted-image")
	other := copyOf("/bin/false", "other-image")
	agentReaches(t, images)
	agentOwns(t, images, granted, other)
	exe := os.Args[0]
	f := newFixture(t, fmt.Sprintf(`version: 0
name: execrace
command: [%q]
tier: landlock
fs:
  write: ["./out/", "/dev/null"]
exec:
%s
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 512
record: summary
`, exe, execBody(granted, other)))
	report := filepath.Join(f.out, "report")
	res, err := Run(context.Background(), f.rt, []string{exe, execRaceArg, fmt.Sprint(execRaceAttempts), granted, other, report}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: the race helper failed", res.ExitCode)
	}
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	r := raceReport{exit: map[int]int{}, plainGranted: -1, plainOther: -1}
	first, rest, _ := strings.Cut(string(b), "\n")
	if _, err := fmt.Sscanf(first, "granted=%d other=%d refused=%d failed=%d", &r.granted, &r.other, &r.refused, &r.failed); err != nil {
		t.Fatalf("report %q: %v", b, err)
	}
	for _, line := range strings.Split(rest, "\n") {
		var pid, code int
		if n, _ := fmt.Sscanf(line, "attempt %d %d", &pid, &code); n == 2 {
			r.exit[pid] = code
		}
		if n, _ := fmt.Sscanf(line, "plain granted %d", &code); n == 1 {
			r.plainGranted = code
		}
		if n, _ := fmt.Sscanf(line, "plain other %d", &code); n == 1 {
			r.plainOther = code
		}
	}
	if strings.Contains(string(b), "first failure") {
		t.Logf("report: %s", b)
	}
	return r, execPaths(t, f.root)
}

// linesOf is a summary of the exec lines for a failure message: verdict, rule and reason with how many of each, so a run
// that refused everything says who refused it.
func linesOf(paths []execPath) string {
	seen := map[string]int{}
	for _, p := range paths {
		seen[fmt.Sprintf("%s %s %s %.14s", p.verdict, p.rule, p.reason, p.path)]++
	}
	return fmt.Sprint(seen)
}

// racedAllowed counts the raced execs the supervisor allowed (an allowed line for the descriptor /proc/self/fd/N, the rule
// naming the file the walk reached, in the child whose pid the agent reported) whose rule matches rule and that ended with
// exit status code: the walk allowed one file and the kernel ran or refused another.
func racedAllowed(r raceReport, paths []execPath, rule func(string) bool, code int) int {
	n := 0
	for _, p := range paths {
		if got, ok := r.exit[p.pid]; ok && got == code && p.verdict == record.VerdictAllow && strings.HasPrefix(p.path, "/proc/self/fd/") && rule(p.rule) {
			n++
		}
	}
	return n
}

func namesGranted(rule string) bool { return strings.HasSuffix(rule, "granted-image]") }
func anyRule(string) bool           { return true }

// TestIntegrationExecRaceStaysInsideTheGrantedSet pins C30's limit as GAPS now words it (D18, 2026-11-22): at tier
// landlock the kernel bounds the exec's image to the files exec.allow grants. A second thread that swaps the descriptor the
// supervisor's walk read, between the walk and the kernel's own open, can make the kernel run another file, never one
// outside the grant. Each case races /proc/self/fd/N between true(1)'s copy (granted-image) and false(1)'s copy
// (other-image), 400 times, and compares what the agent saw with the exec lines the supervisor wrote.
//   - ungranted: only granted-image is granted. other-image never ran, every exec ended as granted-image or EACCES, and the
//     kernel itself refused some execs the supervisor had allowed (more allowed lines for the raced execs than runs of granted-image):
//     the walk and the kernel's open did differ, and Landlock's bound held where the walk could not.
//   - control: both are granted. The kernel ran other-image under lines that name granted-image (more allowed lines for
//     granted-image than runs of it), so the race is a real divergence between the decision and the open, not two
//     lookups that agree.
//   - denied: both are granted as a directory and exec.deny names other-image, which the kernel does not know (Landlock
//     holds the directory's EXECUTE, not the supervisor's deny): other-image can run under a line that names granted-image.
//     This is the raceable part C30 states, documented here; if it stops failing to happen, GAPS C30 is out of date.
func TestIntegrationExecRaceStaysInsideTheGrantedSet(t *testing.T) {
	t.Run("ungranted", func(t *testing.T) {
		r, paths := execRaceRun(t, func(granted, _ string) string {
			return fmt.Sprintf("  allow: [%q, %q]", os.Args[0], granted)
		})
		diverged := racedAllowed(r, paths, namesGranted, exitRaceRefused)
		t.Logf("raced execs: %v; allowed for granted-image yet refused by the kernel: %d", r, diverged)
		if r.plainGranted != 0 || r.plainOther != exitRaceRefused {
			t.Errorf("without a race granted-image exits %d and other-image %d, want 0 and %d (EACCES): %s", r.plainGranted, r.plainOther, exitRaceRefused, linesOf(paths))
		}
		if r.other != 0 {
			t.Errorf("%d raced execs ran the file no exec.allow entry grants: the kernel's bound (Landlock's EXECUTE set) did not hold", r.other)
		}
		if r.failed != 0 {
			t.Errorf("%d raced execs ended in neither the granted file nor EACCES", r.failed)
		}
		if r.granted+r.refused != execRaceAttempts {
			t.Errorf("outcomes %+v do not add up to %d attempts", r, execRaceAttempts)
		}
		if diverged == 0 {
			t.Errorf("the kernel refused no exec whose line the supervisor allowed for granted-image: the pin shows no divergence between the walk and the open")
		}
		for _, p := range paths {
			if strings.HasSuffix(p.rule, "other-image]") && p.verdict == record.VerdictAllow {
				t.Errorf("an exec line reads allow for the ungranted file: %+v", p)
			}
		}
	})
	t.Run("control", func(t *testing.T) {
		r, paths := execRaceRun(t, func(granted, other string) string {
			return fmt.Sprintf("  allow: [%q, %q, %q]", os.Args[0], granted, other)
		})
		diverged := racedAllowed(r, paths, namesGranted, 1)
		t.Logf("raced execs: %v; allowed for granted-image yet other-image ran: %d", r, diverged)
		if r.plainGranted != 0 || r.plainOther != 1 {
			t.Errorf("without a race granted-image exits %d and other-image %d, want 0 and 1: %s", r.plainGranted, r.plainOther, linesOf(paths))
		}
		if r.granted+r.other+r.refused != execRaceAttempts || r.failed != 0 {
			t.Errorf("outcomes %+v do not add up to %d attempts", r, execRaceAttempts)
		}
		if r.other == 0 {
			t.Errorf("the second thread never made the kernel run the other file in %d attempts: the race this test relies on did not happen", execRaceAttempts)
		}
		if diverged == 0 {
			t.Errorf("no exec whose line names granted-image ended as other-image: the decision and the open never differed")
		}
	})
	t.Run("denied", func(t *testing.T) {
		// A directory grant carries no loader of the dynamic files in it (Landlock's builder does not scan directories:
		// enforce/landlock/exec.go, E18). The test binary is the agent and, built with cgo, is dynamic and brings the loader
		// along; the gate builds it without cgo (static), so the images' loader is granted by name here, or every exec
		// of either image is refused whatever the race does.
		var diverged int
		var r raceReport
		var paths []execPath
		// The race flips the descriptor between the walk and the open; a round of 400 attempts shows the divergence in a
		// quarter of them, so a run that shows none in five rounds is not a lost race.
		for round := 1; round <= 5 && diverged == 0; round++ {
			r, paths = execRaceRun(t, func(granted, _ string) string {
				allow := fmt.Sprintf("%q, %q", os.Args[0], filepath.Dir(granted)+"/")
				if loader, err := agent.ReadInterp(granted); err == nil && loader != "" {
					allow += fmt.Sprintf(", %q", loader)
				}
				return fmt.Sprintf("  allow: [%s]\n  deny: [%q]", allow, "other-image")
			})
			diverged = racedAllowed(r, paths, anyRule, 1)
			t.Logf("round %d: raced execs: %v; allowed by the supervisor yet other-image ran: %d", round, r, diverged)
			// Not luck: with no race the supervisor refuses the denied file by name and lets the other run.
			if r.plainGranted != 0 || r.plainOther != exitRaceRefused {
				t.Fatalf("without a race granted-image exits %d and other-image %d, want 0 and %d (exec.deny refuses it): %s", r.plainGranted, r.plainOther, exitRaceRefused, linesOf(paths))
			}
			if r.granted == 0 {
				t.Fatalf("granted-image never ran, so the directory grant does not reach it (a loader, E18?): %v: %s", r, linesOf(paths))
			}
		}
		if r.failed != 0 || r.granted+r.other+r.refused != execRaceAttempts {
			t.Errorf("outcomes %+v do not add up to %d attempts", r, execRaceAttempts)
		}
		if diverged == 0 {
			t.Errorf("other-image, which exec.deny names, never ran under a line the supervisor allowed in five rounds (%v): the raceable part GAPS C30 states did not show; check that text: %s", r, linesOf(paths))
		}
		for _, p := range paths {
			if strings.HasSuffix(p.rule, "other-image]") && p.verdict == record.VerdictAllow {
				t.Errorf("a line allows the file exec.deny names: %+v", p)
			}
		}
	})
}
