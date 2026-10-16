// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const planeAlternateAgent = `with open("sealed/target", "w") as f:
    f.write("VIA-ALT")
print("RESULT wrote", flush=True)
`

// TestPlaneRunWriteAlternateIsPutToTheGate at the root tiers: the held fs.ask write of
// sealed/target is answered from a separate `tego alternate` process. Under `fs.write outside worktree: 90` a file in
// an fs.ask scope outside the worktree, which the gate refuses, is refused by the command (the request still pending)
// and keeps its bytes; the stand-in in ./out/ that follows is written, and its line carries its own gate decision,
// score 0. Under the same rule at 60, not a refusal, the file outside is delivered and its line says score 60, the
// gate's decision on that file, not the target's 0.
func TestPlaneRunWriteAlternateIsPutToTheGate(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, plane := range modes {
		tiers := []string{"cgroup"}
		if plane == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			for _, score := range []int{90, 60} {
				t.Run(fmt.Sprintf("%s@%s/score-%d", tier, plane, score), func(t *testing.T) {
					outside, err := os.MkdirTemp("", "tego-plane-alt-")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.RemoveAll(outside) })
					far := filepath.Join(outside, "x")
					if err := os.WriteFile(far, []byte("ORIGINAL"), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(outside, 0o755); err != nil {
						t.Fatal(err)
					}
					for _, p := range []string{outside, far} {
						if err := os.Lchown(p, uid, gid); err != nil {
							t.Fatal(err)
						}
					}
					contract := fmt.Sprintf(`version: 0
name: plane-alternate-gate
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  ask: ["./sealed/", %q]
exec:
  allow: ["python3"]
gate:
  rules:
    - fs.write outside worktree: %d
ask:
  timeout: 30s
limits:
  wall: 45s
env:
  pass: ["PATH", "HOME"]
capture: off
record: summary
`, outside+"/", score)
					p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": planeAlternateAgent, "agent.yaml": contract,
						"sealed/target": "original", "out/stand-in": "stand-in"}, []string{"out", "sealed"}, nil)
					target, standIn := filepath.Join(p.project, "sealed/target"), filepath.Join(p.project, "out/stand-in")
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					defer cancel()
					var out lockedBuffer
					cmd := p.runAt(ctx, bin, tier, "agent.yaml", plane, &out)
					cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					finished := make(chan struct{})
					var runErr error
					go func() { runErr = cmd.Wait(); close(finished) }()
					t.Cleanup(func() {
						cancel()
						select {
						case <-finished:
						case <-time.After(20 * time.Second):
							_ = cmd.Process.Kill() // still our unreaped launcher
							<-finished
							t.Error("the alternate run needed a forced cleanup")
						}
					})
					runID, req := waitPlaneAsk(t, ctx, bin, p, cmd.Env, finished, &out, "")
					if req.Target != target || req.Op != "open" {
						t.Fatalf("the held request %+v: want the write-open of %s", req, target)
					}
					delivered := standIn
					if score == 90 {
						try := exec.CommandContext(ctx, bin, "alternate", runID, req.AskID, "--file", far)
						try.Env = cmd.Env
						said, err := try.CombinedOutput()
						if err == nil || !strings.Contains(string(said), "refused by the contract's gate (gate.rules[0], score 90)") {
							t.Fatalf("tego alternate of a file the write gate refuses: %v\n%s", err, said)
						}
					} else {
						delivered = far
					}
					planeAskCLI(t, ctx, bin, cmd.Env, "alternate", runID, req.AskID, "--file", delivered)
					select {
					case <-finished:
					case <-ctx.Done():
						t.Fatalf("the run did not finish: %s", out.String())
					}
					if runErr != nil {
						t.Fatalf("the run: %v\n%s", runErr, out.String())
					}
					for path, want := range map[string]string{target: "original", delivered: "VIA-ALT"} {
						if b, err := os.ReadFile(path); err != nil || string(b) != want {
							t.Fatalf("%s holds %q (%v), want %q\n%s", path, b, err, want, out.String())
						}
					}
					if b, _ := os.ReadFile(far); score == 90 && string(b) != "ORIGINAL" {
						t.Fatalf("the file the gate refuses was written: %q", b)
					}
					var lines []map[string]any
					for _, e := range runEvents(t, p.ledger) {
						if e["kind"] == "fs" && e["authority"] == "human" {
							lines = append(lines, e)
						}
					}
					wantScore, wantRule := float64(0), any(nil)
					if score == 60 {
						wantScore, wantRule = 60, "gate.rules[0]"
					}
					if len(lines) != 1 || lines[0]["path"] != delivered || lines[0]["alternate_for"] != target || lines[0]["fd_delivered"] != true ||
						lines[0]["score"] != wantScore || lines[0]["gate_rule"] != wantRule || lines[0]["gate_outcome"] != "ask" {
						t.Fatalf("delivered lines %v: want one on %s, alternate_for the target, with score %v and gate_rule %v", lines, delivered, wantScore, wantRule)
					}
				})
			}
		}
	}
}
