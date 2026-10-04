// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

const planeAskAgent = `import errno, json, os, sys
mode = sys.argv[1]
birth = int(open("/proc/self/stat").read().rsplit(")", 1)[1].split()[19])
print("IDENTITY", json.dumps({"pid": os.getpid(), "tid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(), "birth_ticks": birth, "cgroup": open("/proc/self/cgroup").read().strip()}), flush=True)
try:
    with open("sealed/link", "w") as f:
        f.write("approved")
    assert mode == "approve", "unapproved write succeeded"
    print("RESULT first approved", flush=True)
except OSError as e:
    assert mode != "approve" and e.errno in (errno.EACCES, errno.EPERM), (mode, e)
    print("RESULT first refused", flush=True)
if mode == "approve":
    # The injected OFD grants no ordinary open rights to the same inode.
    try:
        with open("sealed/original", "w") as f:
            f.write("unapproved-second")
        raise AssertionError("approval permanently opened the filesystem floor")
    except OSError as e:
        assert e.errno in (errno.EACCES, errno.EPERM), e
        print("RESULT second refused", flush=True)
`

// Actual CLI approvals originate in a separate process outside the governed
// cgroup. An approved held inode remains writable through its delivered OFD
// under the plane, while new opens require new approvals, even with record off.
func TestPlaneRunApprovedFSAskKeepsDescriptorOnlyGrant(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, plane := range modes {
		tiers := []string{"cgroup"}
		if plane == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			for _, recording := range []string{"summary", "off"} {
				for _, choice := range []string{"approve", "deny", "timeout"} {
					t.Run(tier+"@"+plane+"/"+recording+"/"+choice, func(t *testing.T) {
						timeout := "10s"
						if choice == "timeout" {
							timeout = "750ms"
						}
						contract := fmt.Sprintf(`version: 0
name: plane-approved-fs-ask
command: ["python3", "./agent.py", "%s"]
fs:
  write: ["./out/"]
  ask: ["./sealed/"]
exec:
  allow: ["python3"]
ask:
  hold: connect
  timeout: %s
limits:
  wall: 45s
env:
  pass: ["PATH", "HOME"]
capture: off
record: %s
`, choice, timeout, recording)
						p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": planeAskAgent,
							"agent.yaml": contract, "sealed/original": "original", "sealed/replacement": "untouched"}, []string{"out", "sealed"}, nil)
						link := filepath.Join(p.project, "sealed/link")
						if err := os.Symlink("original", link); err != nil {
							t.Fatal(err)
						}
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
								select {
								case <-finished:
								case <-time.After(20 * time.Second):
									t.Error("owned approval launcher could not be reaped within cleanup bound")
								}
								t.Error("owned approval workload required forced launcher cleanup")
							}
						})
						live := waitPlaneAskIdentity(t, ctx, finished, &out, uid, gid)
						var expectedAskIDs []string
						if choice != "timeout" {
							runID, req := waitPlaneAsk(t, ctx, bin, p, cmd.Env, finished, &out, "")
							assertPlaneAskLive(t, live)
							expectedAskIDs = append(expectedAskIDs, req.AskID)
							if req.Target != filepath.Join(p.project, "sealed/original") {
								t.Fatalf("approval did not hold resolved original inode: %+v", req)
							}
							assertPlaneAskFile(t, p, "original", "original")
							if choice == "approve" {
								if err := os.Remove(link); err != nil {
									t.Fatal(err)
								}
								if err := os.Symlink("replacement", link); err != nil {
									t.Fatal(err)
								}
							}
							planeAskCLI(t, ctx, bin, cmd.Env, choice, "--json", runID, req.AskID)
							if choice == "approve" {
								_, second := waitPlaneAsk(t, ctx, bin, p, cmd.Env, finished, &out, req.AskID)
								assertPlaneAskLive(t, live)
								expectedAskIDs = append(expectedAskIDs, second.AskID)
								if second.Target != req.Target {
									t.Fatalf("second approval was not a new open of the same inode: %+v", second)
								}
								assertPlaneAskFile(t, p, "original", "approved")
								assertPlaneAskFile(t, p, "replacement", "untouched")
								planeAskCLI(t, ctx, bin, cmd.Env, "deny", "--json", runID, second.AskID)
							}
						}
						select {
						case <-finished:
						case <-ctx.Done():
							t.Fatalf("bounded approval workload did not finish: %s", out.String())
						}
						if runErr != nil {
							t.Fatalf("actual approved descriptor write/denial: %v\n%s", runErr, out.String())
						}
						wantData, wantAsks := "original", 1
						if choice == "approve" {
							wantData, wantAsks = "approved", 2
						}
						assertPlaneAskFile(t, p, "original", wantData)
						assertPlaneAskFile(t, p, "replacement", "untouched")
						checkPlaneAskLedger(t, p, tier, plane, recording, choice, wantAsks, live, expectedAskIDs)
						if st, err := proc.New().Stat(live.PID); err == nil && st.StartTicks == live.BirthTicks && st.State != 'Z' && st.State != 'X' {
							t.Fatalf("completed actor remains live with the same birth: %+v", st)
						} else if err != nil && !errors.Is(err, proc.ErrGone) {
							t.Fatalf("cannot verify completed actor: %v", err)
						}
						if _, err := os.Stat(filepath.Join(identity.SystemCgroupRoot, live.scope)); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("completed approval cgroup remains or could not be inspected: %s: %v", live.scope, err)
						}
						paths, _ := filepath.Glob(filepath.Join(p.ledger, "*", "events.jsonl"))
						if len(paths) != 1 {
							t.Fatalf("unexpected run layout: %v", paths)
						}
						planeAskCLI(t, ctx, bin, cmd.Env, "events", "--verify", filepath.Base(filepath.Dir(paths[0])))
					})
				}
			}
		}
	}
}

func assertPlaneAskFile(t *testing.T, p *planeProject, name, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(p.project, "sealed", name))
	if err != nil || string(got) != want {
		t.Fatalf("actual %s changed: got %q want %q err%v", name, got, want, err)
	}
}

func planeAskCLI(t *testing.T, ctx context.Context, bin string, env []string, args ...string) []byte {
	t.Helper()
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(callCtx, bin, args...)
	cmd.Env = env
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("outside-governed actual CLI %v: %v\n%s", args, err, data)
	}
	return data
}

func waitPlaneAsk(t *testing.T, ctx context.Context, bin string, p *planeProject, env []string, finished <-chan struct{}, out *lockedBuffer, previous string) (string, ask.Request) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		paths, _ := filepath.Glob(filepath.Join(p.ledger, "*", ask.SocketName))
		if len(paths) == 1 {
			runID := filepath.Base(filepath.Dir(paths[0]))
			var listed struct {
				Pending []ask.Summary `json:"pending"`
			}
			if err := json.Unmarshal(planeAskCLI(t, ctx, bin, env, "ask", "--json", runID), &listed); err != nil {
				t.Fatal(err)
			}
			if len(listed.Pending) > 1 {
				t.Fatalf("single actor queued multiple approvals: %+v", listed.Pending)
			}
			if len(listed.Pending) == 1 && listed.Pending[0].AskID != previous {
				var detail struct {
					Request ask.Request `json:"request"`
				}
				if err := json.Unmarshal(planeAskCLI(t, ctx, bin, env, "ask", "--json", runID, listed.Pending[0].AskID), &detail); err != nil {
					t.Fatal(err)
				}
				if detail.Request.PID <= 0 || detail.Request.TID != detail.Request.PID || detail.Request.Hold != ask.HoldOpen {
					t.Fatalf("invalid actual actor approval identity: %+v", detail.Request)
				}
				return runID, detail.Request
			}
		}
		select {
		case <-finished:
			t.Fatalf("run finished before pending approval: %s", out.String())
		case <-ctx.Done():
			t.Fatalf("approval wait canceled: %s", out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("run never published actual CLI approval: %s", out.String())
	return "", ask.Request{}
}

type planeAskIdentity struct {
	PID, TID, UID, GID int
	BirthTicks         uint64 `json:"birth_ticks"`
	Cgroup             string
	scope              string
	cgroupID           uint64
}

func waitPlaneAskIdentity(t *testing.T, ctx context.Context, finished <-chan struct{}, out *lockedBuffer, uid, gid int) planeAskIdentity {
	t.Helper()
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	for {
		complete := out.String()
		if end := strings.LastIndexByte(complete, '\n'); end >= 0 {
			complete = complete[:end]
		} else {
			complete = ""
		}
		for _, line := range strings.Split(complete, "\n") {
			if data, ok := strings.CutPrefix(line, "IDENTITY "); ok {
				var live planeAskIdentity
				if err := json.Unmarshal([]byte(data), &live); err != nil {
					t.Fatal(err)
				}
				if live.PID <= 0 || live.TID != live.PID || live.UID != uid || live.GID != gid || live.BirthTicks == 0 {
					t.Fatalf("actor did not report intended identity: %+v", live)
				}
				live.scope = proc.ParseCgroup([]byte(live.Cgroup))
				parent, err := proc.New().Cgroup(os.Getpid())
				if err != nil || live.scope == "" || live.scope == "/" || live.scope == parent {
					t.Fatalf("actor is not in a distinct governed cgroup: %+v, admin=%q err=%v", live, parent, err)
				}
				live.cgroupID, err = cgroupIDOfPath(identity.SystemCgroupRoot, live.scope)
				if err != nil {
					t.Fatalf("actual actor cgroup identity: %v", err)
				}
				assertPlaneAskLive(t, live)
				return live
			}
		}
		select {
		case <-finished:
			t.Fatalf("actor ended before live identity proof: %s", out.String())
		case <-ctx.Done():
			t.Fatalf("actor identity canceled: %s", out.String())
		case <-deadline.C:
			t.Fatalf("actor never reported live identity: %s", out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func assertPlaneAskLive(t *testing.T, live planeAskIdentity) {
	t.Helper()
	st, err := proc.New().Stat(live.PID)
	if err != nil || st.StartTicks != live.BirthTicks || st.State == 'Z' || st.State == 'X' {
		t.Fatalf("actual actor birth/live proof: %+v want %+v err=%v", st, live, err)
	}
	cg, err := proc.New().Cgroup(live.PID)
	if err != nil || cg != live.scope {
		t.Fatalf("actual actor cgroup=%q want%q err=%v", cg, live.scope, err)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", live.PID))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "Uid:" && fields[0] != "Gid:" {
			continue
		}
		want := live.UID
		if fields[0] == "Gid:" {
			want = live.GID
		}
		for _, field := range fields[1:] {
			got, err := strconv.Atoi(field)
			if err != nil || got != want {
				t.Fatalf("actual %s identities=%v want%d", fields[0], fields[1:], want)
			}
		}
		seen++
	}
	if seen != 2 {
		t.Fatal("actual actor status lacks UID/GID identity")
	}
	end, err := proc.New().Stat(live.PID)
	if err != nil || end.StartTicks != live.BirthTicks {
		t.Fatalf("actor birth changed during proof: %+v %v", end, err)
	}
}

func checkPlaneAskLedger(t *testing.T, p *planeProject, tier, plane, recording, choice string, wantAsks int, live planeAskIdentity, expectedIDs []string) {
	t.Helper()
	asks, answers, effects, refused, starts, ends := 0, 0, 0, 0, 0, 0
	askOrder := []string{}
	answerSeen := map[string]bool{}
	for _, e := range runEvents(t, p.ledger) {
		switch e["kind"] {
		case "run_start":
			starts++
			caps, _ := e["capabilities"].(map[string]any)
			if e["tier"] != tier || e["decision_plane"] != plane || caps["ask"] != true || e["cgroup"] != float64(live.cgroupID) {
				t.Errorf("actual ask/plane/cgroup readiness: %v", e)
			}
		case "run_end":
			ends++
			if e["reason"] != "exit" || e["exit_code"] != nil && e["exit_code"] != float64(0) {
				t.Errorf("approval actor did not finish normally: %v", e)
			}
		case "ask", "answer":
			if e["pid"] != float64(live.PID) || e["tid"] != float64(live.TID) || e["cgroup"] != float64(live.cgroupID) {
				t.Errorf("approval attributed outside actual actor: %v", e)
			}
			id, _ := e["ask_id"].(string)
			if id == "" {
				t.Fatal("approval event omitted ask_id")
			}
			if e["kind"] == "ask" {
				if _, ok := answerSeen[id]; ok {
					t.Fatalf("ask_id repeated: %v", e)
				}
				answerSeen[id] = false
				askOrder = append(askOrder, id)
				asks++
			} else {
				answered, asked := answerSeen[id]
				if !asked || answered {
					t.Fatalf("answer lacks one preceding unmatched ask: %v", e)
				}
				wantApproved := choice == "approve" && id == askOrder[0]
				if e["approved"] != wantApproved {
					t.Errorf("actual approval choice for %s: %v want%t", id, e, wantApproved)
				}
				answerSeen[id] = true
				answers++
			}
			if e["kind"] == "answer" && choice == "timeout" && e["answer_reason"] != "ask-timeout" {
				t.Errorf("timeout reason: %v", e)
			}
		case "fs":
			if e["path"] != filepath.Join(p.project, "sealed/original") && e["path"] != filepath.Join(p.project, "sealed/link") {
				continue
			}
			if e["authority"] == "human" && e["verdict"] == "allow" {
				effects++
				if e["operation_completed"] != true || e["fd_delivered"] != true || e["result_unknown"] == true || e["syscall_ret"] == nil {
					t.Errorf("approved actual OFD completion: %v", e)
				}
			}
			if e["verdict"] == "refused" {
				refused++
			}
		}
	}
	if len(expectedIDs) > 0 && strings.Join(askOrder, ",") != strings.Join(expectedIDs, ",") {
		t.Errorf("ledger ask IDs %v differ from actual CLI-held requests %v", askOrder, expectedIDs)
	}
	wantEffects := 0
	if recording != "off" && choice == "approve" {
		wantEffects = 1
	}
	if asks != wantAsks || answers != wantAsks || effects != wantEffects || refused != 1 || starts != 1 || ends != 1 {
		t.Fatalf("ask/answer/effect/refusal/start/end=%d/%d/%d/%d/%d/%d want%d/%d/%d/1/1/1\n%s", asks, answers, effects, refused, starts, ends, wantAsks, wantAsks, wantEffects, ledgerDump(p.ledger))
	}
}
