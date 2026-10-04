// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const execOutcomesAgent = `import os, threading
pid = os.fork()
if pid == 0:
    print("CHILD", os.getpid(), flush=True)
    for name in ("blocked", "blocked", "allowed/missing", "allowed/missing", "allowed/bad", "allowed/busy"):
        try:
            os.execve("./" + name, ["attempt", name], {})
            raise AssertionError("unexpected exec success: " + name)
        except OSError as e:
            print("RESULT", name, e.errno, flush=True)
    def finish():
        print("THREAD", threading.get_native_id(), flush=True)
        os.execve("./allowed/true", ["outcome-ok", "with-argument"], {})
    t = threading.Thread(target=finish)
    t.start()
    t.join()
    os._exit(99)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0, status
`

// Failed attempts of a file must each have one terminal record, even when no
// LSM hook runs. An attempt whose pathname names nothing (allowed/missing) has
// none at any record level: run_end's supervisor.exec_missing counts it, its
// only trace (supervisor R16b (0), record_minor 8). A final exec from a
// non-leader thread must retain that attempt's argv and process identity after
// de_thread changes the executing TID.
func TestPlaneRunExecOutcomes(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes {
		tiers := []string{"cgroup"}
		if mode == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			for _, recording := range []string{"full", "off"} {
				t.Run(tier+"@"+mode+"/"+recording, func(t *testing.T) {
					contract := fmt.Sprintf(`version: 0
name: exec-outcomes
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3", "./allowed/"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: %s
`, recording)
					p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": execOutcomesAgent, "agent.yaml": contract,
						"blocked": string(tool), "allowed/true": string(tool), "allowed/busy": string(tool), "allowed/bad": "not an executable format\n"}, []string{"out"}, nil)
					if err := os.Chmod(filepath.Join(p.project, "allowed/bad"), 0o755); err != nil {
						t.Fatal(err)
					}
					// An outside writer holds this allowed image busy, so the kernel
					// refuses ETXTBSY before a successful sched_process_exec event.
					busy, err := os.OpenFile(filepath.Join(p.project, "allowed/busy"), os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					defer busy.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					defer cancel()
					var out bytes.Buffer
					if err := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out).Run(); err != nil {
						t.Fatalf("run: %v\n%s", err, out.String())
					}
					child, thread := 0, 0
					for _, line := range strings.Split(out.String(), "\n") {
						fields := strings.Fields(line)
						if len(fields) == 2 && fields[0] == "CHILD" {
							child, _ = strconv.Atoi(fields[1])
						}
						if len(fields) == 2 && fields[0] == "THREAD" {
							thread, _ = strconv.Atoi(fields[1])
						}
					}
					if child == 0 || thread == 0 || child == thread {
						t.Fatalf("non-leader exec did not run:\n%s", out.String())
					}
					counts := map[string]int{}
					events := runEvents(t, p.ledger)
					for _, e := range events {
						if e["kind"] != "exec" || e["pid"] != float64(child) {
							continue
						}
						name := strings.TrimPrefix(fmt.Sprint(e["path"]), p.project+"/")
						counts[name]++
						if e["source"] != "kernel" {
							t.Errorf("outcome recorded by supervisor: %v", e)
						}
						switch name {
						case "blocked":
							if e["verdict"] != "refused" || e["syscall_ret"] != float64(-13) {
								t.Errorf("refusal: %v", e)
							}
						case "allowed/true":
							argv, _ := e["argv"].([]any)
							if e["verdict"] != "allow" || len(argv) != 2 || argv[0] != "outcome-ok" || argv[1] != "with-argument" {
								t.Errorf("successful thread exec: %v", e)
							}
						case "allowed/missing":
							t.Errorf("a line for an exec whose pathname names nothing: %v", e)
						default:
							want := map[string]float64{"allowed/bad": -8, "allowed/busy": -26}[name]
							if want == 0 || e["syscall_ret"] != want || e["verdict"] != "observed" {
								t.Errorf("ordinary failure: %v", e)
							}
						}
					}
					wants := map[string]int{"blocked": 2}
					if recording == "full" {
						wants["allowed/bad"] = 1
						wants["allowed/busy"] = 1
						wants["allowed/true"] = 1
					}
					if len(counts) != len(wants) {
						t.Errorf("outcomes %v, want %v", counts, wants)
					}
					for name, want := range wants {
						if counts[name] != want {
							t.Errorf("%s: %d outcomes, want %d", name, counts[name], want)
						}
					}
					end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
					if sup, _ := end["supervisor"].(map[string]any); sup["exec_missing"] != float64(2) {
						t.Errorf("run_end.supervisor.exec_missing = %v, want 2: the two attempts of allowed/missing",
							sup["exec_missing"])
					}
					if t.Failed() {
						t.Log(ledgerDump(p.ledger))
						t.Log(out.String())
					}
				})
			}
		}
	}
}
