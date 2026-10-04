// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const execPrecedenceContract = `version: 0
name: plane-exec-precedence
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow:
    - python3
    - ./dir-first
    - ./dir-first/true
    - ./file-first/true
    - ./file-first
    - ./dir-before-name
    - true
    - ./name-before-dir
    - ./triple-name/true
    - ./triple-name
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`

const execPrecedenceAgent = `import subprocess
for name in ("dir-first", "file-first", "dir-before-name", "name-before-dir", "triple-name"):
    r = subprocess.run(["./" + name + "/true"])
    print("RESULT", name, "ok" if r.returncode == 0 else "exit=%d" % r.returncode, flush=True)
`

// The kernel and the pure policy evaluator choose the earliest exec.allow entry among file, bare-name and
// directory matches. A filesystem row's encoded ledger index is a different namespace from an exec entry's
// index; comparing the encoded indices previously made every file/name entry win over a directory.
func TestPlaneRunExecEntryPrecedence(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		tiers := []string{"cgroup"}
		if mode == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			t.Run(tier+"@"+mode, func(t *testing.T) {
				execPrecedenceRunCell(t, bin, uid, gid, mode, tier)
			})
		}
	}
}

func execPrecedenceRunCell(t *testing.T, bin string, uid, gid int, mode, tier string) {
	t.Helper()
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("the exec fixture is a copy of /bin/true: %v", err)
	}
	files := map[string]string{"agent.py": execPrecedenceAgent, "agent.yaml": execPrecedenceContract}
	wants := map[string]string{
		"dir-first":       "exec[./dir-first]",
		"file-first":      "exec[./file-first/true]",
		"dir-before-name": "exec[./dir-before-name]",
		"name-before-dir": "exec[true]",
		"triple-name":     "exec[true]",
	}
	for name := range wants {
		files[name+"/true"] = string(tool)
	}
	p := newPlaneProject(t, uid, gid, files, []string{"out"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	if err := cmd.Run(); err != nil {
		t.Fatalf("tego run --tier %s (%s): %v\n%s", tier, mode, err, out.String())
	}
	results := agentResults(t, out.String())
	events := runEvents(t, p.ledger)
	for name, wantRule := range wants {
		if results[name] != "ok" {
			t.Errorf("%s executed as %q, want ok", name, results[name])
		}
		var lines []map[string]any
		for _, e := range events {
			if e["kind"] == "exec" && strings.HasSuffix(fmt.Sprint(e["path"]), "/"+name+"/true") {
				lines = append(lines, e)
			}
		}
		if len(lines) != 1 {
			t.Errorf("%s: %d exec lines, want one: %v", name, len(lines), lines)
			continue
		}
		if line := lines[0]; line["verdict"] != "allow" || line["rule"] != wantRule ||
			line["mechanism"] != "plane" || line["decision_plane"] != mode {
			t.Errorf("%s: %v, want allow by %s in plane %s", name, line, wantRule, mode)
		}
	}
	if t.Failed() {
		t.Log(ledgerDump(p.ledger))
	}
}
