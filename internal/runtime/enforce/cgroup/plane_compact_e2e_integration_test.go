// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// compactEnvFiles is ADR 0043 C10's count: more .env files than the plane keys without compaction (decide's
// TestCompactedTableFits holds that 4,500 rows without name entries are over the slot's caps).
const compactEnvFiles = 4500

const compactContract = `version: 0
name: compacted-env
command: ["python3", "./agent.py"]
fs:
  write: ["./out/", "./work/"]
exec:
  allow: [python3]
net:
  allow: []
env:
  pass: ["PATH", "HOME", "PYTHONDONTWRITEBYTECODE"]
record: full
`

// compactAgent reads every .env file, the hard link of one under another name and a plain file, and prints one JSON
// line: how many reads were refused with EACCES, the files read or refused otherwise, and the other two outcomes.
const compactAgent = `import errno, json

def outcome(p):
    try:
        with open(p) as f:
            f.read()
        return "ok"
    except OSError as e:
        return "errno=%d" % e.errno

refused, other = 0, []
for i in range(COUNT):
    p = "work/s%d/.env" % i
    o = outcome(p)
    if o == "errno=%d" % errno.EACCES:
        refused += 1
    else:
        other.append(p + " " + o)
print("RESULT " + json.dumps({"refused": refused, "other": other[:5], "link": outcome("work/h/other.txt"),
    "plain": outcome("work/plain.txt")}), flush=True)
`

// TestCompactedTableStaysAtBPFLSM is ADR 0043 D6 in a governed run: a project with 4,500 .env files beneath a write
// entry compiles to a table the plane holds only by compaction, which compile reports with the rows it dropped; an
// auto run is given tier bpflsm; every file is refused by the plane and named by its own expansion entry, the row
// compaction dropped (the recorder's naming); a file with a second link keeps its row (D6 (b)) and is refused through
// its other name, which no name entry covers; a plain file beside them is read.
func TestCompactedTableStaysAtBPFLSM(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	lsm := false
	for _, m := range modes {
		lsm = lsm || m == "lsm"
	}
	t.Run("bpflsm", func(t *testing.T) {
		if !lsm {
			t.Skip("tier bpflsm needs the plane's lsm mode (bpf in the active LSM list), which this boot lacks")
		}
		compactedRunCell(t, bin, uid, gid)
	})
}

// compactedRunCell is TestCompactedTableStaysAtBPFLSM's run, on a boot with the plane's lsm mode.
func compactedRunCell(t *testing.T, bin string, uid, gid int) {
	t.Helper()
	files := map[string]string{"agent.py": strings.ReplaceAll(compactAgent, "COUNT", fmt.Sprint(compactEnvFiles)), "agent.yaml": compactContract,
		"work/plain.txt": "p\n", "work/h/.env": "H=1\n"}
	for i := range compactEnvFiles {
		files[fmt.Sprintf("work/s%d/.env", i)] = fmt.Sprintf("K%d=V\n", i)
	}
	p := newPlaneProject(t, uid, gid, files, []string{"out"}, map[string]string{"work/h/other.txt": "work/h/.env"})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// compile reports the compaction and the rows it dropped.
	compile := p.runAt(ctx, bin, "", "agent.yaml", "lsm", nil)
	compile.Args = []string{bin, "compile", "agent.yaml"}
	var cout strings.Builder
	compile.Stdout, compile.Stderr = &cout, &cout
	if err := compile.Run(); err != nil {
		t.Fatalf("tego compile: %v\n%s", err, cout.String())
	}
	var dropped, keyed int
	for line := range strings.SplitSeq(cout.String(), "\n") {
		if strings.HasPrefix(line, "plane     ") {
			_, _ = fmt.Sscanf(line, "plane     %d per-file deny_read rows held by the name rows (ADR 0043 D6); %d paths keyed",
				&dropped, &keyed)
		}
	}
	if dropped < compactEnvFiles-1024 {
		t.Fatalf("compile reported %d rows dropped (%d keyed) for %d files:\n%s", dropped, keyed, compactEnvFiles, cout.String())
	}
	t.Logf("compile: %d per-file rows held by the name rows, %d paths keyed", dropped, keyed)

	// An auto run: the machine's selection, under the lsm pin.
	var out lockedBuffer
	run := p.runAt(ctx, bin, "", "agent.yaml", "lsm", &out)
	start := time.Now()
	if err := run.Run(); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out.String())
	}
	t.Logf("the run took %v", time.Since(start))
	var res struct {
		Refused     int
		Other       []string
		Link, Plain string
	}
	for line := range strings.SplitSeq(out.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "RESULT "); ok {
			if err := json.Unmarshal([]byte(rest), &res); err != nil {
				t.Fatal(err)
			}
		}
	}
	if res.Refused != compactEnvFiles || len(res.Other) != 0 || res.Link != "errno=13" || res.Plain != "ok" {
		t.Fatalf("refused %d of %d (others %v), the second link %s, the plain file %s\n%s", res.Refused, compactEnvFiles,
			res.Other, res.Link, res.Plain, out.String())
	}
	named := map[string]bool{}
	var tier any
	for _, e := range runEvents(t, p.ledger) {
		switch {
		case e["kind"] == "run_start":
			tier = e["tier"]
		case e["kind"] == "fs" && e["verdict"] == "refused":
			path, _ := e["path"].(string)
			if e["mechanism"] == "plane" && e["rule"] == "fs.deny_read["+path+"]" {
				named[path] = true
			}
		}
	}
	if tier != "bpflsm" {
		t.Errorf("the auto run was given tier %v, want bpflsm", tier)
	}
	missing := 0
	for i := range compactEnvFiles {
		if !named[filepath.Join(p.project, fmt.Sprintf("work/s%d/.env", i))] {
			missing++
		}
	}
	if missing != 0 {
		t.Errorf("%d of %d refusals have no plane line named by the file's own entry", missing, compactEnvFiles)
	}
	if link := filepath.Join(p.project, "work/h/other.txt"); !refusedAt(runEvents(t, p.ledger), link) {
		t.Errorf("no refusal line for the second link %s", link)
	}
}

// refusedAt reports whether the events hold a refused fs line at path.
func refusedAt(events []map[string]any, path string) bool {
	for _, e := range events {
		if e["kind"] == "fs" && e["verdict"] == "refused" && e["path"] == path {
			return true
		}
	}
	return false
}
