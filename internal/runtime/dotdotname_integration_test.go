// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationDotDotLineNamesTheFileItsVerdictWasTakenOn: an agent flips out/lk between out/a/sub and ../b/sub
// while it
// write-opens out/lk/../f, with fs.write ["./out/"]. Every fs line for f names the file its verdict and rule were taken
// on: an allow names out/a/f, inside the write entry, and a refusal names b/f, outside it. In an earlier build a
// second walk named the line apart from the decision's, and of 1500 opens about 240 lines read "allow b/f, rule
// fs.write[./out/]" or "refused out/a/f, write-outside-contract".
func TestIntegrationDotDotLineNamesTheFileItsVerdictWasTakenOn(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	py, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contractText := fmt.Sprintf(`version: 0
name: idotdotname
command: [%q]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: [%q]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: full
`, py, py)
	f := newFixtureIn(t, project, contractText, nil)
	for _, d := range []string{"out/a/sub", "b/sub"} {
		if err := os.MkdirAll(filepath.Join(project, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"out/a/f", "b/f"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a/sub", filepath.Join(project, "out/lk")); err != nil {
		t.Fatal(err)
	}
	script := `
import os, threading
stop = False
def flip():
    i = 0
    while not stop:
        t = "a/sub" if i % 2 == 0 else "../b/sub"
        try:
            os.symlink(t, "out/lk.tmp")
            os.rename("out/lk.tmp", "out/lk")
        except OSError:
            try: os.unlink("out/lk.tmp")
            except OSError: pass
        i += 1
th = threading.Thread(target=flip)
th.start()
for i in range(1500):
    try:
        os.close(os.open("out/lk/../f", os.O_WRONLY))
    except OSError:
        pass
stop = True
th.join()
`
	res, err := Run(context.Background(), f.rt, []string{py, "-c", script}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the agent exited %d", res.ExitCode)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	inside, outside := project+"/out/a/f", project+"/b/f"
	counts := map[string]int{}
	for _, e := range events(t, dirs[0]) {
		var p record.FSPayload
		if e.Kind != record.KindFS || e.DecodePayload(&p) != nil || p.Op != record.FSOpen || !strings.HasSuffix(p.Path, "/f") {
			continue
		}
		line := fmt.Sprintf("%s %s rule=%s reason=%s", e.Verdict, strings.TrimPrefix(p.Path, project+"/"), e.Rule, e.Reason)
		counts[line]++
		switch {
		case e.Verdict == record.VerdictAllow && p.Path == inside && e.Rule == "fs.write[./out/]":
		case e.Verdict == record.VerdictRefused && p.Path == outside && e.Reason == record.ReasonWriteOutsideContract:
		default:
			if counts[line] == 1 {
				t.Errorf("line %q names a file its verdict was not taken on", line)
			}
		}
	}
	if len(counts) == 0 {
		t.Fatal("no fs line for f")
	}
	t.Logf("fs lines for f: %v", counts)
}
