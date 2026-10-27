// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationUserDenyWriteAtLandlock is ADR 0071 at tier landlock, unprivileged, through the real binary: with
// fs.write ["./out/", "./out/deploy/tmp/"] and fs.deny_write ["./out/deploy/"], the agent's `echo > out/deploy/a` is
// refused by the supervisor (R15c) and leaves the file as it was, the refused line names fs.deny_write[./out/deploy/],
// a write in out/deploy/tmp/, which the nested write entry reopens, goes ahead, and so does the rest of the agent;
// run_start (record minor 19 or later) lists fs.deny_write in best_effort, since no decision plane decides the entry.
func TestIntegrationUserDenyWriteAtLandlock(t *testing.T) {
	bin := tegoBinary(t)
	plain := strings.Replace(contractFor("iuserdenywrite", []string{"/bin/sh", "-c",
		"echo x > out/deploy/a; echo y > out/deploy/tmp/b; echo done > out/done"}, []string{"/bin/sh"}),
		"record: summary\n", "record: full\n", 1)
	contract := strings.Replace(plain, "  write: [\"./out/\"]\n",
		"  write: [\"./out/\", \"./out/deploy/tmp/\"]\n  deny_write: [\"./out/deploy/\"]\n", 1)
	if contract == plain {
		t.Fatal("the contract has no fs.write line to extend")
	}
	// The fixture makes out/; the entry and the nested write entry's parent must exist before `tego run` compiles the
	// contract that names them, which replaces the fixture's.
	f := newFixture(t, plain)
	if err := os.MkdirAll(filepath.Join(f.out, "deploy", "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.out, "deploy", "a"), []byte("orig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, f.out, filepath.Join(f.out, "deploy"), filepath.Join(f.out, "deploy", "tmp"), filepath.Join(f.out, "deploy", "a"))
	cfg := writeMachineConfig(t, f)
	cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	if b, err := os.ReadFile(filepath.Join(f.out, "deploy", "a")); err != nil || string(b) != "orig\n" {
		t.Errorf("out/deploy/a = %q, %v: the agent's write in the fs.deny_write entry went through", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(f.out, "deploy", "tmp", "b")); err != nil || string(b) != "y\n" {
		t.Errorf("out/deploy/tmp/b = %q, %v: the nested write entry reopens it", b, err)
	}
	if _, err := os.Stat(filepath.Join(f.out, "done")); err != nil {
		t.Errorf("the agent did not run on past the refused write: %v\n%s", err, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", f.root, dirs)
	}
	evs := events(t, dirs[0])
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart {
		t.Fatalf("the run's first event is not run_start: %v", evs)
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.Tier != "landlock" || start.RecordMinor < record.MinorUserDenyWrite || !slices.Contains(start.BestEffort, agent.BestEffortUserDenyWrite) ||
		slices.Contains(start.BestEffort, agent.BestEffortDenyWrite) {
		t.Errorf("run_start tier %s minor %d best_effort %v, want landlock, at least %d, and %s alone of the deny_write cells",
			start.Tier, start.RecordMinor, start.BestEffort, record.MinorUserDenyWrite, agent.BestEffortUserDenyWrite)
	}
	const rule = "fs.deny_write[./out/deploy/]"
	if !slices.ContainsFunc(evs, func(e *record.Event) bool {
		return e.Kind == record.KindFS && e.Verdict == record.VerdictRefused && e.Rule == rule && e.Source == record.SourceSeccomp
	}) {
		for _, e := range evs {
			if e.Verdict == record.VerdictRefused {
				t.Logf("refused: %+v", e)
			}
		}
		t.Errorf("no refused seccomp (supervisor) fs line under %s", rule)
	}
	if !slices.ContainsFunc(evs, func(e *record.Event) bool {
		var p record.FSPayload
		return e.Kind == record.KindFS && e.Verdict == record.VerdictAllow && e.Rule == "fs.write[./out/deploy/tmp/]" &&
			e.DecodePayload(&p) == nil && strings.HasSuffix(p.Path, "/out/deploy/tmp/b")
	}) {
		t.Error("no allowed fs line under the nested write entry for out/deploy/tmp/b")
	}
}

// userDenyWriteReviewAgent reports each action as "RESULT <name> <outcome>".
const userDenyWriteReviewAgent = `import os

def attempt(name, fn):
    try:
        fn()
        print("RESULT", name, "ok", flush=True)
    except OSError as e:
        print("RESULT", name, "refused errno=%d" % e.errno, flush=True)

def write(p):
    with open(p, "w") as f:
        f.write("x")

attempt("write-builtin-reopened", lambda: write("out/.claude/projects/x"))
attempt("unlink-link-entry", lambda: os.unlink("out/ci"))
attempt("mkdir-link-entry", lambda: os.mkdir("out/ci"))
attempt("write-reopened", lambda: write("out/deploy/tmp/b"))
attempt("rename-reopened-away", lambda: os.rename("out/deploy/tmp", "out/t2"))
os.symlink(".", "out/s")
attempt("rename-onto-reopened", lambda: os.rename("out/s", "out/deploy/tmp"))
attempt("write-beside", lambda: write("out/ok.txt"))
`

// TestIntegrationUserDenyWriteReviewAtLandlock runs the deny_write shapes at tier landlock, unprivileged, through the
// real binary. out/.claude/, a built-in target, named in fs.deny_write beside a write entry inside it,
// out/.claude/projects/, still refuses a write beneath that write entry, under the built-in target's rule.
// out/ci, a symlink leading to ../ext/ci outside every write entry, named in fs.deny_write, is held at its name: the
// agent can neither remove it nor make a directory in its place. The reopening write entry's own name,
// out/deploy/tmp, is the entry's: it cannot be renamed away, nor the agent's symlink renamed onto it, while a write
// beneath it goes ahead.
func TestIntegrationUserDenyWriteReviewAtLandlock(t *testing.T) {
	bin := tegoBinary(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	head := fmt.Sprintf("version: 0\nname: iuserdenywrite-review\ncommand: [%q, \"./agent.py\"]\ntier: landlock\nfs:\n", python)
	tail := fmt.Sprintf("exec:\n  allow: [%q, %q]\nenv:\n  pass: [\"PATH\", \"HOME\", \"PYTHONDONTWRITEBYTECODE\"]\nlimits:\n  pids: 64\nrecord: full\n",
		python, resolved)
	// The fixture compiles the plain contract; the entries must exist before `tego run` compiles the one naming them.
	f := newFixture(t, head+"  write: [\"./out/\"]\n"+tail)
	for _, d := range []string{filepath.Join(f.out, "deploy", "tmp"), filepath.Join(f.out, ".claude", "projects"), filepath.Join(f.dir, "ext", "ci")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(f.out, "ci")
	if err := os.Symlink(filepath.Join("..", "ext", "ci"), link); err != nil {
		t.Fatal(err)
	}
	contract := head + "  write: [\"./out/\", \"./out/deploy/tmp/\", \"./out/.claude/projects/\"]\n" +
		"  deny_write: [\"./out/deploy/\", \"./out/.claude/\", \"./out/ci\"]\n" + tail
	for name, body := range map[string]string{"agent.yaml": contract, "agent.py": userDenyWriteReviewAgent} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agentOwnsTree(t, f.out, filepath.Join(f.dir, "ext"))
	agentOwns(t, filepath.Join(f.dir, "agent.yaml"), filepath.Join(f.dir, "agent.py"))
	cfg := writeMachineConfig(t, f)
	cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	res := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.SplitN(strings.TrimSpace(line), " ", 3); len(fields) == 3 && fields[0] == "RESULT" {
			res[fields[1]] = fields[2]
		}
	}
	for _, name := range []string{"write-builtin-reopened", "unlink-link-entry", "mkdir-link-entry", "rename-reopened-away", "rename-onto-reopened"} {
		if !strings.HasPrefix(res[name], "refused") {
			t.Errorf("%s: %q, want refused\n%s", name, res[name], out)
		}
	}
	for _, name := range []string{"write-reopened", "write-beside"} {
		if res[name] != "ok" {
			t.Errorf("%s: %q, want ok\n%s", name, res[name], out)
		}
	}
	if dst, err := os.Readlink(link); err != nil || dst != filepath.Join("..", "ext", "ci") {
		t.Errorf("out/ci after the run: %q, %v; the link entry must be left as it was", dst, err)
	}
	if fi, err := os.Lstat(filepath.Join(f.out, "deploy", "tmp")); err != nil || !fi.IsDir() {
		t.Errorf("out/deploy/tmp after the run: %v, %v; want the write entry's directory", fi, err)
	}
	if _, err := os.Lstat(filepath.Join(f.out, ".claude", "projects", "x")); err == nil {
		t.Error("out/.claude/projects/x was written: the built-in target beneath the entry's place must refuse it")
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", f.root, dirs)
	}
	evs := events(t, dirs[0])
	refusedUnder := func(rule, suffix string) bool {
		return slices.ContainsFunc(evs, func(e *record.Event) bool {
			var p record.FSPayload
			return e.Kind == record.KindFS && e.Verdict == record.VerdictRefused && e.Rule == rule &&
				e.DecodePayload(&p) == nil && strings.HasSuffix(p.Path, suffix)
		})
	}
	for _, c := range []struct{ rule, suffix string }{
		{"fs.deny_write[" + filepath.Join(f.out, ".claude") + "]", "/out/.claude/projects/x"},
		{"fs.deny_write[./out/ci]", "/out/ci"},
		{"fs.deny_write[./out/deploy/]", "/out/deploy/tmp"},
	} {
		if !refusedUnder(c.rule, c.suffix) {
			for _, e := range evs {
				if e.Verdict == record.VerdictRefused {
					t.Logf("refused: %+v", e)
				}
			}
			t.Errorf("no refused fs line under %s for a path ending %s", c.rule, c.suffix)
		}
	}
}
