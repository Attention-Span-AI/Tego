// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// userDenyWriteContract governs a write directory out/ holding an fs.deny_write directory out/deploy/ (reopened at
// out/deploy/tmp/ by a nested write entry) and an fs.deny_write file out/conf.yml, which a hard link made before the
// run, out/conf-alias, also names (ADR 0071). out/.claude/ is a built-in target (R20) the contract also names in
// fs.deny_write, with a write entry inside it, out/.claude/projects/, which reopens the declared entry but never the
// built-in target. out/ci is a symlink to ../ext/ci, outside every write entry, that the contract names
// in fs.deny_write: it is held at its own name.
const userDenyWriteContract = `version: 0
name: plane-deny-write
command: ["python3", "./agent.py"]
fs:
  write: ["./out/", "./out/deploy/tmp/", "./out/.claude/projects/"]
  deny_write: ["./out/deploy/", "./out/conf.yml", "./out/.claude/", "./out/ci"]
exec:
  allow: ["python3"]
net:
  allow: []
env:
  pass: ["PATH", "HOME", "PYTHONDONTWRITEBYTECODE"]
record: full
`

// userDenyWriteAgent reports each action as "RESULT <name> <outcome>".
const userDenyWriteAgent = `import os

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def attempt(name, fn):
    try:
        fn()
        result(name, "ok")
    except OSError as e:
        result(name, "refused errno=%d" % e.errno)

def write(p):
    with open(p, "w") as f:
        f.write("x")

attempt("write-in-entry", lambda: write("out/deploy/a"))
attempt("create-in-entry", lambda: write("out/deploy/new"))
attempt("unlink-in-entry", lambda: os.unlink("out/deploy/b"))
attempt("mkdir-in-entry", lambda: os.mkdir("out/deploy/d"))
attempt("chmod-in-entry", lambda: os.chmod("out/deploy/a", 0o600))
attempt("rename-into-entry", lambda: os.rename("out/x", "out/deploy/x"))
attempt("link-out-of-entry", lambda: os.link("out/deploy/a", "out/a-alias"))
attempt("write-file-entry", lambda: write("out/conf.yml"))
attempt("write-hard-link-alias", lambda: write("out/conf-alias"))
attempt("write-linked-in-dir-entry", lambda: write("out/linked-alias"))
attempt("write-linked-in-builtin", lambda: write("out/tasks-alias"))
attempt("write-linked-pair", lambda: write("out/deploy/a2"))
attempt("write-linked-to-file-entry", lambda: write("out/deploy/c2"))
attempt("write-reopened", lambda: write("out/deploy/tmp/b"))
attempt("write-beside", lambda: write("out/ok.txt"))
attempt("write-builtin-reopened", lambda: write("out/.claude/projects/x"))
attempt("unlink-link-entry", lambda: os.unlink("out/ci"))
attempt("rename-link-entry", lambda: os.rename("out/ci", "out/ci-old"))
attempt("rename-reopened-away", lambda: os.rename("out/deploy/tmp", "out/t2"))
os.symlink(".", "out/s")
attempt("rename-onto-reopened", lambda: os.rename("out/s", "out/deploy/tmp"))
`

// TestPlaneUserDenyWrite is ADR 0071 (3) in the kernel: in each plane mode this machine passes, at tier cgroup and, where
// lsm passes, at tier bpflsm, the decision plane refuses every modification at or beneath an fs.deny_write entry — a
// write, a create, an unlink, a mkdir, a chmod, a rename into it and a hard link out of it — and a write through a hard
// link to a file entry made before the run, which no pathname check can see: the plane keys the entry's inode. The
// nested write entry reopens its subtree, a write beside the entries goes ahead, the refused lines name
// fs.deny_write[<entry as declared>], and run_start lists no fs.deny_write best-effort cell, since the plane decides.
// The fanotify listener is the contrast: the supervisor refuses on the copied pathname (R15c), the hard-link alias is
// that refusal's residual, and run_start lists fs.deny_write. Two names of one file beneath the directory entry
// (out/deploy/a2 for out/deploy/a), a file there that is the file entry under another name (out/deploy/c2 for
// out/conf.yml) and two names beneath the built-in target out/.vscode leave the table one the plane holds (each name
// was keyed, two rows named one inode, and the run fell back to the listener at tier cgroup and was refused at tier
// bpflsm), so run_start still names the plane mode and the bpflsm run exits 0.
func TestPlaneUserDenyWrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the plane needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	bin := buildPlaneTego(t, t.TempDir())
	requireTier(t, bin, "cgroup")
	modes := planeModesHere(t, bin)
	if len(modes) == 0 {
		t.Skip("no plane mode passes doctor's probe here")
	}
	for _, mode := range append(modes, PlaneFanotify) {
		t.Run("cgroup/"+mode, func(t *testing.T) { userDenyWriteCell(t, bin, uid, gid, mode, "cgroup") })
	}
	if slices.Contains(modes, "lsm") {
		t.Run("bpflsm/lsm", func(t *testing.T) { userDenyWriteCell(t, bin, uid, gid, "lsm", "bpflsm") })
	}
}

func userDenyWriteCell(t *testing.T, bin string, uid, gid int, mode, tier string) {
	p := newPlaneProject(t, uid, gid, map[string]string{
		"agent.py": userDenyWriteAgent, "agent.yaml": userDenyWriteContract,
		"out/deploy/a": "a\n", "out/deploy/b": "b\n", "out/conf.yml": "conf\n", "out/x": "x\n", "out/.claude/settings.json": "{}\n",
		"ext/ci/pipeline.yml": "ci\n", "out/deploy/linked": "l\n", "out/.vscode/tasks.json": "{}\n",
	}, []string{"out/deploy/tmp", "out/.claude/projects"}, map[string]string{"out/conf-alias": "out/conf.yml",
		"out/linked-alias": "out/deploy/linked", "out/tasks-alias": "out/.vscode/tasks.json",
		"out/deploy/a2": "out/deploy/a", "out/deploy/c2": "out/conf.yml", "out/.vscode/launch.json": "out/.vscode/tasks.json"})
	ciLink := filepath.Join(p.project, "out", "ci")
	if err := os.Symlink(filepath.Join("..", "ext", "ci"), ciLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(ciLink, uid, gid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	if err := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out).Run(); err != nil {
		t.Fatalf("tego run --tier %s (%s): %v\n%s", tier, mode, err, out.String())
	}
	t.Logf("tego run --tier %s (%s):\n%s", tier, mode, out.String())
	res := agentResults(t, out.String())
	plane := mode != PlaneFanotify
	for _, name := range []string{"write-in-entry", "create-in-entry", "unlink-in-entry", "mkdir-in-entry", "rename-into-entry",
		"link-out-of-entry", "write-file-entry", "write-builtin-reopened", "unlink-link-entry", "rename-link-entry",
		"write-linked-pair", "write-linked-to-file-entry",
		"rename-reopened-away", "rename-onto-reopened"} {
		if !strings.HasPrefix(res[name], "refused") {
			t.Errorf("%s: %q, want refused", name, res[name])
		}
	}
	for _, name := range []string{"write-reopened", "write-beside"} {
		if res[name] != "ok" {
			t.Errorf("%s: %q, want ok", name, res[name])
		}
	}
	// Only a kernel decision plane refuses an attribute change (SEMANTICS §1) and a write through a hard link made
	// before the run, which names the file entry's inode, or that of a file beneath the directory entry (compile
	// records it, the plane keys it), under another name (R15c's residual on the listener).
	for _, name := range []string{"chmod-in-entry", "write-hard-link-alias", "write-linked-in-dir-entry", "write-linked-in-builtin"} {
		if refused := strings.HasPrefix(res[name], "refused"); refused != plane {
			t.Errorf("%s: %q, want refused exactly where the plane decides (%s)", name, res[name], mode)
		}
	}
	for name, want := range map[string]string{"out/deploy/a": "a\n", "out/deploy/b": "b\n"} {
		if b, err := os.ReadFile(filepath.Join(p.project, name)); err != nil || string(b) != want {
			t.Errorf("%s after the run: %q, %v; want it unchanged", name, b, err)
		}
	}
	if plane {
		if b, err := os.ReadFile(filepath.Join(p.project, "out", "conf.yml")); err != nil || string(b) != "conf\n" {
			t.Errorf("out/conf.yml after the run: %q, %v; the plane holds the file entry's inode, under any name", b, err)
		}
		for name, want := range map[string]string{"out/deploy/linked": "l\n", "out/.vscode/tasks.json": "{}\n"} {
			if b, err := os.ReadFile(filepath.Join(p.project, name)); err != nil || string(b) != want {
				t.Errorf("%s after the run: %q, %v; the plane holds the linked file's inode, under any name", name, b, err)
			}
		}
	}
	events := runEvents(t, p.ledger)
	start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" })
	if start == nil || start["tier"] != tier || start["decision_plane"] != mode {
		t.Errorf("run_start %v, want tier %s decision_plane %s", start, tier, mode)
	}
	if be, _ := start["best_effort"].([]any); slices.Contains(be, any("fs.deny_write")) == plane {
		t.Errorf("run_start best_effort %v: fs.deny_write belongs there exactly when no plane decides (%s)", start["best_effort"], mode)
	}
	// The reopening write entry's own name keeps its directory: no rename moved it away or put the
	// agent's symlink in its place.
	if fi, err := os.Lstat(filepath.Join(p.project, "out", "deploy", "tmp")); err != nil || !fi.IsDir() {
		t.Errorf("out/deploy/tmp after the run: %v, %v; want the write entry's directory", fi, err)
	}
	if dst, err := os.Readlink(ciLink); err != nil || dst != filepath.Join("..", "ext", "ci") {
		t.Errorf("out/ci after the run: %q, %v; the link entry must be left as it was", dst, err)
	}
	for _, rule := range []string{"fs.deny_write[./out/deploy/]", "fs.deny_write[./out/conf.yml]", "fs.deny_write[./out/ci]"} {
		if findEvent(events, func(e map[string]any) bool {
			return e["kind"] == "fs" && e["verdict"] == "refused" && e["rule"] == rule
		}) == nil {
			t.Errorf("no refused fs line under %s", rule)
		}
	}
	// The write beneath out/.claude/projects/ is refused under the built-in target, which the entry at its place left
	// in the table.
	builtIn := "fs.deny_write[" + filepath.Join(p.project, "out", ".claude") + "]"
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["verdict"] == "refused" && e["rule"] == builtIn &&
			strings.HasSuffix(fmt.Sprint(e["path"]), filepath.Join(".claude", "projects", "x"))
	}) == nil {
		t.Errorf("no refused fs line under %s for out/.claude/projects/x", builtIn)
	}
	if plane && findEvent(events, func(e map[string]any) bool {
		return e["verdict"] == "refused" && e["source"] == "kernel" && e["mechanism"] == "plane" &&
			e["rule"] == "fs.deny_write[./out/conf.yml]" && strings.HasSuffix(fmt.Sprint(e["path"]), "conf-alias")
	}) == nil {
		t.Error("no refused source=kernel mechanism=plane line naming fs.deny_write[./out/conf.yml] for the hard-link alias")
	}
	if plane && findEvent(events, func(e map[string]any) bool {
		return e["verdict"] == "refused" && e["source"] == "kernel" && e["mechanism"] == "plane" &&
			e["rule"] == "fs.deny_write[./out/deploy/]" && strings.HasSuffix(fmt.Sprint(e["path"]), "linked-alias")
	}) == nil {
		t.Error("no refused source=kernel mechanism=plane line naming fs.deny_write[./out/deploy/] for the linked file's alias")
	}
}
