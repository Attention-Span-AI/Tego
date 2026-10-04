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
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// dropContract is planeContract under record: summary, kill test 4's and the default, where the filter leaves the
// plane every mutation its loaded hooks decide, write-opens and creat included (record: full keeps the open family
// notified, TIER3-PLAN T16).
var dropContract = strings.Replace(planeContract, "record: full", "record: summary", 1)

// dropAgent makes one mutation of each kind the narrowed filter no longer notifies, each in a directory no entry is
// (subdirectories of the write entry, which the recorder's directory index does not hold), then refuses two:
// `mv .git` and a mkdir outside every entry.
const dropAgent = `import os

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

attempt("mkdir-deep", lambda: os.mkdir("out/pkg/a/b"))
write("out/pkg/a/b/t.tmp")
attempt("rename-deep", lambda: os.rename("out/pkg/a/b/t.tmp", "out/pkg/a/b/t"))
attempt("rename-across", lambda: os.rename("out/pkg/a/b/t", "out/pkg/c/t"))
attempt("unlink-deep", lambda: os.unlink("out/pkg/c/t"))
attempt("rmdir-deep", lambda: os.rmdir("out/pkg/a/b"))
attempt("symlink-deep", lambda: os.symlink("f", "out/pkg/a/l"))
attempt("link-deep", lambda: os.link("out/pkg/a/f", "out/pkg/a/f2"))
attempt("truncate-deep", lambda: os.truncate("out/pkg/a/f", 0))
attempt("mv-git", lambda: os.rename("out/repo/.git", "out/repo/.git.old"))
attempt("mkdir-outside", lambda: os.mkdir("outside"))
`

// TestPlaneRunDropsAndNamesByPath is enforce-plane §2.13's condition 1 lifted (§2.15; TIER3-PLAN T16): in each plane
// mode this machine passes, a record: summary run at tier cgroup has its filter narrowed (the launcher logs what it
// no longer notifies), so the kernel recorder's line is each mutation's only line, and it names the mutation by its
// full path and the contract's rule on its own: an allowed unlink, rmdir, mkdir, rename (within a directory and
// across two), symlink, hard link and truncate in subdirectories of the write entry are one allow line each under
// the write entry's rule, never unmatched and never dev:ino/name, and the refused `mv .git` and a mkdir outside every
// entry one refused line each, by path.
func TestPlaneRunDropsAndNamesByPath(t *testing.T) {
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
	dir := t.TempDir()
	bin := buildPlaneTego(t, dir)
	requireTier(t, bin, "cgroup")
	modes := planeModesHere(t, bin)
	if len(modes) == 0 {
		t.Skip("no plane mode passes doctor's probe here")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) { planeDropCell(t, bin, uid, gid, mode) })
	}
}

func planeDropCell(t *testing.T, bin string, uid, gid int, mode string) {
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("the project's binary is a copy of /bin/true: %v", err)
	}
	files := map[string]string{
		"agent.py": dropAgent, "agent.yaml": dropContract, "out/pkg/a/f": "data\n",
		"out/repo/.git/HEAD": "ref: refs/heads/main\n", "out/repo/.git/hooks/pre-commit": "#!/bin/sh\n",
		"bin/tool": string(tool),
	}
	p := newPlaneProject(t, uid, gid, files, []string{"out/pkg/c", "out/secret"}, nil)
	// The launcher's debug line is what says the filter was narrowed: the ledger reads the same either way.
	cfg, err := os.ReadFile(p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.cfg, append(cfg, []byte("log:\n  level: debug\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.run(ctx, bin, "agent.yaml", mode, &out)
	runErr := cmd.Run()
	t.Logf("tego run (%s): %v\n%s", mode, runErr, out.String())
	if runErr != nil {
		t.Fatalf("the run did not complete: %v", runErr)
	}
	own, _ := os.ReadFile(filepath.Join(p.base, "home", ".tego", "tego.log"))
	if !bytes.Contains(own, []byte("the decision plane decides what the filter no longer notifies")) {
		t.Fatalf("the filter was not narrowed: the launcher's log has no drop line:\n%s", own)
	}
	res := agentResults(t, out.String())
	// Below Landlock ABI 3 (6.2) the filter's errno arm refuses truncate(2) with EPERM before any hook runs
	// (enforce-landlock R2, E31): no hook, no line, on AL2023's 6.1. The kernel's ABI says which applies, never the
	// result, so an EPERM from ABI 3 fails the cell rather than skipping it.
	abi, err := sys.LandlockABI()
	if err != nil {
		t.Fatalf("the Landlock ABI: %v", err)
	}
	truncates := abi >= 3
	if !truncates {
		if res["truncate-deep"] != "refused errno=1" {
			t.Errorf("truncate-deep on Landlock ABI %d: %q, want the filter's refused errno=1 (E31)", abi, res["truncate-deep"])
		}
		t.Logf("Landlock ABI %d: truncate(2) is refused by the filter, so its ledger line is not asked for", abi)
	}
	for _, name := range []string{"mkdir-deep", "rename-deep", "rename-across", "unlink-deep", "rmdir-deep",
		"symlink-deep", "link-deep", "truncate-deep"} {
		if name == "truncate-deep" && !truncates {
			continue
		}
		if res[name] != "ok" {
			t.Errorf("%s: %q, want ok", name, res[name])
		}
	}
	for _, name := range []string{"mv-git", "mkdir-outside"} {
		if !strings.HasPrefix(res[name], "refused") {
			t.Errorf("%s: %q, want refused", name, res[name])
		}
	}
	events := runEvents(t, p.ledger)
	pkg, write := filepath.Join(p.project, "out", "pkg"), "fs.write[./out/]"
	for _, c := range []struct {
		op, path, path2, verdict string
		rule                     func(string) bool
	}{
		{"mkdir", filepath.Join(pkg, "a", "b"), "", "allow", ruleIs(write)},
		{"rename", filepath.Join(pkg, "a", "b", "t.tmp"), filepath.Join(pkg, "a", "b", "t"), "allow", ruleIs(write)},
		{"rename", filepath.Join(pkg, "a", "b", "t"), filepath.Join(pkg, "c", "t"), "allow", ruleIs(write)},
		{"unlink", filepath.Join(pkg, "c", "t"), "", "allow", ruleIs(write)},
		{"unlink", filepath.Join(pkg, "a", "b"), "", "allow", ruleIs(write)}, // an rmdir is the unlink the supervisor calls it
		{"symlink", filepath.Join(pkg, "a", "l"), "f", "allow", ruleIs(write)},
		{"link", filepath.Join(pkg, "a", "f"), filepath.Join(pkg, "a", "f2"), "allow", ruleIs(write)},
		{"truncate", filepath.Join(pkg, "a", "f"), "", "allow", ruleIs(write)},
		{"rename", filepath.Join(p.project, "out", "repo", ".git"), filepath.Join(p.project, "out", "repo", ".git.old"),
			"refused", func(r string) bool { return strings.HasPrefix(r, "fs.deny_write[") }},
		{"mkdir", filepath.Join(p.project, "outside"), "", "refused", ruleIs("unmatched")},
	} {
		if c.op == "truncate" && !truncates {
			continue
		}
		var lines []map[string]any
		for _, e := range events {
			if e["kind"] == "fs" && e["op"] == c.op && e["path"] == c.path {
				lines = append(lines, e)
			}
		}
		if len(lines) != 1 {
			t.Errorf("%s %s: %d lines, want one: %v", c.op, c.path, len(lines), lines)
			continue
		}
		e := lines[0]
		p2, _ := e["path2"].(string)
		if e["verdict"] != c.verdict || !c.rule(fmt.Sprint(e["rule"])) || p2 != c.path2 || e["source"] != "kernel" {
			t.Errorf("%s %s: %v, want %s, path2 %q, source kernel", c.op, c.path, e, c.verdict, c.path2)
		}
	}
	for _, e := range events {
		if e["kind"] != "fs" {
			continue
		}
		if path := fmt.Sprint(e["path"]); !strings.HasPrefix(path, "/") {
			t.Errorf("an fs line not named by its path: %v", e)
		}
	}
}

func ruleIs(want string) func(string) bool { return func(got string) bool { return got == want } }
