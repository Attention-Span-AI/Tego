// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// compileProject compiles contract, the body of a version 0 contract, in the project root as tego run does, with its
// state beneath root.
func compileProject(t *testing.T, root, contract string) *agent.RuleTable {
	t.Helper()
	for _, d := range []string{"home", "ledger"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "agent.yaml")
	data := []byte("version: 0\nname: t\ncommand: [\"/bin/true\"]\n" + contract)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(path, data, nil)
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithCwd(root), agent.WithHome(filepath.Join(root, "home")), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	return rt
}

// TestPlaneHoldsLinkedFilesOfDenyWrite at the plane's own check: a table whose deny_write
// directory holds two names of one file, or a file that is another keyed row's file under another name, is one the
// plane holds (PlaneHoldable), where both names were keyed and the table ran on the fanotify listener at tier cgroup
// and was refused at tier bpflsm. The shapes: two hooks linked to each other beneath .git/hooks with no fs.deny_write
// at all (R20 alone); a file beneath an fs.deny_write directory linked to an fs.deny_write file entry; two names of one
// file beneath the directory entry, one of them with a third name outside it, which the plane keys once.
func TestPlaneHoldsLinkedFilesOfDenyWrite(t *testing.T) {
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	deploy, hooks := filepath.Join(repo, "deploy"), filepath.Join(repo, ".git", "hooks")
	for _, d := range []string{deploy, hooks, filepath.Join(repo, ".git", "objects"), filepath.Join(repo, ".git", "refs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for p, body := range map[string]string{
		filepath.Join(repo, ".git", "HEAD"): "ref: refs/heads/main\n", filepath.Join(repo, ".git", "config"): "[core]\n",
		filepath.Join(hooks, "pre-commit"): "#!/bin/sh\n", filepath.Join(repo, "conf.yml"): "x", filepath.Join(deploy, "a"): "x",
		filepath.Join(deploy, "x"): "x",
	} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for alias, src := range map[string]string{
		filepath.Join(hooks, "pre-push"): filepath.Join(hooks, "pre-commit"),
		filepath.Join(deploy, "conf"):    filepath.Join(repo, "conf.yml"),
		filepath.Join(deploy, "b"):       filepath.Join(deploy, "a"),
		filepath.Join(deploy, "x2"):      filepath.Join(deploy, "x"), filepath.Join(repo, "x-alias"): filepath.Join(deploy, "x"),
	} {
		if err := os.Link(src, alias); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		contract string
		linked   []string
		refused  []string // a write at each is refused by the rows' walk
	}{
		"r20-alone": {contract: "fs:\n  write: [\"./repo/\"]\n", refused: []string{filepath.Join(hooks, "pre-push")}},
		"deny-write": {contract: "fs:\n  write: [\"./repo/\"]\n  deny_write: [\"./repo/conf.yml\", \"./repo/deploy/\"]\n",
			linked: []string{filepath.Join(deploy, "x")}, refused: []string{filepath.Join(hooks, "pre-push"), filepath.Join(deploy, "b"),
				filepath.Join(deploy, "conf"), filepath.Join(deploy, "x")}},
	} {
		rt := compileProject(t, root, tc.contract)
		if !slices.Equal(rt.DenyWriteLinked, tc.linked) {
			t.Errorf("%s: DenyWriteLinked %v, want %v", name, rt.DenyWriteLinked, tc.linked)
		}
		rows, err := decide.CompilePlane(rt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := PlaneHoldable(rows); err != nil {
			t.Errorf("%s: PlaneHoldable = %v, want held", name, err)
		}
		for _, p := range tc.refused {
			if v := rows.Decide(p, decide.PlaneModify); v.Allow {
				t.Errorf("%s: a write at %s: %+v, want refused", name, p, v)
			}
		}
	}
}
