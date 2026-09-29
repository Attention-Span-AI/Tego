// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestHeldIdentityIsFixedAtOpenTime is docs/p0/enforce-landlock.md E12 (ADR 0010): a write entry declared
// through a symlink is whatever the link named when Prepare opened it. Retargeting the link afterwards
// does not move the held fd, so the rule stays on the inode Prepare saw and nothing here re-validates it.
func TestHeldIdentityIsFixedAtOpenTime(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "a/", "b/")
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "a"), link); err != nil {
		t.Fatal(err)
	}
	var stA, stB unix.Stat_t
	if err := unix.Stat(filepath.Join(root, "a"), &stA); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(root, "b"), &stB); err != nil {
		t.Fatal(err)
	}
	h, _ := prepare(t, 7, &agent.RuleTable{FS: []agent.FSRule{fsRule(agent.FSWrite, link)}})
	var held *openPath
	for i := range h.fds.open {
		p := &h.fds.open[i]
		var st unix.Stat_t
		if p.Kind == kindWrite && unix.Fstat(p.FD, &st) == nil && st.Ino == stA.Ino && st.Dev == stA.Dev {
			held = p
		}
	}
	if held == nil {
		t.Fatalf("no write entry holds the link's target a (ino %d)", stA.Ino)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "b"), link); err != nil {
		t.Fatal(err)
	}
	var now unix.Stat_t
	if err := unix.Fstat(held.FD, &now); err != nil {
		t.Fatal(err)
	}
	if now.Ino != stA.Ino || now.Ino == stB.Ino {
		t.Errorf("held fd names ino %d after the link moved, want a's %d and not b's %d (E12)", now.Ino, stA.Ino, stB.Ino)
	}
}

// TestConcurrentPreparesShareNothing is docs/p0/enforce-landlock.md E15: two runs whose deny_read targets sit
// under one parent build fully independent fd sets and rulesets. No number is shared, and closing one
// handle leaves the other's descriptors, ruleset included, open.
func TestConcurrentPreparesShareNothing(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "home/.ssh/id", "home/.aws/cred", "home/notes")
	rt := func(target string) *agent.RuleTable {
		return &agent.RuleTable{FS: []agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(root, "home", target))}}
	}
	h1, f1 := prepare(t, 7, rt(".ssh"))
	h2, f2 := prepare(t, 7, rt(".aws"))
	if len(f1.created) != 1 || len(f2.created) != 1 {
		t.Fatalf("rulesets created = %d and %d, want one each", len(f1.created), len(f2.created))
	}
	fds1 := map[int]bool{h1.rulesetFD: true}
	for _, p := range h1.fds.open {
		fds1[p.FD] = true
	}
	if fds1[h2.rulesetFD] {
		t.Errorf("both handles hold ruleset number %d", h2.rulesetFD)
	}
	var second []int
	for _, p := range h2.fds.open {
		if fds1[p.FD] {
			t.Errorf("fd %d (%s) is in both runs' sets", p.FD, p.Path)
		}
		second = append(second, p.FD)
	}
	if len(second) == 0 {
		t.Fatal("the second run holds nothing")
	}
	if err := h1.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fd := range append(second, h2.rulesetFD) {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Errorf("closing the first run closed the second's fd %d: %v", fd, err)
		}
	}
}

// TestPackageReadsNoClockAndKeepsNoPIDState is docs/p0/enforce-landlock.md E19 and E23: the ruleset and the
// filter are static, so nothing in this package reads wall-clock time, and it holds no PID-keyed state.
// The check is over the package's own non-test source: a call that reads the clock or asks for a process
// or thread id.
func TestPackageReadsNoClockAndKeepsNoPIDState(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v (%d files)", err, len(files))
	}
	clock := map[string]bool{"Now": true, "Since": true, "Until": true, "After": true, "Tick": true, "NewTimer": true, "NewTicker": true, "AfterFunc": true}
	pid := map[string]bool{"Getpid": true, "Getppid": true, "Gettid": true, "FindProcess": true, "Getpgid": true}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case id.Name == "time" && clock[sel.Sel.Name]:
				t.Errorf("%s: time.%s reads or waits on the clock (E19)", fset.Position(sel.Pos()), sel.Sel.Name)
			case (id.Name == "os" || id.Name == "unix" || id.Name == "syscall") && pid[sel.Sel.Name]:
				t.Errorf("%s: %s.%s keys state on a process id (E23)", fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
			}
			return true
		})
	}
}
