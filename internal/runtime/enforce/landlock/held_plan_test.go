// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Compile's resolved names must not substitute for the objects Prepare holds.
// Retargeting a grant or deny before Prepare changes containment and must trip I5.
func TestHeldPlanDetectsChangedContainment(t *testing.T) {
	for _, changeGrant := range []bool{true, false} {
		t.Run(map[bool]string{true: "write", false: "deny"}[changeGrant], func(t *testing.T) {
			root := tempDir(t)
			mkTree(t, root, "work/secret", "other/secret")
			work, other := filepath.Join(root, "work"), filepath.Join(root, "other")
			link := filepath.Join(root, "link")
			if err := os.Symlink(other, link); err != nil {
				t.Fatal(err)
			}
			write, target := fsRule(agent.FSWrite, link), agent.FSRule{Kind: agent.FSDenyRead, Path: filepath.Join(work, "secret")}
			write.Resolved = other
			if !changeGrant {
				write = fsRule(agent.FSWrite, other)
				target = agent.FSRule{Kind: agent.FSDenyRead, Path: filepath.Join(link, "secret"), Resolved: filepath.Join(other, "secret"), Unenforced: true}
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(work, link); err != nil {
				t.Fatal(err)
			}
			rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{write, target}}
			if err := prepareErr(t, 7, rt, nil); !errors.Is(err, ErrRulesetBuild) {
				t.Fatalf("changed held containment must fail I5, got %v", err)
			}
		})
	}
}

// Once a grant is held, later path changes must not change the plan's object.
func TestHeldPlanKeepsGrantSnapshot(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "work/secret", "other/secret")
	work, other, link := filepath.Join(root, "work"), filepath.Join(root, "other"), filepath.Join(root, "link")
	if err := os.Symlink(work, link); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: link, Resolved: work, Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: filepath.Join(work, "secret"), Unenforced: true},
	}}
	bd := newBuilder(context.Background(), rt, Run{}, profileFor(7), &fakeSyscalls{abi: 7})
	t.Cleanup(func() {
		if err := bd.fds.closeAll(); err != nil {
			t.Error(err)
		}
	})
	if err := bd.fsEntries(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if err := bd.denyRead(); err != nil {
		t.Fatalf("held grant changed after open: %v", err)
	}
	first := bd.fds.paths[link]
	if _, err := bd.hold(link, kindWrite, 0); err != nil {
		t.Fatal(err)
	}
	if bd.fds.paths[link] != first {
		t.Fatal("a held grant was reopened at a different object")
	}
}

// A shared symlink can move the grant and its nested deny together. Containment
// is unchanged, but the fallback still names the compiled resolved subtree.
func TestHeldPlanRejectsChangedNamesWithSameContainment(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "before/secret", "after/secret")
	before, after, link := filepath.Join(root, "before"), filepath.Join(root, "after"), filepath.Join(root, "link")
	if err := os.Symlink(before, link); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: link, Resolved: before, Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: filepath.Join(link, "secret"), Resolved: filepath.Join(before, "secret"), Unenforced: true},
	}}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(after, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareErr(t, 7, rt, nil); !errors.Is(err, ErrRulesetBuild) {
		t.Fatalf("same containment with changed compiled decision names must fail, got %v", err)
	}
}
