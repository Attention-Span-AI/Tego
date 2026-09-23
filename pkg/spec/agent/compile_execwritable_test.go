// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestExecAllowDirInsideWriteEntryWarns pins E38's main case. `exec.allow: [<dir>]` with
// `fs.write: [<ancestor>]` is a natural-looking contract for a repo with a scripts directory, and it
// hands the exec list away: Landlock's LANDLOCK_RULE_PATH_BENEATH is a file *hierarchy*
// (man 2 landlock_add_rule), so the EXECUTE grant covers files created after
// landlock_restrict_self, and the root tiers match the same directory by path prefix
// (internal/runtime/match.go matchExec). The agent writes a binary there and runs it.
//
// The assertion is that compile says so. Before this warning existed the contract compiled with no
// finding at all, while `deny_read` under the same directory, a redundant write entry, a mount
// point and a models[] host in net.allow all warned — the strictly weaker analogues.
// agent-contract.md E38: an exec entry inside a write entry warns exec-writable in every tier.
func TestExecAllowDirInsideWriteEntryWarns(t *testing.T) {
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			f := newFixture(t)
			tools := filepath.Join(f.project, "out", "tools")
			if err := os.MkdirAll(tools, 0o755); err != nil {
				t.Fatal(err)
			}

			c := f.load("version: 0\nname: a\ncommand: [python]\ntier: " + tier +
				"\nfs:\n  write: [\"out/\"]\nexec:\n  allow: [\"" + tools + "\"]\n")
			rt, ds := f.compile(c)

			if !hasCode(ds, CodeExecWritable) {
				t.Fatalf("exec.allow %s inside fs.write out/ produced no %s warning:\n%s", tools, CodeExecWritable, render(ds))
			}
			out := render(ds)
			if !strings.Contains(out, tools) || !strings.Contains(out, "list the individual binaries") {
				t.Errorf("warning does not name the directory and the fix:\n%s", out)
			}

			// The capability the warning is about: a binary that does not exist at compile
			// time is already allowed to run, in this tier, because the grant is on the
			// hierarchy and the agent can create the file.
			planted := filepath.Join(tools, "planted")
			if got := rt.Evaluate(Action{Kind: ActionExec, Path: planted}, backend.Tier(tier)); got.Verdict != VerdictAllow {
				t.Errorf("exec %s = %q (rule %s); the warning claims it is allowed", planted, got.Verdict, got.Rule)
			}
			if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: planted}, backend.Tier(tier)); got.Verdict != VerdictAllow {
				t.Errorf("write %s = %q; the warning claims the agent can create it", planted, got.Verdict)
			}
		})
	}
}

// TestExecAllowDirHoldingWriteEntryWarns is E38's other nesting: the write entry is strictly
// beneath the directory exec grant. tools/cache/planted is inside the exec grant's hierarchy and
// inside the write entry, so the agent writes a binary there and runs it, exactly as when the exec
// directory sits inside the write entry.
func TestExecAllowDirHoldingWriteEntryWarns(t *testing.T) {
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			f := newFixture(t)
			tools := filepath.Join(f.project, "tools")
			cache := filepath.Join(tools, "cache")
			if err := os.MkdirAll(cache, 0o755); err != nil {
				t.Fatal(err)
			}

			c := f.load("version: 0\nname: a\ncommand: [python]\ntier: " + tier +
				"\nfs:\n  write: [\"tools/cache/\"]\nexec:\n  allow: [\"" + tools + "\"]\n")
			rt, ds := f.compile(c)

			if !hasCode(ds, CodeExecWritable) {
				t.Fatalf("exec.allow %s holding fs.write tools/cache/ produced no %s warning:\n%s", tools, CodeExecWritable, render(ds))
			}
			if out := render(ds); !strings.Contains(out, tools) || !strings.Contains(out, "list the individual binaries") {
				t.Errorf("warning does not name the directory and the fix:\n%s", out)
			}

			planted := filepath.Join(cache, "planted")
			if got := rt.Evaluate(Action{Kind: ActionExec, Path: planted}, backend.Tier(tier)); got.Verdict != VerdictAllow {
				t.Errorf("exec %s = %q (rule %s); the warning claims it is allowed", planted, got.Verdict, got.Rule)
			}
			if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: planted}, backend.Tier(tier)); got.Verdict != VerdictAllow {
				t.Errorf("write %s = %q; the warning claims the agent can create it", planted, got.Verdict)
			}
		})
	}

	// Control: a write entry beside the exec directory, not beneath it, stays quiet.
	f := newFixture(t)
	tools := filepath.Join(f.project, "tools")
	if err := os.MkdirAll(filepath.Join(f.project, "toolsx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"toolsx/\"]\nexec:\n  allow: [\"" + tools + "\"]\n")
	if _, ds := f.compile(c); hasCode(ds, CodeExecWritable) {
		t.Errorf("write entry beside the exec directory warned:\n%s", render(ds))
	}
}

// TestExecAllowFileInsideWriteEntryWarns is E38's narrower half: a single binary listed inside a
// write entry. Landlock pins the inode, but AccessWriteSet carries WRITE_FILE and TRUNCATE over the
// whole write subtree, so the agent rewrites that very inode in place; the root tiers match by path
// and the agent can replace the file outright. Either way the rule stops naming fixed code.
func TestExecAllowFileInsideWriteEntryWarns(t *testing.T) {
	f := newFixture(t)
	helper := filepath.Join(f.project, "out", "helper")
	f.file(helper, string(elf64("/lib64/ld-fake.so.2", 2)), 0o755)

	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"out/\"]\nexec:\n  allow: [\"" + helper + "\"]\n")
	_, ds := f.compile(c)

	if !hasCode(ds, CodeExecWritable) {
		t.Fatalf("exec.allow %s inside fs.write out/ produced no %s warning:\n%s", helper, CodeExecWritable, render(ds))
	}
	if out := render(ds); !strings.Contains(out, "overwrite that binary") {
		t.Errorf("file case is worded as the directory case:\n%s", out)
	}
}

// TestExecOutsideWriteEntryIsSilent is the control pair: the same directory grant outside every
// write entry, and a write entry with no exec grant inside it, must stay quiet. A warning that
// fires on the ordinary contract shape (binaries on PATH, writes confined to the worktree) would be
// noise, and noise is how the real warnings get ignored.
func TestExecOutsideWriteEntryIsSilent(t *testing.T) {
	f := newFixture(t)

	// f.bin is outside f.project; the write entry is project/out.
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"out/\"]\nexec:\n  allow: [\"" + f.bin + "\", static-tool]\n")
	if _, ds := f.compile(c); hasCode(ds, CodeExecWritable) {
		t.Errorf("exec.allow outside every write entry warned:\n%s", render(ds))
	}

	// No fs.write at all: nothing is writable, so nothing is E38.
	c = f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nexec:\n  allow: [\"" + f.bin + "\"]\n")
	if _, ds := f.compile(c); hasCode(ds, CodeExecWritable) {
		t.Errorf("contract with no fs.write warned:\n%s", render(ds))
	}
}

// TestExecWritableFollowsSymlinks holds E38 to E8's rule that every containment question is asked of
// the resolved path. A write entry symlinked onto the exec directory's parent grants the same
// writes the kernel would grant, since the run opens each entry O_PATH without O_NOFOLLOW.
func TestExecWritableFollowsSymlinks(t *testing.T) {
	f := newFixture(t)
	real := filepath.Join(f.root, "elsewhere")
	tools := filepath.Join(real, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.project, "linked")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	// The write entry is the symlink; the exec entry names the real directory. Lexically they
	// share nothing.
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"" + link + "\"]\nexec:\n  allow: [\"" + tools + "\"]\n")
	if _, ds := f.compile(c); !hasCode(ds, CodeExecWritable) {
		t.Fatalf("symlinked write entry %s -> %s hides the grant on %s:\n%s", link, real, tools, render(ds))
	}
}
