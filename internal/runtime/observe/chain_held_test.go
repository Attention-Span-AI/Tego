// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecorderExplainsReferByTheHeldInode: Landlock binds an exec.allow grant to the inode the builder held, and the
// rule moves with it. The index holds the exec entries' inodes when it is built, before the agent runs; after `mv
// out/bin out/old; mkdir out/bin` inside the write entry, a chain refusal of a rename or a link into out/old (EXDEV,
// EXECUTE gained) is the ruleset's, and a move or a link into the new out/bin gains nothing, as tier 1's line says.
// By the declared names alone the first two read observed by another mechanism, and a refusal of
// the last two would have been the ruleset's.
func TestRecorderExplainsReferByTheHeldInode(t *testing.T) {
	dir := t.TempDir()
	out, bin, old := filepath.Join(dir, "out"), filepath.Join(dir, "out", "bin"), filepath.Join(dir, "out", "old")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Record: agent.RecordFull,
		Contract: &agent.Contract{Name: "held", Exec: &agent.ExecSection{Allow: []string{"./out/bin/"}}},
		FS:       []agent.FSRule{{Kind: agent.FSWrite, Path: out, Resolved: out, Raw: "./out/", Access: agent.AccessWriteSet}},
		Exec:     []agent.ExecRule{{Raw: "./out/bin/", Path: bin, Resolved: bin, IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow}},
	}
	ri := newRuleIndexAt(rt, "/nonexistent")
	if err := os.Rename(bin, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(out, "a"), filepath.Join(old, "t")} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const writeOut = "fs.write[./out/]"
	for _, c := range []struct {
		name, src, dst string
		link, refused  bool
	}{
		{"a rename into the moved exec directory", filepath.Join(out, "a"), filepath.Join(old, "a"), false, true},
		{"a link into it", filepath.Join(out, "a"), filepath.Join(old, "b"), true, true},
		{"a move out of it into the recreated name", filepath.Join(old, "t"), filepath.Join(bin, "t"), false, false},
		{"a link into the recreated name", filepath.Join(out, "a"), filepath.Join(bin, "c"), true, false},
	} {
		rule, refused := ri.landlockRenameRefusal(c.src, c.dst)
		if c.link {
			rule, refused = ri.landlockLinkRefusal(c.src, c.dst)
		}
		if refused != c.refused || (refused && rule != writeOut) {
			t.Errorf("%s: refused=%v via %q, want refused=%v via %s", c.name, refused, rule, c.refused, writeOut)
		}
	}
}

// TestRecorderExecOpenFollowsTheHeldDirectory: an exec.allow directory's EXECUTE is on the inode the Landlock builder
// held. After `mv out/bin out/old; mkdir out/bin` inside a write entry, the kernel refuses the exec's open of a file in
// the fresh out/bin (EACCES): no rule grants it, so the refusal is the ruleset's, unmatched, as tier 1's line says
// (supervisor dirHeld). By the declared name alone the line read observed under the directory entry,
// a refusal by another mechanism of an exec the contract grants (ADR 0017's refer/exec-in-recreated-exec-name at the
// plane axes). While the name still holds the inode, a chain refusal stays another mechanism's.
func TestRecorderExecOpenFollowsTheHeldDirectory(t *testing.T) {
	for _, moved := range []bool{false, true} {
		t.Run(map[bool]string{false: "held", true: "recreated"}[moved], func(t *testing.T) {
			f := newFixture(t)
			bin, old := filepath.Join(f.out, "bin"), filepath.Join(f.out, "old")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			f.rules.Tier = backend.TierBPFLSM
			f.rules.Exec = append(f.rules.Exec, agent.ExecRule{Raw: "./out/bin/", Path: bin, Resolved: bin, IsDir: true,
				Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
			tool := filepath.Join(bin, "u")
			built := func() {
				if moved {
					if err := os.Rename(bin, old); err != nil {
						t.Error(err)
					}
					if err := os.Mkdir(bin, 0o755); err != nil {
						t.Error(err)
					}
				}
				if err := os.WriteFile(tool, []byte("x"), 0o755); err != nil {
					t.Error(err)
				}
			}
			n := outcomeNaming(10)
			h := execOutcomeHeader(20)
			h.Kind, h.Ret, h.RetOK = KindOpen, -13, true
			_, sink := runRecorderAfter(t, f, Options{ExecResults: true,
				ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }}, built,
				execOpenSample(h, tool), execResultSample(execOutcomeHeader(30), -13))
			ev, p := oneExecOutcome(t, sink)
			if moved {
				if ev.Verdict != record.VerdictRefused || ev.Rule != RuleUnmatched || ev.Reason != record.ReasonExecNotAllowed ||
					p.By != "lsm-chain" {
					t.Fatalf("exec in the recreated name = %s/%s/%s by %q, want refused/unmatched/%s by lsm-chain",
						ev.Verdict, ev.Rule, ev.Reason, p.By, record.ReasonExecNotAllowed)
				}
				return
			}
			if ev.Verdict != record.VerdictObserved || ev.Rule != "exec[./out/bin/]" || p.By != record.FSByOther || p.Errno != 13 {
				t.Fatalf("exec in the held directory = %s/%s by %q errno %d, want observed/exec[./out/bin/] by %s errno 13",
					ev.Verdict, ev.Rule, p.By, p.Errno, record.FSByOther)
			}
		})
	}
}

// TestRecorderExecOpenFollowsTheHeldFile: an exec.allow file entry's EXECUTE is on the inode the Landlock builder held,
// as a directory entry's is. After `mv out/tool.new out/tool` inside a write entry the name holds a fresh inode with
// no grant, and the kernel refuses the exec's open (EACCES): no rule grants it, so the refusal is the ruleset's,
// unmatched, as tier 1's line says (the supervisor pins file entries by inode, execIDs). Only directory entries were
// asked by inode, so the line read observed under exec[./out/tool], a refusal by another mechanism of an exec the
// contract grants. While the name still holds the inode, a chain refusal stays another
// mechanism's.
func TestRecorderExecOpenFollowsTheHeldFile(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(map[bool]string{false: "held", true: "replaced"}[replaced], func(t *testing.T) {
			f := newFixture(t)
			tool := filepath.Join(f.out, "tool")
			if err := os.WriteFile(tool, []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
			f.rules.Tier = backend.TierBPFLSM
			f.rules.Exec = append(f.rules.Exec, agent.ExecRule{Raw: "./out/tool", Path: tool, Resolved: tool,
				Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
			built := func() {
				if !replaced {
					return
				}
				next := tool + ".new"
				if err := os.WriteFile(next, []byte("y"), 0o755); err != nil {
					t.Error(err)
				}
				if err := os.Rename(next, tool); err != nil {
					t.Error(err)
				}
			}
			n := outcomeNaming(10)
			h := execOutcomeHeader(20)
			h.Kind, h.Ret, h.RetOK = KindOpen, -13, true
			_, sink := runRecorderAfter(t, f, Options{ExecResults: true,
				ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }}, built,
				execOpenSample(h, tool), execResultSample(execOutcomeHeader(30), -13))
			ev, p := oneExecOutcome(t, sink)
			if replaced {
				if ev.Verdict != record.VerdictRefused || ev.Rule != RuleUnmatched || ev.Reason != record.ReasonExecNotAllowed ||
					p.By != "lsm-chain" {
					t.Fatalf("exec of the replaced file entry = %s/%s/%s by %q, want refused/unmatched/%s by lsm-chain",
						ev.Verdict, ev.Rule, ev.Reason, p.By, record.ReasonExecNotAllowed)
				}
				return
			}
			if ev.Verdict != record.VerdictObserved || ev.Rule != "exec[./out/tool]" || p.By != record.FSByOther || p.Errno != 13 {
				t.Fatalf("exec of the held file entry = %s/%s by %q errno %d, want observed/exec[./out/tool] by %s errno 13",
					ev.Verdict, ev.Rule, p.By, p.Errno, record.FSByOther)
			}
		})
	}
}
