// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// flaggedExecLine is an exec line as the supervisor writes it, carrying the record's fileless and dropped flags as
// given (record-ledger.md §2.2).
func flaggedExecLine(verdict, rule, path string, fileless, dropped bool) map[string]any {
	l := map[string]any{"kind": "exec", "source": "seccomp", "rule": rule, "verdict": verdict, "authority": "rule",
		"attribution": map[string]string{"confidence": "unattributed", "method": "time"}, "path": path,
		"argv": []string{path}, "exec_id": "r/455/1"}
	if verdict == "refused" {
		l["reason"] = "exec-not-allowed"
	}
	if fileless {
		l["fileless"] = true
	}
	if dropped {
		l["dropped"] = true
	}
	return l
}

// execMirror is the refused line the pipeline writes right after a refused exec. It carries neither flag, and R13
// never counts it.
func execMirror(rule, target string) map[string]any {
	return map[string]any{"kind": "refused", "source": "seccomp", "rule": rule, "reason": "exec-not-allowed",
		"op": "exec", "target": target}
}

// flaggedTable is a contract that grants git and the tool the run builds under its write entry (exec[./out/tool]).
func flaggedTable() *agent.RuleTable {
	rt := modelTable()
	rt.Exec = []agent.ExecRule{
		{Raw: "./out/tool", Path: "/w/out/tool", Basename: "tool", Source: agent.ExecSourceAllow},
		{Raw: "git", Path: "/usr/bin/git", Basename: "git", Source: agent.ExecSourceAllow},
	}
	return rt
}

// flaggedRun computes the report of a run holding body between its run_start and run_end.
func flaggedRun(t *testing.T, rt *agent.RuleTable, body ...map[string]any) *Report {
	t.Helper()
	lines := append([]map[string]any{runStartLine()}, body...)
	rep, err := Compute(readerOver(t, modelLedger(append(lines, runEndLine())...)), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return rep
}

// TestDriftListsFlaggedExecs is GAPS C30's condition and R17a: drift reads the exec payload's fileless and dropped keys
// and lists each image they flag, with its execs by verdict, whatever the verdict, and names no exec the record did not
// flag. Without it a run's drop-and-execute or memfd exec was a count under exec[...] or exec-anon in the table, with
// nothing saying which image it was or that the run had written it.
func TestDriftListsFlaggedExecs(t *testing.T) {
	const blob = "8e3b4c1d2a6f7e9b0c5d4a3f2e1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b"
	blobbed := flaggedExecLine("allow", "exec[./out/tool]", "", false, true)
	delete(blobbed, "path")
	blobbed["path_blob"] = blob
	for _, tc := range []struct {
		name              string
		body              []map[string]any
		fileless, dropped []FlaggedExec
	}{{
		name: "a refused fileless exec, an allowed dropped exec and a plain exec",
		body: []map[string]any{
			flaggedExecLine("refused", "exec-anon", "/memfd:payload", true, false),
			execMirror("exec-anon", "/memfd:payload"),
			flaggedExecLine("allow", "exec[./out/tool]", "/w/out/tool", false, true),
			flaggedExecLine("allow", "exec[git]", "/usr/bin/git", false, false),
		},
		fileless: []FlaggedExec{{Path: "/memfd:payload", Refused: 1}},
		dropped:  []FlaggedExec{{Path: "/w/out/tool", Allow: 1}},
	}, {
		// A memfd whose #! line names an interpreter the run wrote, in a run with command rules: both flags, so both
		// lists, one exec in each.
		name:     "an exec flagged both ways is in both lists",
		body:     []map[string]any{flaggedExecLine("refused", "exec-anon", "/memfd:script", true, true)},
		fileless: []FlaggedExec{{Path: "/memfd:script", Refused: 1}},
		dropped:  []FlaggedExec{{Path: "/memfd:script", Refused: 1}},
	}, {
		// A PATH-search candidate the run planted is observed (nothing ran there); an observe run's would-be refusal
		// is too. Each verdict is its own count, and the images come out sorted.
		name: "one image's verdicts add up, images sorted by path",
		body: []map[string]any{
			flaggedExecLine("allow", "exec[./out/tool]", "/w/out/tool", false, true),
			flaggedExecLine("observed", "exec[git]", "/w/bin/git", false, true),
			flaggedExecLine("allow", "exec[./out/tool]", "/w/out/tool", false, true),
			flaggedExecLine("refused", "unmatched", "/w/out/tool", false, true),
			flaggedExecLine("allow", "exec[git]", "/usr/bin/git", false, false),
		},
		dropped: []FlaggedExec{{Path: "/w/bin/git", Observed: 1}, {Path: "/w/out/tool", Allow: 2, Refused: 1}},
	}, {
		name:    "a path the ledger stored apart is named by its blob",
		body:    []map[string]any{blobbed},
		dropped: []FlaggedExec{{Path: "path_blob:" + blob, Allow: 1}},
	}, {
		name: "a run that flagged nothing lists nothing",
		body: []map[string]any{
			flaggedExecLine("allow", "exec[./out/tool]", "/w/out/tool", false, false),
			flaggedExecLine("allow", "exec[git]", "/usr/bin/git", false, false),
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			rep := flaggedRun(t, flaggedTable(), tc.body...)
			if !slices.Equal(rep.Fileless, tc.fileless) || !slices.Equal(rep.Dropped, tc.dropped) {
				t.Errorf("fileless %+v dropped %+v\nwant fileless %+v dropped %+v", rep.Fileless, rep.Dropped, tc.fileless, tc.dropped)
			}
			if rep.FilelessMore != 0 || rep.DroppedMore != 0 {
				t.Errorf("more %d %d, want none under the bound", rep.FilelessMore, rep.DroppedMore)
			}
		})
	}
}

// TestFlaggedExecIsNoDriftOnItsOwn is R17a's "never drift on their own": a binary the run built and ran under the
// exec.allow entry that grants it is the contract at work, so the run with nothing else to say exits 0 with the image
// listed, while a refused fileless exec drifts by its refusal, as it did before the list existed.
func TestFlaggedExecIsNoDriftOnItsOwn(t *testing.T) {
	built := flaggedRun(t, flaggedTable(),
		flaggedExecLine("allow", "exec[./out/tool]", "/w/out/tool", false, true),
		flaggedExecLine("allow", "exec[git]", "/usr/bin/git", false, false))
	if built.Drifted() || len(built.Dropped) != 1 {
		t.Errorf("drifted %v dropped %+v: want a listed image and no drift", built.Drifted(), built.Dropped)
	}
	memfd := flaggedRun(t, flaggedTable(),
		flaggedExecLine("allow", "exec[./out/tool]", "/w/out/tool", false, false),
		flaggedExecLine("allow", "exec[git]", "/usr/bin/git", false, false),
		flaggedExecLine("refused", "exec-anon", "/memfd:payload", true, false),
		execMirror("exec-anon", "/memfd:payload"))
	if !memfd.Drifted() || len(memfd.Fileless) != 1 {
		t.Errorf("drifted %v fileless %+v: a refused memfd exec is drift and listed", memfd.Drifted(), memfd.Fileless)
	}
}

// TestFlaggedImagesAreBounded: the images' names are the agent's, so a list keeps the first maxFlagged it saw and
// counts the execs of the rest; an image it kept still counts every exec of it. Over an aggregate the lists add up by
// path under the same bound, and every run's execs past its own bound stay counted.
func TestFlaggedImagesAreBounded(t *testing.T) {
	images := func(prefix string, n int) []map[string]any {
		var body []map[string]any
		for i := range n {
			body = append(body, flaggedExecLine("allow", "unmatched", fmt.Sprintf("/w/%s/%03d", prefix, i), false, true))
		}
		return body
	}
	body := images("a", maxFlagged+8)
	body = append(body, flaggedExecLine("allow", "unmatched", "/w/a/000", false, true))
	rep := flaggedRun(t, flaggedTable(), body...)
	if len(rep.Dropped) != maxFlagged || rep.DroppedMore != 8 {
		t.Fatalf("%d images and %d more, want %d and 8", len(rep.Dropped), rep.DroppedMore, maxFlagged)
	}
	if first := rep.Dropped[0]; first.Path != "/w/a/000" || first.Allow != 2 {
		t.Errorf("first image %+v, want /w/a/000 run twice", first)
	}
	if last := rep.Dropped[maxFlagged-1].Path; last != fmt.Sprintf("/w/a/%03d", maxFlagged-1) {
		t.Errorf("the list kept %s last, not the first %d images seen", last, maxFlagged)
	}
	other := flaggedRun(t, flaggedTable(), images("b", 4)...)
	agg, err := Aggregate([]*Report{rep, other, rep})
	if err != nil {
		t.Fatal(err)
	}
	// The first run's 32 images fill the list; the other run's 4 and the third run's 8 past its bound are counted.
	if len(agg.Dropped) != maxFlagged || agg.DroppedMore != 8+4+8 {
		t.Errorf("aggregate: %d images and %d more, want %d and 20", len(agg.Dropped), agg.DroppedMore, maxFlagged)
	}
	if first := agg.Dropped[0]; first.Path != "/w/a/000" || first.Allow != 4 {
		t.Errorf("aggregate first image %+v, want /w/a/000 run four times", first)
	}
	for _, f := range agg.Dropped {
		if strings.HasPrefix(f.Path, "/w/b/") {
			t.Errorf("the aggregate kept %s past its bound", f.Path)
		}
	}
	small, err := Aggregate([]*Report{other, flaggedRun(t, flaggedTable(), images("b", 2)...)})
	if err != nil {
		t.Fatal(err)
	}
	want := []FlaggedExec{{Path: "/w/b/000", Allow: 2}, {Path: "/w/b/001", Allow: 2}, {Path: "/w/b/002", Allow: 1}, {Path: "/w/b/003", Allow: 1}}
	if !slices.Equal(small.Dropped, want) || small.DroppedMore != 0 || small.Fileless != nil {
		t.Errorf("aggregate %+v (%d more, fileless %+v), want %+v", small.Dropped, small.DroppedMore, small.Fileless, want)
	}
}
