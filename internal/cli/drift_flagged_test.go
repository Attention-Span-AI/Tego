// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// flaggedDriftRun is the frozen fixture's run_start followed by a refused memfd exec (and the refused line that
// mirrors it), a binary the run wrote and then ran, a plain exec and run_end: the lines GAPS C30's condition asks drift
// to read, as the supervisor writes them (record-ledger.md §2.2).
func flaggedDriftRun(t *testing.T) string {
	t.Helper()
	start, _, _ := strings.Cut(string(fixtureBytes(t)), "\n")
	attr := map[string]string{"confidence": "unattributed", "method": "none"}
	execLine := func(rule, verdict, path string, flags ...string) map[string]any {
		l := map[string]any{"kind": "exec", "source": "seccomp", "rule": rule, "verdict": verdict, "authority": "rule",
			"attribution": attr, "path": path, "argv": []string{filepath.Base(path)},
			"exec_id": "r-3f9c2a1b-0dllq06ts7400-k7m2pq/48300/1"}
		if verdict == "refused" {
			l["reason"] = "exec-not-allowed"
		}
		for _, f := range flags {
			l[f] = true
		}
		return l
	}
	lines := []map[string]any{
		execLine("exec-anon", "refused", "/memfd:payload", "fileless"),
		{"kind": "refused", "source": "seccomp", "rule": "exec-anon", "reason": "exec-not-allowed", "op": "exec",
			"target": "/memfd:payload"},
		execLine("exec[tool]", "allow", "/home/u/proj/out/tool", "dropped"),
		execLine("exec[git]", "allow", "/usr/bin/git"),
		{"kind": "run_end", "source": "supervisor", "reason": "exit", "exit_code": 0},
	}
	var b strings.Builder
	b.WriteString(start + "\n")
	for i, l := range lines {
		l["v"], l["seq"], l["ts"], l["mono_ns"] = 1, i+1, "2026-09-22T09:00:01Z", 812400000000+i
		// Drift decodes the lines and never verifies the chain, so plausible ids are enough.
		l["id"], l["prev"] = strings.Repeat(fmt.Sprintf("%x", (i+1)%16), 64), strings.Repeat(fmt.Sprintf("%x", i%16), 64)
		l["run"], l["agent"], l["pid"], l["tid"], l["cgroup"] = "r-3f9c2a1b-0dllq06ts7400-k7m2pq", "retriever", 48300, 48300, 44821
		data, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestFlaggedTextEscapesTheImage: an image's name is the agent's to choose (a memfd's is any string it passes), so the
// line escapes it for the terminal as every name drift prints is escaped, and it says how many execs named images past
// the report's bound.
func TestFlaggedTextEscapesTheImage(t *testing.T) {
	got := flaggedText([]drift.FlaggedExec{{Path: "/memfd:\x1b]0;owned\a", Refused: 1, Observed: 2}}, 3)
	if want := `/memfd:\x1b]0;owned\a (refused x1, observed x2), +3 execs of other images`; got != want {
		t.Errorf("flaggedText = %q, want %q", got, want)
	}
}

// TestDriftFlaggedExecsGolden pins R17a on the command line, in the table and in --json: drift names the refused memfd
// exec and the binary the run wrote and ran, each with its verdicts, and not the plain exec; empty lists are [] in
// --json (TestDriftJSON). The run drifts by its refusal and its undeclared rules, never by the lists.
func TestDriftFlaggedExecsGolden(t *testing.T) {
	dir := flaggedDriftRun(t)
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"drift-flagged.golden", []string{"drift", dir}},
		{"drift-flagged-json.golden", []string{"drift", dir, "--json"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			code, out, errs := run(t, tc.args...)
			if code != identity.ExitFinding {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
			golden := filepath.Join("testdata", tc.golden)
			if *updateGolden {
				if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (go test -run TestDriftFlaggedExecsGolden -update writes it)", err)
			}
			if out != string(want) {
				t.Fatalf("drift differs from %s:\ngot:\n%s\nwant:\n%s", golden, out, want)
			}
		})
	}
}
