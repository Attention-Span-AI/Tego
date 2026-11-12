// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// fixedReport is a passing report with fixed paths and run ids, the shape a real tego test prints.
func fixedReport() Report {
	dir := "/tmp/tego-selftest-123"
	work := dir + "/work"
	r := Report{Schema: Schema, Tier: "landlock", Dir: dir, Checks: []Row{
		{Name: CheckReadSecret, Action: "read a fake SSH key in a fake home",
			Baseline: Outcome{Result: ResultSucceeded, Detail: "read 115 bytes"},
			UnderTego: Outcome{Result: ResultRefused, Run: "r-1", Rule: "fs.deny_read[" + work + "/home/.ssh/]",
				Reason: "read-denied", Target: work + "/home/.ssh/id_ed25519", Match: MatchTarget,
				Detail: "open " + work + "/home/.ssh/id_ed25519: permission denied"}},
		{Name: CheckWriteOutside, Action: "write a file outside the project's writable folder",
			Baseline: Outcome{Result: ResultSucceeded, Detail: "wrote outside.txt"},
			UnderTego: Outcome{Result: ResultRefused, Run: "r-2", Rule: "unmatched", Reason: "write-outside-contract",
				Target: work + "/outside.txt", Match: MatchTarget,
				Detail: "open " + work + "/outside.txt: permission denied"}},
		{Name: CheckRunUnlisted, Action: "run a program the contract does not list",
			Baseline: Outcome{Result: ResultSucceeded, Detail: "ran true"},
			UnderTego: Outcome{Result: ResultRefused, Run: "r-3", Rule: "unmatched", Reason: "exec-not-allowed",
				Target: work + "/bin/true", Match: MatchTarget,
				Detail: "fork/exec " + work + "/bin/true: permission denied"}},
		{Name: CheckConnect, Action: "connect to a local port the contract does not allow",
			Baseline: Outcome{Result: ResultSucceeded, Detail: "connected to 127.0.0.1:40000"},
			UnderTego: Outcome{Result: ResultRefused, Run: "r-4", Rule: "unmatched", Reason: "net-not-allowed",
				Target: "127.0.0.1:40000", Match: MatchTarget,
				Detail: "dial tcp 127.0.0.1:40000: connect: permission denied"}},
	}}
	r.finish()
	return r
}

// golden compares got with testdata/name, or rewrites it under -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// TestSelftestJSONGolden holds the --json object to its documented shape (docs/user/self-check.md): a change to it is a
// change of tego.selftest/v1, which only ever adds fields.
func TestSelftestJSONGolden(t *testing.T) {
	var b bytes.Buffer
	if err := fixedReport().WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.json.golden", b.Bytes())
}

// TestSelftestTextGolden is the one screen: the headline, a row per action, and what the verdict means.
func TestSelftestTextGolden(t *testing.T) {
	var b bytes.Buffer
	if err := fixedReport().WriteText(&b); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.txt.golden", b.Bytes())
}

// TestVerdictAndExitCode: 0 when every action succeeded directly and was refused under Tego, 1 when one got through
// or went unrecorded (whatever else happened), 125 when one could not be judged.
func TestVerdictAndExitCode(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(r *Report)
		verdict  string
		code     int
		refusals int
	}{
		{"all refused", func(*Report) {}, VerdictPass, identity.ExitOK, 4},
		{"one allowed", func(r *Report) { r.Checks[2].UnderTego = Outcome{Result: ResultAllowed} }, VerdictFail, identity.ExitFinding, 3},
		{"one unrecorded", func(r *Report) { r.Checks[0].UnderTego = Outcome{Result: ResultUnrecorded} }, VerdictFail, identity.ExitFinding, 3},
		{"allowed wins over error", func(r *Report) {
			r.Checks[0].UnderTego = Outcome{Result: ResultAllowed}
			r.Checks[1].UnderTego = Outcome{Result: ResultError}
		}, VerdictFail, identity.ExitFinding, 2},
		{"baseline failed", func(r *Report) { r.Checks[3].Baseline = Outcome{Result: ResultFailed} }, VerdictInconclusive, identity.ExitError, 4},
		{"run error", func(r *Report) { r.Checks[1].UnderTego = Outcome{Result: ResultError} }, VerdictInconclusive, identity.ExitError, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fixedReport()
			tc.mutate(&r)
			r.finish()
			if r.Verdict != tc.verdict || r.ExitCode() != tc.code || r.Refused != tc.refusals || r.Actions != 4 {
				t.Errorf("verdict %s exit %d refused %d/%d, want %s exit %d refused %d/4", r.Verdict, r.ExitCode(),
					r.Refused, r.Actions, tc.verdict, tc.code, tc.refusals)
			}
		})
	}
}

// TestJudge: an effect is allowed whatever the ledger says; no effect is refused only with a matching refusal in
// the ledger, by target or else by the check's reason; otherwise it is unrecorded.
func TestJudge(t *testing.T) {
	l := layout{work: "/tmp/tego-selftest-1/work"}
	c, _ := checkByName(CheckReadSecret)
	hit := refusal{Kind: "refused", Rule: "fs.deny_read[x]", Reason: "read-denied", Op: "open", Target: l.key()}
	other := refusal{Kind: "refused", Rule: "unmatched", Reason: "write-outside-contract", Target: "/dev/tty"}
	byReason := refusal{Kind: "refused", Rule: "fs.deny_read[y]", Reason: "read-denied", Target: "/elsewhere"}
	cases := []struct {
		name string
		ev   runEvents
		took bool
		want Outcome
	}{
		{"took effect", runEvents{refused: []refusal{hit}}, true, Outcome{Result: ResultAllowed, Run: "r"}},
		{"refused by target", runEvents{refused: []refusal{other, hit}}, false,
			Outcome{Result: ResultRefused, Run: "r", Rule: hit.Rule, Reason: hit.Reason, Target: hit.Target, Match: MatchTarget}},
		{"refused by reason", runEvents{refused: []refusal{other, byReason}}, false,
			Outcome{Result: ResultRefused, Run: "r", Rule: byReason.Rule, Reason: byReason.Reason, Target: byReason.Target, Match: MatchReason}},
		{"unrecorded", runEvents{refused: []refusal{other}}, false, Outcome{Result: ResultUnrecorded, Run: "r"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := judge(c, l, checkResult{Run: "r"}, tc.ev, tc.took); got != tc.want {
				t.Errorf("judge = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestTextSaysARefusalMatchedByReason: a refusal tied to its check by reason alone, not by its target, is shown as
// such, with the target the record named, so weaker evidence never reads like the check's own refusal.
func TestTextSaysARefusalMatchedByReason(t *testing.T) {
	r := fixedReport()
	r.Checks[0].UnderTego.Match = MatchReason
	r.Checks[0].UnderTego.Target = r.Dir + "/elsewhere"
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "(by reason: the record names <tmp>/elsewhere)") {
		t.Errorf("the screen does not say the refusal matched by reason:\n%s", b.String())
	}
}

// TestNothingJudgedSaysSo: when no run under Tego started (every under-Tego half an error, as from a shell outside the
// user manager's cgroup), the report never says "Nothing got through", which would claim what was never tried; one
// error among refusals keeps the old words (acceptance B, 2026-11-11).
func TestNothingJudgedSaysSo(t *testing.T) {
	r := fixedReport()
	for i := range r.Checks {
		r.Checks[i].UnderTego = Outcome{Result: ResultError, Detail: "exit status 125: no enforcement tier available"}
	}
	r.finish()
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Nothing got through") || !strings.Contains(b.String(), "No action could be judged") ||
		r.ExitCode() != identity.ExitError {
		t.Errorf("exit %d:\n%s", r.ExitCode(), b.String())
	}
	r = fixedReport()
	r.Checks[1].UnderTego = Outcome{Result: ResultError}
	r.finish()
	b.Reset()
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Nothing got through") {
		t.Errorf("one error among refusals:\n%s", b.String())
	}
}
