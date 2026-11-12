// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSameFileRefusalsAreSaid: a live block on /bin/ls refused /bin/sleep, another name of the same program file (a
// multi-call program's applets are one file), and the line's rule names /bin/ls. The receipt says which program it
// refused and why, from the rule and the path alone, counting each; a refusal of /bin/ls itself, and every other
// refusal, says nothing more. The record and the counts by rule are as before.
func TestSameFileRefusalsAreSaid(t *testing.T) {
	const blockRule = "live.block[exec:/bin/ls]"
	refused := func(at time.Duration, rule, path string) line {
		return line{kind: record.KindExec, at: at, verdict: record.VerdictRefused, rule: rule, reason: record.ReasonExecNotAllowed,
			payload: record.ExecPayload{Path: path, Argv: []string{path, "0.1"}, ExecID: "x"}}
	}
	lines := []line{start("off", true), refused(time.Second, blockRule, "/bin/ls")}
	for i := range 3 {
		lines = append(lines, refused(time.Duration(2+i)*time.Second, blockRule, "/bin/sleep"))
	}
	lines = append(lines, refused(6*time.Second, "unmatched", "/usr/bin/curl"), refused(7*time.Second, "live.block[exec:curl]", "/usr/bin/curl"),
		end(10*time.Second, 0))
	rc := compute(t, lines, Options{})
	got := rc.SameFile()
	want := []SameFileRefusal{{Path: "/bin/sleep", Note: "same program file as /bin/ls, which is blocked", Count: 3}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("SameFile = %+v, want %+v", got, want)
	}
	if rc.Refusals.Total != 6 || rc.Refusals.ByRule[0].Rule != blockRule || rc.Refusals.ByRule[0].Count != 4 {
		t.Errorf("the counts changed: %+v", rc.Refusals)
	}
	var out bytes.Buffer
	if err := rc.Text(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "    /bin/sleep: refused, same program file as /bin/ls, which is blocked (3 times)\n") {
		t.Errorf("the receipt does not say why /bin/sleep was refused:\n%s", out.String())
	}
	if strings.Contains(out.String(), "/bin/ls: refused, same program file") || strings.Contains(out.String(), "curl: refused, same") {
		t.Errorf("a direct refusal is said as a same-file one:\n%s", out.String())
	}
	var js bytes.Buffer
	if err := rc.JSON(&js); err != nil || strings.Contains(js.String(), "same program file") {
		t.Errorf("the receipt's JSON changed: %v", err)
	}
}
