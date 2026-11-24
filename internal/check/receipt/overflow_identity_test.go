// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestOverflowAttemptsAreNotIdentities(t *testing.T) {
	ls := []line{start("off", true)}
	for i := 0; i < MaxPaths; i++ {
		ls = append(ls, line{kind: record.KindNet, rule: "n", verdict: record.VerdictAllow, payload: record.NetPayload{Proto: "tcp", Dst: fmt.Sprintf("host-%d.example:443", i)}}, line{kind: record.KindExec, rule: "exec", verdict: record.VerdictAllow, payload: record.ExecPayload{Path: fmt.Sprintf("/bin/program-%d", i)}})
	}
	for i := 0; i < 3; i++ {
		ls = append(ls, line{kind: record.KindNet, rule: "n", verdict: record.VerdictAllow, payload: record.NetPayload{Proto: "tcp", Dst: "untracked.example:443"}}, line{kind: record.KindExec, rule: "exec", verdict: record.VerdictAllow, payload: record.ExecPayload{Path: "/bin/untracked"}})
	}
	rc := compute(t, ls, Options{})
	var b bytes.Buffer
	if err := rc.Text(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), fmt.Sprintf("to %d places", MaxPaths+3)) || strings.Contains(b.String(), fmt.Sprintf("%d programs;", MaxPaths+3)) {
		t.Error("terminal counts repeated overflow attempts as identities")
	}
	for _, words := range []string{"listed places", "listed programs", "3 connection attempts beyond the identity limit", "3 program starts beyond the identity limit"} {
		if !strings.Contains(b.String(), words) {
			t.Errorf("terminal lacks %q", words)
		}
	}
	b.Reset()
	if err := rc.JSON(&b); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"connections_more", "programs_more"} {
		if out[key] != float64(MaxPaths-MaxTop) {
			t.Errorf("%s=%v counts attempts", key, out[key])
		}
	}
	for _, key := range []string{"connections_overflow_attempts", "programs_overflow_attempts"} {
		if out[key] != float64(3) {
			t.Errorf("%s=%v", key, out[key])
		}
	}
}
