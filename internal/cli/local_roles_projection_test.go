// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalRolesCLIAttributionRequiresRevisionAndCompleteAnswer(t *testing.T) {
	const actor = `"actor":{"uid":0,"pid":42,"start_boot_ns":10,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}`
	for _, tc := range []struct {
		name     string
		minor    int
		decision string
		noFloor  bool // the run's run_start carries no local_approval_authority
		want     bool
	}{
		{"below-minor", 31, `"approved":true`, false, false}, {"valid", 37, `"approved":true`, false, true}, {"invalid-denial", 37, `"approved":false`, false, false}, {"invalid-approval", 37, `"approved":true,"answer_reason":"ask-timeout"`, false, false},
		// A line rewritten to claim root in a run that never started under the floor is not shown as root's.
		{"valid-line-without-the-floor", 37, `"approved":true`, true, false}, {"valid-line-without-the-floor-at-41", 41, `"approved":true`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := `"v":1,"seq":0,"id":"` + strings.Repeat("0", 64) + `","prev":"","ts":"2026-11-12T00:00:00Z","mono_ns":1,"run":"r-00000000-000000000000a-aaaaaa","agent":"test","pid":1,"tid":1,"cgroup":0,"source":"supervisor"`
			floor := ""
			if !tc.noFloor {
				floor = `,"local_approval_authority":{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`
			}
			// The answer pairs with an ask line before it: an answer with no ask answers nothing (askpair).
			data := fmt.Sprintf(`{%s,"kind":"run_start","record_minor":%d`+floor+`}`+"\n"+`{%s,"kind":"ask","ask_id":"q-local","hold":"open"}`+"\n"+`{%s,"kind":"answer","ask_id":"q-local","by":"uid:0 pid:42",%s,%s}`+"\n",
				base, tc.minor, strings.Replace(base, `"seq":0`, `"seq":1`, 1), strings.Replace(base, `"seq":0`, `"seq":2`, 1), tc.decision, actor)
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			a := recordedAsk(dir, "q-local")
			if got := a.Actor != nil; got != tc.want {
				t.Fatalf("attribution=%v want %v: %+v", got, tc.want, a)
			}
			var out bytes.Buffer
			if found, err := writeRecordedAsk("r-test", dir, "q-local", true, true, &out); err != nil || !found {
				t.Fatalf("recorded answer not emitted: found=%v err=%v", found, err)
			}
			if bytes.Contains(out.Bytes(), []byte(`"actor"`)) != tc.want {
				t.Fatalf("copied unvalidated attribution: %s", &out)
			}
			if strings.Contains(a.words(true), "role Owner") != tc.want {
				t.Fatalf("displayed unvalidated attribution: %s", a.words(true))
			}
		})
	}
}
