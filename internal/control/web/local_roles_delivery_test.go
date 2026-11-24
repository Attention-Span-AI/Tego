// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An answer append can survive cancellation during sync. The refused operation
// that follows is separate evidence; the selection must never read as done.
func TestLocalRolesRecordedApprovalIsNotDelivery(t *testing.T) {
	root := t.TempDir()
	ts := time.Now().Add(-time.Minute)
	start := `"record_minor":37,"tier":"landlock","local_approval_authority":{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`
	ask := `"ask_id":"q-recorded","op":"open","target":"/held/effect","ask_rule":"fs.ask[/held/]","hold":"open"`
	answer := `"ask_id":"q-recorded","op":"open","target":"/held/effect","ask_rule":"fs.ask[/held/]","approved":true,"by":"uid:0 pid:42","actor":{"uid":0,"pid":42,"start_boot_ns":10,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}`
	refused := `"op":"open","path":"/held/effect","rule":"fs.ask[/held/]","verdict":"refused","authority":"human","reason":"ask-unavailable","errno":13,"operation_completed":false,"fd_delivered":false`
	lines := line(harmRun, "roles", 0, ts, "run_start", start) + line(harmRun, "roles", 1, ts.Add(time.Second), "ask", ask) + line(harmRun, "roles", 2, ts.Add(2*time.Second), "answer", answer) + line(harmRun, "roles", 3, ts.Add(3*time.Second), "fs", refused) + line(harmRun, "roles", 4, ts.Add(4*time.Second), "run_end", `"exit_code":1`)
	dir := filepath.Join(root, harmRun)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	for _, path := range []string{"/approvals", "/approvals?tab=history", "/runs/" + harmRun, "/runs/" + harmRun + "/receipt", "/runs/" + harmRun + "/lines/2"} {
		t.Run(path, func(t *testing.T) {
			body := get(t, s, c, path)
			if !strings.Contains(strings.ToLower(body), "approval recorded") {
				t.Errorf("missing recorded selection on %s", path)
			}
			if strings.Contains(body, ">Allowed</span>") || strings.Contains(body, ">Allowed once</") {
				t.Errorf("answer presented as delivered on %s", path)
			}
			if path == "/runs/"+harmRun+"/receipt" && strings.Contains(strings.ToLower(body), `class="b b-allowed">approval recorded`) {
				t.Errorf("recorded approval has an allowed chip")
			}
			if path == "/runs/"+harmRun+"/lines/2" && (!strings.Contains(body, "What followed") || !strings.Contains(body, "/lines/3")) {
				t.Errorf("missing refused operation link")
			}
		})
	}
}
