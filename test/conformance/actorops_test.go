// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryTableOpHasAnActorOp: every op a table may name is one the actor performs. Each op runs once on paths
// that do not exist, outside any run, and must fail (or succeed) as that op, never as an op the actor does not
// know: a cell whose op the actor lacked would report the same failure on every axis and judge nothing.
func TestEveryTableOpHasAnActorOp(t *testing.T) {
	actor := buildActor(t)
	dir := t.TempDir()
	var list []script
	for op := range ops {
		// Each op its own names: one that makes a node (mknod's FIFO) must not leave a later op's open blocked on it.
		list = append(list, script{ID: op, Op: op, Path: filepath.Join(dir, op+"-absent"), Dest: filepath.Join(dir, op+"-absent2"),
			Addr: "127.0.0.1:1"})
	}
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "script.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(actor, "run", path)
	// The actor, not tego: it reads no variable, so it gets none, and nothing of the invoking user's reaches it.
	cmd.Dir, cmd.Env = dir, []string{}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("actor: %v", err)
	}
	seen := map[string]bool{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		var r struct {
			ID  string `json:"id"`
			Err string `json:"err"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("actor output %q: %v", sc.Text(), err)
		}
		seen[r.ID] = true
		if strings.Contains(r.Err, "unknown op") {
			t.Errorf("op %s is in the tables' vocabulary but the actor does not perform it: %s", r.ID, r.Err)
		}
	}
	for op := range ops {
		if !seen[op] {
			t.Errorf("the actor reported nothing for op %s", op)
		}
	}
}
