// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCachedTailRefusesChangedLine(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	var head struct {
		Run string `json:"run"`
	}
	if err := json.Unmarshal(lines[0], &head); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, old, next, reason string
		index                   int
	}{
		{"baseline-null", `"plane":""`, `"plane":null`, "plane", 0},
		{"baseline-minor", `"record_minor":39`, `"record_minor":36`, "record_minor", 0},
		{"other-kind", `"v":1`, `"v":0`, "version", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			original := lines[tc.index]
			writeRun(t, root, head.Run, string(original)+"\n")
			snapshot, err := Open(root).Snapshot()
			if err != nil || snapshot.Find(head.Run) == nil {
				t.Fatalf("snapshot: %v", err)
			}
			changed := bytes.Replace(original, []byte(tc.old), []byte(tc.next), 1)
			if bytes.Equal(original, changed) {
				t.Fatal("mutation did not fire")
			}
			if err := os.WriteFile(filepath.Join(root, head.Run, "events.jsonl"), append(changed, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if _, ok := StampRun(root, head.Run); ok {
				t.Error("refused tail was stamped as a valid cache input")
			}
			if _, err := LoadReceipt(t.Context(), root, head.Run); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("uncached receipt lost decoder reason: %v", err)
			}
		})
	}
}
