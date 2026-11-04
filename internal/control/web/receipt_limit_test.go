// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReceiptTabShowsPendingAskLimit(t *testing.T) {
	root, id := t.TempDir(), "r-aaaaaaaa-0000000000009-asklim"
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	var lines strings.Builder
	lines.WriteString(line(id, "fixture", 0, at, "run_start", `"tier":"observe","command":["codex"]`))
	for i := range 32_769 {
		lines.WriteString(line(id, "fixture", i+1, at, "ask", fmt.Sprintf(`"ask_id":"q-%d","hold":"exec"`, i)))
	}
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	html := getPage(t, s, "/runs/"+id+"/receipt")
	if !strings.Contains(html, "No receipt for this run:") || !strings.Contains(html, "pending ask limit exceeded") {
		t.Fatal("receipt tab did not show the explicit limit error")
	}
}
