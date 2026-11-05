// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReceiptTabPreservesSharedTracingUncertainty(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000052-shared"
	root := t.TempDir()
	t0 := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	ls := []string{
		line(run, "demo", 0, t0, "run_start", `"tier":"cgroup","capture":"off","command":["true"]`),
		line(run, "demo", 1, t0.Add(time.Second), "gap", `"what":"record","why":"bpf-trampoline-miss/shared-build","count":17`),
		line(run, "demo", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`),
	}
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	page := get(t, s, c, "/runs/"+run+"/receipt")
	for _, want := range []string{"coverage is uncertain", "17 reported skipped executions of shared tracing programs", "other runs or ungoverned tasks"} {
		if !strings.Contains(page, want) {
			t.Errorf("receipt page discards %q", want)
		}
	}
	if strings.Contains(page, "events lost") || strings.Contains(page, "knows it missed") {
		t.Error("receipt page claims known lost actions")
	}
}
