// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOverviewRefusalsListWhatMattersFirst: a run whose newest 400 refusals are an agent's route probes (port 65535,
// background on the run page) and whose older refusal is a denied SSH key. The overview's list shows the key as High
// and leaves the routine probes out.
func TestOverviewRefusalsListWhatMattersFirst(t *testing.T) {
	root := t.TempDir()
	run := "r-aaaaaaaa-0000000000005-overvw"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ls := []string{line(run, "supply-chain", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/proj"`),
		line(run, "supply-chain", 1, t0.Add(time.Second), "refused", `"rule":"fs.deny_read[/w/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`)}
	for i := 0; i < 400; i++ {
		ls = append(ls, line(run, "supply-chain", 2+i, t0.Add(time.Minute), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:65535"`))
	}
	// The UDP action line is what makes them route probes (ledgerview.RouteProbe): a connect to that port is otherwise a real attempt.
	ls = append(ls, line(run, "supply-chain", 402, t0.Add(time.Minute), "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"104.18.32.47:65535"`))
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/")
	ref := body[strings.Index(body, `id="h-ref"`):]
	if !strings.Contains(ref, `<span class="sev sev-High">High</span>`) || !strings.Contains(ref, "id_rsa") {
		t.Errorf("the Overview's list does not lead with the High key read:\n%s", ref)
	}
	if strings.Contains(ref, "104.18.32.47:65535") {
		t.Error("the Overview's list shows a routine probe")
	}
	// On a phone the grid's head is hidden, so each count keeps its column's name through data-label (signal.css).
	for _, label := range []string{"Files", "Programs", "Network", "All"} {
		if !strings.Contains(body, `<td class="num" data-label="`+label+`">`) {
			t.Errorf("the Overview's grid has no %s label", label)
		}
	}
}
