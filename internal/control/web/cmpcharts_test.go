// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestMeterGolden(t *testing.T) {
	for name, svg := range map[string]string{
		"meter":      render(t, meter(3, 4, "ch-leak", "Secrets reached, run A (watch-codex)")),
		"meter-zero": render(t, meter(0, 0, "ch-refused", "Attempts stopped, run B")),
	} {
		t.Run(name, func(t *testing.T) {
			checkSVG(t, svg)
			golden(t, name, svg)
		})
	}
	if s := render(t, meter(1, 1, `x"/><script>`, `<b>`)); strings.Contains(s, "<script>") || strings.Contains(s, "<b>") {
		t.Errorf("meter text not escaped: %s", s)
	}
}

func TestCmpCharts(t *testing.T) {
	if cmpCharts(nil) != nil {
		t.Error("no comparison draws bars")
	}
	c := &ledgerview.Comparison{
		A: ledgerview.CmpSide{Run: &ledgerview.Run{ID: "a", Agent: "watch-codex", Tier: "observe"}, SecretsOpened: 3, OffList: 2},
		B: ledgerview.CmpSide{Run: &ledgerview.Run{ID: "b"}, Verdict: ledgerview.Verdict{SecretReads: 2, Sends: 1}},
	}
	m := cmpCharts(c)
	if len(m) != 3 {
		t.Fatalf("got %d bar pairs, want 3", len(m))
	}
	got := [3][2]int{}
	for i := range m {
		got[i] = [2]int{m[i].Rows[0].N, m[i].Rows[1].N}
	}
	if want := [3][2]int{{3, 0}, {2, 0}, {0, 3}}; got != want {
		t.Errorf("counts = %v, want %v", got, want)
	}
	if m[0].Rows[0].Agent != "watch-codex" || m[0].Rows[1].Agent != "run B" {
		t.Errorf("agents = %q, %q", m[0].Rows[0].Agent, m[0].Rows[1].Agent)
	}
	if !strings.Contains(render(t, m[0].Rows[0].Bar), `class="ch-leak"`) || !strings.Contains(render(t, m[2].Rows[1].Bar), `class="ch-refused"`) {
		t.Error("got-through bars are not red or stopped bars not green")
	}
}
