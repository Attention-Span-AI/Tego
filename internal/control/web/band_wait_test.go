// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
)

// A person can answer from either band. Both must show the held duration and
// whether the agent is likely still waiting before presenting those controls.
func TestAskBandWaitContext(t *testing.T) {
	s, c := f3Server(t)
	for _, path := range []string{"/", "/logs", "/no-such-page"} {
		b := do(s, "GET", path, "127.0.0.1:8484", c).Body.String()
		start := strings.Index(b, `id="ask-banner"`)
		if start < 0 {
			t.Fatalf("%s lacks band", path)
		}
		b = b[start:]
		b = b[:strings.Index(b, "</section>")]
		for _, want := range []string{"Held for 2 m 0 s", "asked at", "Codex has likely given up; Tego refuses it at 3 m"} {
			if !strings.Contains(f3Text(b), want) {
				t.Errorf("%s band lacks %q: %s", path, want, f3Text(b))
			}
		}
	}
}
