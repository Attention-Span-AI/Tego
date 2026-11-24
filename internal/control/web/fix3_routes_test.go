// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRouteCountsRejectUnreadablePrefix(t *testing.T) {
	root := routesFixture(t)
	f, err := os.OpenFile(filepath.Join(root, harmRun, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("{invalid route facts}\n")
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	body := getRaw(t, s, c, "/routes?run="+harmRun)
	if !strings.Contains(body, "read route requests") {
		t.Fatal("route reader failure was hidden")
	}
	if strings.Contains(body, `data-number="routes.requests"`) {
		t.Fatal("route prefix presented as an exact request count")
	}
}

func TestRouteCountsRejectTypedPayloadErrors(t *testing.T) {
	for _, tc := range []struct{ kind, extra string }{{"ssl_request", `"host":12`}, {"gap", `"what":12`}, {"gap", `"what":"enforce","why":"model-route-changed"`}} {
		t.Run(tc.kind+tc.extra, func(t *testing.T) {
			root := routesFixture(t)
			appendLine(t, root, harmRun, line(harmRun, "Agent", 100, time.Now(), tc.kind, tc.extra))
			s := newServer(t, root)
			c := login(t, s)
			body := getRaw(t, s, c, "/routes?run="+harmRun)
			if !strings.Contains(body, "read route requests") || strings.Contains(body, `data-number="routes.requests"`) {
				t.Fatal("typed route fact error was presented as a complete count")
			}
		})
	}
}
