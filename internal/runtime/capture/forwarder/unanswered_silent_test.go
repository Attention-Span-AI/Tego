// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"net/http"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A request to a path that spends nothing (telemetry outside /v1, model listing, count_tokens) that the upstream
// drops unanswered is not reported unmetered, so it cannot end a budgeted run (ADR 0037 amendment 2026-09-24).
func TestUnansweredSilentPathIsNotReported(t *testing.T) {
	for _, p := range []string{"/api/event_logging/batch", "/v1/messages/count_tokens", "/"} {
		t.Run(p, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				c, _, err := http.NewResponseController(w).Hijack()
				if err == nil {
					_ = c.Close()
				}
			}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			m := meter(h)
			resp := h.post(p, []byte(`{"events":[]}`), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			h.sink.waitFor(t, record.KindGap, 1)
			if got := waitReported(m, 1); len(got) != 0 {
				t.Errorf("silent path %s reported unmetered: %q", p, got)
			}
		})
	}
}

// A large 2xx answer on a path that spends nothing (a Files API download, the model list) whose copy the
// capture budget cut is not reported unmetered: it cannot end a budgeted run.
func TestCutSilentPathAnswerIsNotReported(t *testing.T) {
	for _, p := range []string{"/v1/files/file_1/content", "/v1/models"} {
		t.Run(p, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(make([]byte, 64<<10))
			}, Options{MaxBody: 16 << 10, Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			m := meter(h)
			resp, err := http.Get(h.listener.BaseURL() + p)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			h.sink.waitFor(t, record.KindSSLResponse, 1)
			if got := waitReported(m, 1); len(got) != 0 {
				t.Errorf("silent path %s reported unmetered: %q", p, got)
			}
		})
	}
}
