// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// zeroDeriver reads nothing of any exchange: its facts carry no usage, and no verdict that the exchange is
// unmetered.
type zeroDeriver struct{}

func (zeroDeriver) Handle(*derive.Message, *derive.Message, derive.Meta) (derive.Result, error) {
	return derive.Result{}, nil
}

// A stream the wire ended after message_start, with no usage from derive, left the scanner's placeholder
// output (message_start's 1) as the exchange's metered count. The scanner's reading without a message_delta is
// never a count to charge: it takes the request's max_tokens as a bound.
func TestScannedPlaceholderIsNeverCharged(t *testing.T) {
	cut := r4Stream[:strings.Index(r4Stream, "event: message_delta")]
	for _, tc := range []struct {
		name    string
		deriver Deriver
		stream  string
	}{
		{"deriver reads nothing", zeroDeriver{}, cut},
		// derive fails at the first frame, before message_start, which the scanner still reads.
		{"derive fails before message_start", derive.NewDispatcher([]derive.Parser{anthropic.New()}),
			"data: {bad\n\n" + cut},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, sseHandler(tc.stream), Options{Deriver: tc.deriver})
			m := meter(h)
			resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":2048,"stream":true,"messages":[]}`), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
			if p.Usage == nil || p.Usage.Output != 2048 || !p.Usage.OutputBound || p.Usage.Input != 1200 {
				t.Fatalf("usage = %+v, want input 1200 and output 2048 marked a bound", p.Usage)
			}
			if got := m.reported(); len(got) != 0 {
				t.Errorf("a bounded cut stream was reported unmetered: %q", got)
			}
		})
	}
	t.Run("no max_tokens", func(t *testing.T) {
		h := newHarness(t, sseHandler(cut), Options{Deriver: zeroDeriver{}})
		m := meter(h)
		resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","stream":true,"messages":[]}`), nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		h.sink.waitFor(t, record.KindSSLResponse, 1)
		if got := waitReported(m, 1); len(got) != 1 {
			t.Errorf("reported %q, want the placeholder count reported unmetered once", got)
		}
	})
}
