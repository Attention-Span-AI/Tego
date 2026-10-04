// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A JSON-looking unknown SSE field is not a data payload. Both the retained body parser and the
// incremental wire scanner must ignore it, including when capture retained only a prefix.
func TestUnknownSSEFieldsCannotContributeUsage(t *testing.T) {
	const unknown = `{"type":"message_delta","usage":{"output_tokens":99999}}` + "\n\n"
	for _, at := range []string{"before start", "before stop"} {
		for _, maxBody := range []int{256, 8192} {
			t.Run(at+"/"+strconv.Itoa(maxBody), func(t *testing.T) {
				stream := unknown + r4Stream
				if at == "before stop" {
					stream = strings.Replace(r4Stream, "event: message_stop", unknown+"event: message_stop", 1)
				}
				h := newHarness(t, sseHandler(stream), Options{MaxBody: maxBody,
					Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
				m := meter(h)
				resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`), nil)
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || string(body) != stream {
					t.Fatalf("relayed bytes differ: %v", err)
				}
				p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
				if p.Usage == nil || p.Usage.Input != 1200 || p.Usage.Output != 7 || p.Usage.OutputBound {
					t.Fatalf("unknown field changed accounting: %+v", p.Usage)
				}
				if got := m.reported(); len(got) != 0 {
					t.Fatalf("unknown field made a valid stream incomplete: %v", got)
				}
			})
		}
	}
}
