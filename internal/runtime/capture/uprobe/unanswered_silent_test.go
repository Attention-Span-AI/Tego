// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// An unanswered request to a path the deriver calls silent (telemetry outside /v1, token counting, the health
// check, a model listing) spends nothing whatever its answer, so it is not reported unmetered; a Messages API
// request lost the same way still is, and so is an ambiguous path (ADR 0037 amendment 2026-09-24).
func TestUnansweredSilentPathIsNotReported(t *testing.T) {
	const ssl = 0x5900
	for _, tc := range []struct {
		method, path string
		want         int64
	}{
		{"POST", "/api/event_logging/batch", 0},
		{"POST", "/v1/messages/count_tokens", 0},
		{"GET", "/v1/models", 0},
		{"GET", "/", 0},
		{"POST", "/v1/messages", 1},
		{"POST", "/V1/messages", 1},
		{"POST", "/v1/unknown", 1},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			body := `{"events":[]}`
			req := tc.method + " " + tc.path + " HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n" +
				"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			sink := r3Metered(t, [][]byte{
				chunkRecord(41, 770, 770, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false),
				closeRecord(41, 770, 770, ssl, 2_000_000),
			})
			if got := sink.reported(); got != tc.want {
				t.Errorf("reported %d (%q), want %d", got, sink.whys, tc.want)
			}
		})
	}
}
