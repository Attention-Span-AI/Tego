// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// TestCutResponseIsReportedUnmetered: a 2xx answer on a model host whose body ends early because its
// connection's count restarted at 1 mid-body (as an SSL_free or a stop also end it) is emitted Truncated and
// paired with its own request. Its spend is not counted from it: derive cannot read usage from a JSON body cut
// short, however little is missing, so the exchange is reported unmetered (limits-check-doctor-cli.md R1 (a)),
// which ends a budgeted run. The whole answer reports nothing.
func TestCutResponseIsReportedUnmetered(t *testing.T) {
	req, resp := messagesExchange("length")
	usageAt := strings.Index(resp, `"usage"`)
	for _, tc := range []struct {
		name string
		cut  int // bytes of resp that arrive
		want int64
	}{
		{"cut before its usage", usageAt - 10, 1},
		{"cut one byte short", len(resp) - 1, 1},
		{"whole", len(resp), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const ssl = 0x5900
			sink := r3Metered(t, [][]byte{
				numbered(chunkRecord(41, 770, 770, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false), 1),
				numbered(chunkRecord(41, 770, 770, ssl, bpf.SSLRead, 2_000_000, []byte(resp[:tc.cut]), false), 2),
				// The pointer's count restarts: a new connection, which ends the old one mid-body.
				numbered(chunkRecord(41, 770, 770, ssl, bpf.SSLWrite, 3_000_000, []byte(req), false), 1),
				numbered(chunkRecord(41, 770, 770, ssl, bpf.SSLRead, 4_000_000, []byte(resp), false), 2),
			})
			if got := sink.reported(); got != tc.want {
				t.Errorf("reported %d exchanges unmetered (%q), want %d", got, sink.whys, tc.want)
			}
		})
	}
}
