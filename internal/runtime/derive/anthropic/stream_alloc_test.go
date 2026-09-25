// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"runtime"
	"testing"
)

// TestParseStreamAllocationBoundedByBody holds ParseStream's allocations to a small multiple of the body it
// is given. The body is agent-shaped on the uprobe path (a traced process's own SSL_read plaintext, up to
// httpstream's 64 MiB MaxBody after decoding) and parsed in the launcher, which also holds the ledger writer
// and the supervisor; splitting it into one string per line, and one frame per short line, costs 16 to 40
// bytes of headers per byte of body.
func TestParseStreamAllocationBoundedByBody(t *testing.T) {
	const n = 8 << 20
	for _, fill := range []string{"\n", "{\n", "event:\n\n", ":\n"} {
		body := bytes.Repeat([]byte(fill), n/len(fill))
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, _, _ = ParseStream(body)
		runtime.ReadMemStats(&after)
		if got := after.TotalAlloc - before.TotalAlloc; got > 4*uint64(len(body)) {
			t.Errorf("fill %q: ParseStream allocated %d MiB for a %d MiB body, want at most %d MiB",
				fill, got>>20, len(body)>>20, 4*len(body)>>20)
		}
	}
}
