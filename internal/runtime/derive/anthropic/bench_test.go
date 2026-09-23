// SPDX-License-Identifier: Apache-2.0

package anthropic

import "testing"

// BenchmarkParse measures one response on the budgeted path: derive runs once per model call, between
// the last response byte and the ssl_response line (§9 Benchmarks).
func BenchmarkParse(b *testing.B) {
	p := New()
	reqBody := readBench(b, "messages-request.json")
	shapes := []struct {
		name, file, contentType string
		sse                     bool
	}{
		{name: "json", file: "messages-response.json", contentType: "application/json"},
		{name: "stream", file: "messages-stream.sse", contentType: "text/event-stream", sse: true},
	}
	for _, s := range shapes {
		body := readBench(b, s.file)
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				req := request(reqBody)
				resp := response(body, s.contentType)
				resp.SSE = s.sse
				if _, err := p.Parse(req, resp); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// readBench is read() for a benchmark's testing.B.
func readBench(b *testing.B, name string) []byte {
	b.Helper()
	data, err := readFile(name)
	if err != nil {
		b.Fatal(err)
	}
	return data
}
