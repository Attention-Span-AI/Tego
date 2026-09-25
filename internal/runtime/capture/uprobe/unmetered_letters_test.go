// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// letterRow is one lettered case of docs/p0/limits-check-doctor-cli.md R1 on the uprobe path: the chunk
// records a run's traffic produces, and whether the source reports it unmetered. The report is the whole of
// the uprobe path's decision: the runner ends a run with a token or cost budget at the first one and leaves a
// run with neither running (runtime.TestUnmeteredSpendEndsABudgetedRun), so reported here is "the budgeted run
// ends" and not reported is "it runs on".
type letterRow struct {
	letter, name string
	records      [][]byte
	// opts, when set, builds the source; nil is the Anthropic parser with the default reassembler.
	opts func() (Options, func())
	// reported says the row ends a budgeted run; why, when set, is a substring the report's detail carries,
	// which tells apart the paths that give up on a request (e: close, stop, restart, a later answer, eviction).
	reported bool
	why      string
}

// letterRequest is a Messages API request to host with body.
func letterRequest(method, target, host, body string) string {
	return method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// letterResponse is an answer with status, content type and a Content-Length framed body.
func letterResponse(status int, ctype, body string) string {
	return "HTTP/1.1 " + strconv.Itoa(status) + " X\r\nContent-Type: " + ctype + "\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

const (
	letterMessage = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`
	letterStart = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-test","usage":{"input_tokens":20,"output_tokens":1}}}` +
		"\n\n"
	letterStreamError = "event: error\n" +
		`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}` + "\n\n"
)

// exchangeOn is one request and its answer on one SSL*, and optionally its close.
func exchangeOn(ssl uint64, req, resp string, closeIt bool) [][]byte {
	recs := [][]byte{chunkRecord(41, 900, 900, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false)}
	if resp != "" {
		recs = append(recs, chunkRecord(41, 900, 900, ssl, bpf.SSLRead, 2_000_000, []byte(resp), false))
	}
	if closeIt {
		recs = append(recs, closeRecord(41, 900, 900, ssl, 3_000_000))
	}
	return recs
}

// TestEveryR1LetterOnTheUprobePath is limits-check-doctor-cli.md R1's two lists on the uprobe path, one row per
// letter the path can meet (the sub-cases a letter names each have a row): every "Reported as unmetered" case
// ends a budgeted run, every "Not reported" case does not. The letters the uprobe path cannot meet are pinned
// at their own layer: (j) the hook queue is the runner's (runtime.TestHookQueueNeverWaitsAndCountsWhatItDrops),
// (r) the price table's (runtime.TestUnfeedServerToolEndsACostBudgetedRun and limits' server-tool tests), (o)
// the forwarder's dial (forwarder.TestEveryR1LetterOnTheForwarder).
func TestEveryR1LetterOnTheUprobePath(t *testing.T) {
	const model = "api.anthropic.com"
	msgs := `{"model":"claude-test","max_tokens":8,"messages":[]}`
	stream := `{"model":"claude-test","stream":true,"max_tokens":2048,"messages":[]}`
	streamNoBound := `{"model":"claude-test","stream":true,"messages":[]}`
	h2cReq, h2cResp := h2cUpgrade("pypi.org")
	tunnel := func(authority string) [][]byte {
		return exchangeOn(0x6100, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n",
			"HTTP/1.1 200 Connection Established\r\n\r\n", true)
	}
	budgetCut := func() (Options, func()) {
		asm := httpstream.NewAssembler(httpstream.Options{MaxBody: 1 << 20, MaxBytes: 3 << 20})
		held := asm.Budget().Take(asm.Budget().Limit() - 64<<10)
		return Options{Assembler: asm, Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})},
			func() { asm.Budget().Give(held) }
	}
	bigBody := `{"id":"msg_01","type":"message","model":"m","content":[],"usage":{"input_tokens":5,"output_tokens":5}}` +
		strings.Repeat(" ", 4<<20)
	bigRecordsFor := func(ssl uint64, req, body string) [][]byte {
		resp := letterResponse(200, "application/json", body)
		recs := [][]byte{chunkRecord(41, 900, 900, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false)}
		for off, mono := 0, uint64(2_000_000); off < len(resp); off, mono = off+32<<10, mono+1 {
			recs = append(recs, chunkRecord(41, 900, 900, ssl, bpf.SSLRead, mono,
				[]byte(resp[off:min(off+32<<10, len(resp))]), false))
		}
		return recs
	}
	bigRecords := bigRecordsFor(0x6200, letterRequest("POST", "/v1/messages", model, msgs), bigBody)
	bigFile := bigRecordsFor(0x6201, letterRequest("GET", "/v1/files/file_1/content", model, ""), strings.Repeat("x", 4<<20))
	// (e) the pending table's bound: one more request than a connection may hold waiting, none answered; the
	// oldest is given up at once.
	var evict [][]byte
	for i := 0; i <= maxPendingPerConn; i++ {
		evict = append(evict, chunkRecord(41, 900, 900, 0x6300, bpf.SSLWrite, uint64(1_000_000+i),
			[]byte(letterRequest("POST", "/v1/messages", model, msgs)), false))
	}
	pipelinedReq := letterRequest("POST", "/v1/messages", model, msgs)
	closeDelimited := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + letterMessage
	on := func(ssl uint64, tid uint32, dir uint8, seq uint32, mono uint64, data string) []byte {
		return numbered(chunkRecord(41, 900, tid, ssl, dir, mono, []byte(data), false), seq)
	}

	rows := []letterRow{
		// Reported as unmetered.
		{letter: "a", name: "2xx body with no usage", records: exchangeOn(0x6001,
			letterRequest("POST", "/v1/messages", model, msgs), letterResponse(200, "application/json", `{"id":"msg_1"}`), false),
			reported: true, why: "usage unreadable"},
		{letter: "a", name: "2xx on a /v1 path the parser reads no usage from", records: exchangeOn(0x6002,
			letterRequest("POST", "/v1/unknown", model, msgs), letterResponse(200, "application/json", letterMessage), false),
			reported: true, why: "usage unreadable"},
		{letter: "a", name: "2xx on /V1/messages", records: exchangeOn(0x6003,
			letterRequest("POST", "/V1/messages", model, msgs), letterResponse(200, "application/json", letterMessage), false),
			reported: true, why: "usage unreadable"},
		{letter: "a", name: "2xx on /v1;x/messages", records: exchangeOn(0x6004,
			letterRequest("POST", "/v1;x/messages", model, msgs), letterResponse(200, "application/json", letterMessage), false),
			reported: true, why: "usage unreadable"},
		{letter: "b", name: "message batch created", records: exchangeOn(0x6005,
			letterRequest("POST", "/v1/messages/batches", model, `{"requests":[]}`),
			letterResponse(200, "application/json", `{"id":"msgbatch_1","type":"message_batch","processing_status":"in_progress"}`), false),
			reported: true},
		{letter: "c", name: "stream cut after message_start, no max_tokens", records: exchangeOn(0x6006,
			letterRequest("POST", "/v1/messages", model, streamNoBound), letterResponse(200, "text/event-stream", letterStart), false),
			reported: true, why: "usage unreadable"},
		{letter: "d", name: "2xx body the byte budget cut", records: bigRecords, opts: budgetCut,
			reported: true, why: "usage unreadable"},
		{letter: "e", name: "unanswered at close", records: exchangeOn(0x6007,
			letterRequest("POST", "/v1/messages", model, msgs), "", true),
			reported: true, why: "before its connection closed"},
		{letter: "e", name: "unanswered at the source's stop", records: exchangeOn(0x6008,
			letterRequest("POST", "/v1/messages", model, msgs), "", false),
			reported: true, why: "before the capture source stopped"},
		{letter: "e", name: "the SSL* starts a new connection (count at 1)", records: [][]byte{
			on(0x6009, 900, bpf.SSLWrite, 1, 1_000_000, letterRequest("POST", "/v1/messages", model, msgs)),
			on(0x6009, 900, bpf.SSLWrite, 1, 2_000_000, letterRequest("GET", "/v1/models", model, "")),
			on(0x6009, 900, bpf.SSLRead, 2, 3_000_000, letterResponse(200, "application/json", `{"data":[]}`)),
		}, reported: true, why: "before its connection ended"},
		{letter: "e", name: "a later response shows it never will be answered", records: [][]byte{
			chunkRecord(41, 900, 900, 0x600a, bpf.SSLWrite, 1_000_000, []byte(pipelinedReq+pipelinedReq), false),
			chunkRecord(41, 900, 900, 0x600a, bpf.SSLRead, 2_000_000, []byte(closeDelimited), false),
			chunkRecord(41, 900, 900, 0x600a, bpf.SSLWrite, 3_000_000, []byte(pipelinedReq), false),
			chunkRecord(41, 900, 900, 0x600a, bpf.SSLRead, 4_000_000, []byte(letterResponse(200, "application/json", letterMessage)), false),
		}, reported: true, why: "before its connection ended"},
		{letter: "e", name: "evicted from the pending table", records: evict, opts: func() (Options, func()) {
			// A reassembler that queues more than the table holds, so the table's own bound is what gives up.
			return Options{Assembler: httpstream.NewAssembler(httpstream.Options{MaxPipeline: 4 * maxPendingPerConn}),
				Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})}, func() {}
		}, reported: true, why: "given up waiting for"},
		{letter: "e", name: "unreadable target unanswered, whatever its Host", records: exchangeOn(0x600b,
			letterRequest("POST", "api.anthropic.com/v1/messages", "pypi.org", msgs), "", true), reported: true},
		{letter: "f", name: "sequence hole with a model request waiting", records: [][]byte{
			on(0x600c, 900, bpf.SSLWrite, 1, 1_000_000, letterRequest("POST", "/v1/messages", model, msgs)),
			on(0x600c, 900, bpf.SSLWrite, 3, 3_000_000, letterRequest("POST", "/v1/messages", model, msgs)),
		}, reported: true, why: "capture hole"},
		{letter: "f", name: "sequence hole with nothing waiting, last host a model's", records: [][]byte{
			on(0x600d, 900, bpf.SSLWrite, 1, 1_000_000, letterRequest("POST", "/v1/messages", model, msgs)),
			on(0x600d, 900, bpf.SSLRead, 2, 2_000_000, letterResponse(200, "application/json", letterMessage)),
			on(0x600d, 900, bpf.SSLWrite, 4, 4_000_000, letterRequest("POST", "/v1/messages", model, msgs)),
		}, reported: true, why: "capture hole"},
		{letter: "f", name: "an SSL*'s I/O split across threads", records: [][]byte{
			on(0x600e, 901, bpf.SSLWrite, 1, 1_000_000, letterRequest("POST", "/v1/messages", model, msgs)),
			on(0x600e, 902, bpf.SSLRead, 1, 2_000_000, letterResponse(200, "application/json", letterMessage)),
		}, reported: true, why: "split across two threads"},
		{letter: "g", name: "h2 preface on a fresh connection", records: [][]byte{
			chunkRecord(41, 900, 900, 0x600f, bpf.SSLWrite, 1_000_000, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), false),
		}, reported: true, why: "HTTP/2"},
		{letter: "h", name: "2xx to an unreadable target", records: exchangeOn(0x6010,
			letterRequest("POST", "api.anthropic.com/v1/messages", "pypi.org", msgs),
			letterResponse(200, "application/json", letterMessage), false), reported: true, why: "usage unreadable"},
		{letter: "i", name: "CONNECT tunnel to a model host", records: tunnel("api.anthropic.com:443"),
			reported: true, why: "usage unreadable"},

		// Not reported.
		{letter: "k", name: "4xx on /v1/messages", records: exchangeOn(0x6011,
			letterRequest("POST", "/v1/messages", model, msgs),
			letterResponse(429, "application/json", `{"type":"error","error":{"type":"rate_limit_error"}}`), true)},
		{letter: "k", name: "2xx stream whose first event is an error", records: exchangeOn(0x6012,
			letterRequest("POST", "/v1/messages", model, streamNoBound),
			letterResponse(200, "text/event-stream", letterStreamError), true)},
		{letter: "l", name: "model listing answered", records: exchangeOn(0x6013,
			letterRequest("GET", "/v1/models", model, ""), letterResponse(200, "application/json", `{"data":[]}`), true)},
		{letter: "l", name: "token counting unanswered", records: exchangeOn(0x6014,
			letterRequest("POST", "/v1/messages/count_tokens", model, msgs), "", true)},
		{letter: "l", name: "batch status answered", records: exchangeOn(0x6015,
			letterRequest("GET", "/v1/messages/batches/msgbatch_1", model, ""),
			letterResponse(200, "application/json", `{"id":"msgbatch_1","type":"message_batch"}`), true)},
		{letter: "l", name: "telemetry outside /v1 unanswered", records: exchangeOn(0x6016,
			letterRequest("POST", "/api/event_logging/batch", model, `{"events":[]}`), "", true)},
		{letter: "l", name: "files download the byte budget cut", records: bigFile, opts: budgetCut},
		{letter: "m", name: "stream cut after message_start, max_tokens known", records: exchangeOn(0x6017,
			letterRequest("POST", "/v1/messages", model, stream), letterResponse(200, "text/event-stream", letterStart), true)},
		{letter: "m", name: "stream cut after an error event past message_start", records: exchangeOn(0x6018,
			letterRequest("POST", "/v1/messages", model, stream),
			letterResponse(200, "text/event-stream", letterStart+letterStreamError), true)},
		{letter: "n", name: "exchange with a host no model entry or parser claims", records: exchangeOn(0x6019,
			letterRequest("POST", "/v1/messages", "pypi.org", msgs), letterResponse(200, "application/json", `{"ok":1}`), true)},
		{letter: "p", name: "an exchange whose request start capture missed", records: [][]byte{
			numbered(chunkRecord(41, 900, 900, 0x601a, bpf.SSLWrite, 1_000_000, []byte(`"messages":[]}`), false), 1),
			numbered(chunkRecord(41, 900, 900, 0x601a, bpf.SSLRead, 2_000_000,
				[]byte(letterResponse(200, "application/json", letterMessage)), false), 2),
		}},
		{letter: "q", name: "h2c upgrade from a learned non-model host", records: [][]byte{
			chunkRecord(41, 900, 900, 0x601b, bpf.SSLWrite, 1_000_000, []byte(h2cReq), false),
			chunkRecord(41, 900, 900, 0x601b, bpf.SSLRead, 2_000_000, []byte(h2cResp), false),
		}},
		{letter: "q", name: "CONNECT tunnel to a non-model host", records: tunnel("pypi.org:443")},
		{letter: "q", name: "a connection that closes with nothing waiting", records: exchangeOn(0x601c,
			letterRequest("POST", "/v1/messages", model, msgs), letterResponse(200, "application/json", letterMessage), true)},
	}
	for _, row := range rows {
		t.Run("("+row.letter+") "+row.name, func(t *testing.T) {
			opts := Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})}
			if row.opts != nil {
				var done func()
				opts, done = row.opts()
				defer done()
			}
			u, _ := newTestUprobe(t, row.records, opts)
			sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
			got := sink.reported()
			switch {
			case row.reported && got == 0:
				t.Fatalf("R1 (%s) is reported as unmetered and so ends a budgeted run; the source reported nothing", row.letter)
			case !row.reported && got != 0:
				t.Fatalf("R1 (%s) is not reported, and a budgeted run would have ended: reported %d (%q)", row.letter, got, sink.whys)
			}
			if row.why != "" && !strings.Contains(strings.Join(sink.whys, "|"), row.why) {
				t.Errorf("R1 (%s): reports %q, want one saying %q", row.letter, sink.whys, row.why)
			}
		})
	}
}
