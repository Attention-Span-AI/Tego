// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// meteredSink is a fakeSink that also collects what the source reports unmetered (source.MeteredSink).
type meteredSink struct {
	fakeSink
	umu  sync.Mutex
	lost int64
	whys []string
}

func (s *meteredSink) Unmetered(n int64, why string) {
	s.umu.Lock()
	defer s.umu.Unlock()
	s.lost += n
	s.whys = append(s.whys, why)
}

func (s *meteredSink) reported() int64 {
	s.umu.Lock()
	defer s.umu.Unlock()
	return s.lost
}

// runMetered starts a source into a metered sink, waits for its drain and stops it.
func runMetered(t *testing.T, u *Uprobe, run source.RunRef) *meteredSink {
	t.Helper()
	sink := &meteredSink{}
	if err := u.Start(context.Background(), run, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-u.done
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	return sink
}

// R2-H2, capture-derive.md R7a: requests that never get a response are held in u.pending with their whole header map, outside the
// byte budget; R11's refused requests too, since the message is still returned and emitted.
func TestPendingRequestsHoldHeadersUnbounded(t *testing.T) {
	pad := strings.Repeat("a", 30<<10)
	req := []byte("GET /x HTTP/1.1\r\nHost: api.anthropic.com\r\nX-Pad: " + pad + "\r\n\r\n")
	const n = 4000
	records := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, uint64(1_000_000+i), req, false))
	}
	u, sink := newTestUprobe(t, records, Options{Rules: &agent.RuleTable{Record: agent.RecordSummary},
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	<-u.done
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	held := 0
	for _, byIndex := range u.pending {
		held += len(byIndex)
		for _, r := range byIndex {
			if r.Msg != nil && r.Msg.Header != nil {
				t.Error("a pending request keeps its header map for derive, which reads none of it")
			}
		}
	}
	t.Logf("%d requests held pending, heap in use %d MiB, budget used %d", held, ms.HeapInuse>>20, u.asm.Budget().Used())
	if held > 64 {
		t.Errorf("%d unanswered requests (%d MiB of header) held until Stop, none of it budgeted", held, held*30>>10)
	}
	var sizes int
	for _, ev := range sink.events() {
		if ev.Kind == record.KindSSLRequest {
			sizes++
		}
	}
	if sizes != n {
		t.Errorf("%d ssl_request lines for %d requests: a refused request still has its line", sizes, n)
	}
	_ = u.Stop()
}

// A refused request (R11) is recorded by its wire size, with no blob stored under record: full.
func TestRefusedRequestStoresNoBlob(t *testing.T) {
	var records [][]byte
	for i := 0; i < httpstream.DefaultMaxPipeline+3; i++ {
		records = append(records, chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, uint64(1_000_000+i),
			[]byte(exchangeRequest), false))
	}
	blobs := &fakeBlobs{}
	u, sink := newTestUprobe(t, records, Options{Blobs: blobs, Rules: &agent.RuleTable{Record: agent.RecordFull}})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	var withBlob, without int
	for _, ev := range sink.events() {
		if ev.Kind != record.KindSSLRequest {
			continue
		}
		var p record.SSLRequestPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Size != 17 {
			t.Errorf("size = %d, want the body's 17 bytes", p.Size)
		}
		if p.Blob != "" {
			withBlob++
		} else {
			without++
		}
	}
	if withBlob != httpstream.DefaultMaxPipeline || without != 3 {
		t.Errorf("%d requests stored a blob and %d did not; want the %d queued with one and the 3 refused without",
			withBlob, without, httpstream.DefaultMaxPipeline)
	}
}

// M1: a connection lost to a sequence hole while a request to a model host waited on it is reported unmetered,
// which ends a budgeted run; one to a host no models[] entry names is not.
func TestLostConnectionIsReportedUnmetered(t *testing.T) {
	for _, tc := range []struct {
		host string
		want int64
	}{{"api.anthropic.com", 1}, {"pypi.org", 0}} {
		t.Run(tc.host, func(t *testing.T) {
			const ssl = 0x5100
			request := strings.Replace(exchangeRequest, "api.anthropic.com", tc.host, 1)
			records := [][]byte{
				numbered(chunkRecord(41, 700, 700, ssl, bpf.SSLWrite, 1_000_000, []byte(request), false), 1),
				// seq 2, its response, never reached the ring
				numbered(chunkRecord(41, 700, 700, ssl, bpf.SSLWrite, 3_000_000, []byte(request), false), 3),
			}
			u, _ := newTestUprobe(t, records, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
			if got := sink.reported(); got != tc.want {
				t.Errorf("reported %d exchanges unmetered (%q), want %d", got, sink.whys, tc.want)
			}
		})
	}
}

// M1: a successful answer on a model host whose body the byte budget cut is reported unmetered.
func TestBudgetCutResponseIsReportedUnmetered(t *testing.T) {
	body := `{"id":"msg_01","type":"message","model":"m","content":[],"usage":{"input_tokens":5,"output_tokens":5}}`
	body += strings.Repeat(" ", 4<<20)
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	records := [][]byte{chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false)}
	for off, mono := 0, uint64(2_000_000); off < len(resp); off, mono = off+32<<10, mono+1 {
		records = append(records, chunkRecord(41, 100, 101, 0xabc, bpf.SSLRead, mono, []byte(resp[off:min(off+32<<10, len(resp))]), false))
	}
	asm := httpstream.NewAssembler(httpstream.Options{MaxBody: 1 << 20, MaxBytes: 3 << 20})
	// Hold most of the budget, as other connections' bodies would.
	held := asm.Budget().Take(asm.Budget().Limit() - 64<<10)
	defer asm.Budget().Give(held)
	u, _ := newTestUprobe(t, records, Options{Assembler: asm, Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if got := sink.reported(); got != 1 {
		t.Errorf("reported %d exchanges unmetered (%q), want the budget-cut response", got, sink.whys)
	}
}

// M2 (capture-derive.md E11): an SSL* whose one exchange is split across two threads — the request written on one, the response read
// on the other — is given up with a gap, never paired with a later exchange's response, and its loss is
// reported.
func TestSplitAcrossThreadsFailsClosed(t *testing.T) {
	const ssl = 0x7700
	on := func(tid uint32, dir uint8, seq uint32, mono uint64, data string) []byte {
		return numbered(chunkRecord(41, 700, tid, ssl, dir, mono, []byte(data), false), seq)
	}
	records := [][]byte{
		on(701, bpf.SSLWrite, 1, 1_000_000, exchangeRequest), // request 1 on thread 701
		on(702, bpf.SSLRead, 1, 2_000_000, exchangeResponse), // its response read on thread 702
		on(701, bpf.SSLWrite, 2, 3_000_000, exchangeRequest), // request 2 on 701
		on(701, bpf.SSLRead, 3, 4_000_000, exchangeResponse), // response 2 on 701: would pair with request 1
		on(702, bpf.SSLWrite, 2, 5_000_000, exchangeRequest), // and back again
		on(702, bpf.SSLRead, 3, 6_000_000, exchangeResponse),
	}
	u, _ := newTestUprobe(t, records, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if _, resps := countKinds(&sink.fakeSink); resps != 0 {
		t.Errorf("%d responses recorded for an SSL* whose I/O split across threads; any pairing is a guess", resps)
	}
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got < 1 {
		t.Errorf("the split left no gap: %+v", u.Gaps())
	}
	if got := sink.reported(); got != 1 {
		t.Errorf("reported %d unmetered, want the request that lost its response", got)
	}
}

// M2's other half: a connection handed to another thread between exchanges — a pool — loses nothing.
func TestHandoffBetweenExchangesKeepsPairing(t *testing.T) {
	const ssl = 0x7800
	on := func(tid uint32, dir uint8, seq uint32, mono uint64, data string) []byte {
		return numbered(chunkRecord(41, 700, tid, ssl, dir, mono, []byte(data), false), seq)
	}
	records := [][]byte{
		on(701, bpf.SSLWrite, 1, 1_000_000, exchangeRequest),
		on(701, bpf.SSLRead, 2, 2_000_000, exchangeResponse),
		on(702, bpf.SSLWrite, 1, 3_000_000, exchangeRequest),
		on(702, bpf.SSLRead, 2, 4_000_000, exchangeResponse),
		on(701, bpf.SSLWrite, 3, 5_000_000, exchangeRequest),
		on(701, bpf.SSLRead, 4, 6_000_000, exchangeResponse),
	}
	u, _ := newTestUprobe(t, records, Options{})
	sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if reqs, resps := countKinds(&sink.fakeSink); reqs != 3 || resps != 3 {
		t.Errorf("%d requests and %d responses, want 3 pairs across the handoffs", reqs, resps)
	}
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 0 {
		t.Errorf("a handoff between exchanges left %d malformed gaps", got)
	}
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}

// The source reports; the runner ends a run for a report only when it has a token or cost budget
// (runtime.captureUnmetered), so a report here is what ends a budgeted run.

// r3Metered runs records through a source with the Anthropic parser and returns what it reported unmetered.
func r3Metered(t *testing.T, records [][]byte) *meteredSink {
	t.Helper()
	u, _ := newTestUprobe(t, records, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	return runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
}

// h2cUpgrade is an HTTP/1.1 request asking host to upgrade the connection to h2c, and the 101 that does.
func h2cUpgrade(host string) (req, resp string) {
	req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" +
		"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n"
	resp = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
	return req, resp
}

// H2: an h2 connection is model spend capture cannot read. A preface on a fresh connection names no host, so
// it is reported unmetered, as is an upgrade from a model host; one capture learned is to another host is
// exempt.
func TestHTTP2UnderBudgetIsReportedUnmetered(t *testing.T) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	const ssl = 0x5300
	upgrade := func(host string) [][]byte {
		req, resp := h2cUpgrade(host)
		return [][]byte{
			chunkRecord(41, 710, 710, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false),
			chunkRecord(41, 710, 710, ssl, bpf.SSLRead, 2_000_000, []byte(resp), false),
		}
	}
	for _, tc := range []struct {
		name    string
		records [][]byte
		want    int64
	}{
		{"preface, host unknown", [][]byte{
			chunkRecord(41, 710, 710, ssl, bpf.SSLWrite, 1_000_000, []byte(preface), false)}, 1},
		{"upgrade from a model host", upgrade("api.anthropic.com"), 1},
		{"upgrade from a learned non-model host", upgrade("pypi.org"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := r3Metered(t, tc.records)
			if got := sink.reported(); got != tc.want {
				t.Errorf("reported %d exchanges unmetered (%q), want %d", got, sink.whys, tc.want)
			}
		})
	}
}

// M1: a request whose response capture never saw, followed by its connection's close or the source's stop,
// is reported unmetered when its host may have been a model's; one to a non-model host is not.
func TestUnansweredRequestAtCloseIsReportedUnmetered(t *testing.T) {
	const ssl = 0x5400
	for _, tc := range []struct {
		name  string
		host  string
		close bool
		want  int64
	}{
		{"close, model host", "api.anthropic.com", true, 1},
		{"close, non-model host", "pypi.org", true, 0},
		{"stop, model host", "api.anthropic.com", false, 1},
		{"stop, non-model host", "pypi.org", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := strings.Replace(exchangeRequest, "api.anthropic.com", tc.host, 1)
			records := [][]byte{chunkRecord(41, 720, 720, ssl, bpf.SSLWrite, 1_000_000, []byte(request), false)}
			if tc.close {
				records = append(records, closeRecord(41, 720, 720, ssl, 2_000_000))
			}
			sink := r3Metered(t, records)
			if got := sink.reported(); got != tc.want {
				t.Errorf("reported %d exchanges unmetered (%q), want %d", got, sink.whys, tc.want)
			}
		})
	}
}

// M1: an answered request leaves nothing pending, so its close reports nothing.
func TestAnsweredRequestAtCloseReportsNothing(t *testing.T) {
	const ssl = 0x5500
	req, resp := messagesExchange("length")
	sink := r3Metered(t, [][]byte{
		chunkRecord(41, 730, 730, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false),
		chunkRecord(41, 730, 730, ssl, bpf.SSLRead, 2_000_000, []byte(resp), false),
		closeRecord(41, 730, 730, ssl, 3_000_000),
	})
	if got := sink.reported(); got != 0 {
		t.Errorf("reported %d exchanges unmetered (%q) for an answered request", got, sink.whys)
	}
}

// Finding 5: loseConn counts a pending BadTarget request whatever its Host; closePending did not, so the same
// request lost at a close instead of a hole passed silently.
func TestBadTargetUnansweredAtCloseIsReported(t *testing.T) {
	const ssl = 0x5600
	body := `{"model":"claude-test","max_tokens":8,"messages":[]}`
	req := "POST api.anthropic.com/v1/messages HTTP/1.1\r\nHost: pypi.org\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	sink := r3Metered(t, [][]byte{
		chunkRecord(41, 740, 740, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false),
		closeRecord(41, 740, 740, ssl, 2_000_000),
	})
	if got := sink.reported(); got != 1 {
		t.Errorf("reported %d (%q), want 1: an unreadable target lost at close", got, sink.whys)
	}
}

// Finding 6: CONNECT through an HTTPS proxy is authority-form, and was taken for an unreadable target whose 200
// ended a budgeted run. It opens a tunnel: not spend, unless the tunnel reaches a model host, whose TLS inside
// capture cannot tell it reads (the h2 rule, ADR 0035). The tunnel's own bytes are not HTTP and cost nothing.
func TestConnectThroughTLSProxyIsNotSpend(t *testing.T) {
	const ssl = 0x5700
	tunnel := func(authority string) [][]byte {
		req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
		resp := "HTTP/1.1 200 Connection Established\r\n\r\n"
		return [][]byte{
			chunkRecord(41, 750, 750, ssl, bpf.SSLWrite, 1_000_000, []byte(req), false),
			chunkRecord(41, 750, 750, ssl, bpf.SSLRead, 2_000_000, []byte(resp), false),
			// The tunnel's TLS: a ClientHello's record header one way, a ServerHello's the other.
			chunkRecord(41, 750, 750, ssl, bpf.SSLWrite, 3_000_000, []byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"), false),
			chunkRecord(41, 750, 750, ssl, bpf.SSLRead, 4_000_000, []byte("\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03"), false),
			closeRecord(41, 750, 750, ssl, 5_000_000),
		}
	}
	for _, tc := range []struct {
		authority string
		want      int64
	}{
		{"pypi.org:443", 0},
		{"api.anthropic.com:443", 1},
	} {
		t.Run(tc.authority, func(t *testing.T) {
			u, _ := newTestUprobe(t, tunnel(tc.authority),
				Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
			if got := sink.reported(); got != tc.want {
				t.Errorf("reported %d (%q), want %d", got, sink.whys, tc.want)
			}
			for _, g := range u.Gaps() {
				if g.Why == httpstream.GapMalformed {
					t.Errorf("the tunnel's bytes were parsed as HTTP: %+v", g)
				}
			}
		})
	}
}

// messagesExchange is a non-streaming Messages API request and a JSON answer to it, the answer's framing given.
func messagesExchange(framing string) (req, resp string) {
	body := `{"model":"claude-test","max_tokens":8,"messages":[]}`
	req = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	answer := `{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`
	head := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
	if framing == "length" {
		head += "Content-Length: " + strconv.Itoa(len(answer)) + "\r\n"
	}
	return req, head + "\r\n" + answer
}

// The pipelined-drop check (asked alongside finding 3): emitResponse drops a pending request older than the one
// a response answers. Its comment said only refused and headless requests reach there, but neither is ever
// pending: what does is a request whose connection httpstream ended under the same key without answering it —
// a close-delimited response ended by the next connection's first request (conn.endCloseDelimited). That
// request is unanswered, and was dropped with no report.
func TestPipelinedRequestLostToAnEndedConnectionIsReported(t *testing.T) {
	const ssl = 0x5800
	req, closeDelimited := messagesExchange("close")
	_, withLength := messagesExchange("length")
	sink := r3Metered(t, [][]byte{
		// Two requests pipelined; the first is answered by a response whose body ends only at the close.
		chunkRecord(41, 760, 760, ssl, bpf.SSLWrite, 1_000_000, []byte(req+req), false),
		chunkRecord(41, 760, 760, ssl, bpf.SSLRead, 2_000_000, []byte(closeDelimited), false),
		// The next connection on the same SSL* and thread, its close never seen: the second request above
		// will never be answered.
		chunkRecord(41, 760, 760, ssl, bpf.SSLWrite, 3_000_000, []byte(req), false),
		chunkRecord(41, 760, 760, ssl, bpf.SSLRead, 4_000_000, []byte(withLength), false),
	})
	if got := sink.reported(); got != 1 {
		t.Errorf("reported %d (%q), want 1: the pipelined request its connection ended without answering", got, sink.whys)
	}
}

// Finding 4, uprobe side: a request body larger than the reassembler keeps does not parse, so derive had no
// max_tokens to bound a cut stream by, and reported it unmetered. httpstream reads the bound off every byte.
func TestLargeRequestCutStreamIsBounded(t *testing.T) {
	const ssl = 0x5900
	body := `{"model":"claude-test","stream":true,"messages":[{"role":"user","content":"` +
		strings.Repeat("x", 60<<10) + `"}],"max_tokens":2048}`
	head := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n"
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-test","usage":{"input_tokens":20000,"output_tokens":1}}}` +
		"\n\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + strconv.Itoa(len(stream)) +
		"\r\n\r\n" + stream
	wire := head + body
	var records [][]byte
	for mono := uint64(1_000_000); len(wire) > 0; mono++ {
		n := min(len(wire), 16<<10)
		records = append(records, chunkRecord(41, 770, 770, ssl, bpf.SSLWrite, mono, []byte(wire[:n]), false))
		wire = wire[n:]
	}
	records = append(records, chunkRecord(41, 770, 770, ssl, bpf.SSLRead, 9_000_000, []byte(resp), false))
	u, _ := newTestUprobe(t, records, Options{
		Deriver:   derive.NewDispatcher([]derive.Parser{anthropic.New()}),
		Assembler: httpstream.NewAssembler(httpstream.Options{MaxBody: 16 << 10, BodyScanner: maxTokensScanner}),
	})
	sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if got := sink.reported(); got != 0 {
		t.Errorf("reported %d (%q): a cut stream whose request stated max_tokens on the wire", got, sink.whys)
	}
	var found bool
	for _, ev := range sink.events() {
		if ev.Kind != record.KindSSLResponse {
			continue
		}
		var p record.SSLResponsePayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		found = true
		if p.Usage == nil || p.Usage.Output != 2048 || !p.Usage.OutputBound {
			t.Errorf("usage = %+v, want output 2048 marked a bound", p.Usage)
		}
	}
	if !found {
		t.Fatal("no ssl_response")
	}
}

// abandonSink also collects the pairs the source gave up on (source.AbandonSink).
type abandonSink struct {
	meteredSink
	pairs []uint64
}

func (s *abandonSink) Abandoned(pair uint64) {
	s.umu.Lock()
	defer s.umu.Unlock()
	s.pairs = append(s.pairs, pair)
}

// A request whose connection was lost is reported abandoned by its pair, so derive.Steps does not keep the
// thread in flight (capture-derive.md R33).
func TestLostConnectionAbandonsItsRequest(t *testing.T) {
	const ssl = 0x5100
	records := [][]byte{
		numbered(chunkRecord(41, 700, 700, ssl, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false), 1),
		numbered(chunkRecord(41, 700, 700, ssl, bpf.SSLWrite, 3_000_000, []byte(exchangeRequest), false), 3),
	}
	u, _ := newTestUprobe(t, records, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	sink := &abandonSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	<-u.done
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	var first uint64
	for _, ev := range sink.events() {
		if ev.Kind == record.KindSSLRequest {
			first = ev.Pair
			break
		}
	}
	if first == 0 || !slices.Contains(sink.pairs, first) {
		t.Errorf("abandoned pairs %v, want the lost request's pair %d", sink.pairs, first)
	}
}
