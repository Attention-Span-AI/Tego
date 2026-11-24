// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// oversizeGaps is the gap lines the sink holds, decoded.
func oversizeGaps(t *testing.T, sk *sink) []record.GapPayload {
	t.Helper()
	var out []record.GapPayload
	for _, e := range sk.of(record.KindGap) {
		var g record.GapPayload
		if err := e.DecodePayload(&g); err != nil {
			t.Fatal(err)
		}
		out = append(out, g)
	}
	return out
}

// wantOversize checks one gap line: what=record, the why, and a binary that names the server, the size and the limit.
func wantOversize(t *testing.T, g record.GapPayload, why, server string, minSize, limit int64) {
	t.Helper()
	srv, size, lim, ok := record.ParseOversizeNote(g.Binary)
	if g.What != record.GapRecord || g.Why != why || !ok || srv != server || lim != limit || size < minSize {
		t.Fatalf("gap %+v: parsed server %q size %d limit %d ok %v, want what=record why=%s server %s size >= %d limit %d",
			g, srv, size, lim, ok, why, server, minSize, limit)
	}
}

// TestOversizeServerLineIsRecorded (GAPS C201): a stdio server's answer past the size the relay reads is dropped, and the
// drop is a gap line in the record that names the server, how big the answer was and the limit.
func TestOversizeServerLineIsRecorded(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	if err := sh.fw.Write(Frame{Oversize: "s", Size: MaxLine + 12345}); err != nil {
		t.Fatal(err)
	}
	sh.client(toolCall(3, "read_file")) // the loop has handled the oversize frame once this one is answered
	if f := sh.read(); string(f.ToServer) != toolCall(3, "read_file") {
		t.Fatalf("the first frame back: %+v", f)
	}
	gs := oversizeGaps(t, sk)
	if len(gs) != 1 {
		t.Fatalf("gap lines %+v, want one", gs)
	}
	wantOversize(t, gs[0], record.GapMCPResponseOversize, "files", MaxLine+12345, MaxLine)
}

// TestOversizeLinesAreBounded: a server that answers with nothing but oversize lines writes record.OversizeLines lines
// and one counted line at the end, so the loss is all in the record and the record does not fill.
func TestOversizeLinesAreBounded(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	const sent = record.OversizeLines + 5
	for range sent {
		if err := sh.fw.Write(Frame{Oversize: "s", Size: MaxLine + 1}); err != nil {
			t.Fatal(err)
		}
	}
	sh.client(toolCall(3, "read_file"))
	_ = sh.read()
	if n := len(oversizeGaps(t, sk)); n != record.OversizeLines {
		t.Fatalf("%d gap lines, want %d", n, record.OversizeLines)
	}
	gaps := s.Gaps()
	if len(gaps) != 1 || gaps[0].What != record.GapRecord || gaps[0].Why != record.GapMCPResponseOversize ||
		gaps[0].Count != 5 || gaps[0].Binary != "" {
		t.Fatalf("Gaps() = %+v, want one counted line of 5", gaps)
	}
}

// httpOversizeRelay is a started HTTP relay of one server whose upstream is h.
func httpOversizeRelay(t *testing.T, h http.HandlerFunc) (relay string, sk *sink) {
	t.Helper()
	upstream := httptest.NewServer(h)
	t.Cleanup(upstream.Close)
	s, sk, _ := start(t, nil, Server{Name: "web", URL: upstream.URL + "/mcp", Rules: mcptool.Rules{Deny: []string{"delete_file"}}})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	return s.httpURLs()["web"], sk
}

const listRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

// TestOversizeHTTPAnswerIsRecorded (GAPS C201): a url server's tools/list answer past the bound is dropped with a 502,
// and the record has a line for it.
func TestOversizeHTTPAnswerIsRecorded(t *testing.T) {
	relay, sk := httpOversizeRelay(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"pad":"`+strings.Repeat("x", maxHTTPResult)+`"}}`)
	})
	resp, err := http.Post(relay, "application/json", strings.NewReader(listRequest))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	gs := oversizeGaps(t, sk)
	if len(gs) != 1 {
		t.Fatalf("gap lines %+v, want one", gs)
	}
	wantOversize(t, gs[0], record.GapMCPResponseOversize, "web", 0, maxHTTPResult)
	if !strings.Contains(gs[0].Binary, "more than") {
		t.Fatalf("binary %q: the relay stopped at the limit and must say it did not learn the size", gs[0].Binary)
	}
}

// TestOversizeStreamMessageIsRecorded (GAPS C202): one message of an event stream past the bound is left out of the
// stream, the messages around it still pass, and the record has a line that names the server, the size and the limit.
func TestOversizeStreamMessageIsRecorded(t *testing.T) {
	relay, sk := httpOversizeRelay(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"first\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"x\":\""+strings.Repeat("y", maxHTTPResult+100)+"\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"last\"}\n\n")
	})
	resp, err := http.Post(relay, "application/json", strings.NewReader(listRequest))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(b), `"first"`) || !strings.Contains(string(b), `"last"`) || strings.Contains(string(b), "yyyy") {
		t.Fatalf("the stream the client got: %.200s", b)
	}
	gs := oversizeGaps(t, sk)
	if len(gs) != 1 {
		t.Fatalf("gap lines %+v, want one", gs)
	}
	wantOversize(t, gs[0], record.GapMCPStreamOversize, "web", maxHTTPResult+100, maxHTTPResult)
}

func TestOversizeNoteRoundTrips(t *testing.T) {
	for _, c := range []struct {
		server      string
		size, limit int64
	}{{"files", 9000000, 8388608}, {"a: b", 0, 100}, {"x", 101, 100}} {
		srv, size, limit, ok := record.ParseOversizeNote(record.OversizeNote(c.server, c.size, c.limit))
		if !ok || srv != c.server || size != c.size || limit != c.limit {
			t.Errorf("%+v -> %q %d %d %v (note %q)", c, srv, size, limit, ok, record.OversizeNote(c.server, c.size, c.limit))
		}
	}
	if _, _, _, ok := record.ParseOversizeNote("/usr/bin/curl"); ok {
		t.Error("a binary path parsed as an oversize note")
	}
}
