// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// bodyTap is a Deriver that keeps a copy of every Message.Body derive was handed, then derives for real.
type bodyTap struct {
	next     Deriver
	mu       sync.Mutex
	req, res [][]byte
}

func (b *bodyTap) Handle(req, resp *derive.Message, meta derive.Meta) (derive.Result, error) {
	b.mu.Lock()
	b.req = append(b.req, bytes.Clone(req.Body))
	b.res = append(b.res, bytes.Clone(resp.Body))
	b.mu.Unlock()
	return b.next.Handle(req, resp, meta)
}

// TestDeriveReadsTheBytesTheBlobHolds is capture-derive.md I10 on the uprobe path: the Message.Body derive
// parsed is byte for byte what blob(sha) holds on disk, for both halves of the exchange, and the blob's own
// content hashes to the name the event records. The response is chunked, so derive's copy is the decoded
// body, never the wire's framing, and so must the blob be (R15). The store is the ledger's real one.
func TestDeriveReadsTheBytesTheBlobHolds(t *testing.T) {
	reqBody := `{"model":"claude-test","max_tokens":64,"messages":[{"role":"user","content":"` +
		strings.Repeat("é漢 ", 300) + `"}]}`
	request := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
	half := len(messagesReply) / 2
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" +
		strconv.FormatInt(int64(half), 16) + "\r\n" + messagesReply[:half] + "\r\n" +
		strconv.FormatInt(int64(len(messagesReply)-half), 16) + "\r\n" + messagesReply[half:] + "\r\n0\r\n\r\n"
	records := [][]byte{
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(request), false),
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLRead, 9_000_000, []byte(response), false),
	}
	runDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runDir, ledger.BlobsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	store := ledger.NewBlobRepository(runDir)
	tap := &bodyTap{next: derive.NewDispatcher([]derive.Parser{anthropic.New()})}
	rules := &agent.RuleTable{Record: agent.RecordFull, Contract: &agent.Contract{
		Models: []agent.ModelEndpoint{{Provider: anthropic.Provider, Host: "api.anthropic.com"}}}}
	u, sink := newTestUprobe(t, records, Options{Rules: rules, Blobs: store, Deriver: tap})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	var reqSHA, resSHA string
	for _, ev := range sink.events() {
		switch ev.Kind {
		case record.KindSSLRequest:
			var p record.SSLRequestPayload
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatal(err)
			}
			reqSHA = p.Blob
		case record.KindSSLResponse:
			var p record.SSLResponsePayload
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatal(err)
			}
			resSHA = p.Blob
		}
	}
	if len(tap.req) != 1 || len(tap.res) != 1 {
		t.Fatalf("derive saw %d requests and %d responses, want one exchange", len(tap.req), len(tap.res))
	}
	for _, c := range []struct {
		half   string
		sha    string
		parsed []byte
	}{{"request", reqSHA, tap.req[0]}, {"response", resSHA, tap.res[0]}} {
		if c.sha == "" {
			t.Fatalf("the %s names no blob under record: full", c.half)
		}
		rc, err := store.Get(c.sha)
		if err != nil {
			t.Fatalf("%s blob %s: %v", c.half, c.sha, err)
		}
		onDisk, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(onDisk)
		if got := hex.EncodeToString(sum[:]); got != c.sha {
			t.Errorf("%s blob hashes to %s, not the %s its event names", c.half, got, c.sha)
		}
		parsed := sha256.Sum256(c.parsed)
		if parsed != sum || !bytes.Equal(c.parsed, onDisk) {
			t.Errorf("%s: derive parsed %d bytes (sha %x), the blob holds %d (sha %x) (I10)", c.half,
				len(c.parsed), parsed, len(onDisk), sum)
		}
	}
	if string(tap.res[0]) != messagesReply {
		t.Errorf("derive's response body is not the dechunked reply: %q", tap.res[0])
	}
}
