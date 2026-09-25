// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
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

func (b *bodyTap) bodies() (req, res [][]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.req, b.res
}

// blobOf stores an event's "body" field the way the ledger's R10 split does (the decoded string's bytes
// through the run's blob store) and reads the blob back by the sha the store named, checking the name is
// the content's own hash.
func blobOf(t *testing.T, store ledger.BlobRepository, ev *record.Event) []byte {
	t.Helper()
	var fields struct {
		Body *string `json:"body"`
	}
	if err := json.Unmarshal(ev.Payload, &fields); err != nil {
		t.Fatal(err)
	}
	if fields.Body == nil {
		t.Fatalf("%s carries no body: %s", ev.Kind, ev.Payload)
	}
	sha, err := store.Put([]byte(*fields.Body))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := store.Get(sha)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	onDisk, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(onDisk)
	if hex.EncodeToString(sum[:]) != sha {
		t.Fatalf("blob %s holds content hashing to %x", sha, sum)
	}
	return onDisk
}

// TestDeriveReadsTheBytesTheBlobHolds is capture-derive.md I10 on the forwarder path: the Message.Body derive
// parsed is byte for byte what blob(sha) holds, for both halves, a plain answer and a gzip one alike (the
// blob holds decoded content, R15). The bodies are over the ledger's blob threshold, so each really is
// stored as a blob rather than inline.
func TestDeriveReadsTheBytesTheBlobHolds(t *testing.T) {
	answer := `{"id":"msg_01Xq0001Z","type":"message","model":"claude-opus-5","stop_reason":"end_turn",` +
		`"content":[{"type":"text","text":"` + strings.Repeat("é漢<&> ", 1200) + `"}],` +
		`"usage":{"input_tokens":10,"output_tokens":20}}`
	for _, gz := range []bool{false, true} {
		name := map[bool]string{false: "identity", true: "gzip"}[gz]
		t.Run(name, func(t *testing.T) {
			tap := &bodyTap{next: derive.NewDispatcher([]derive.Parser{anthropic.New()})}
			h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if gz {
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write(gzipBytes(t, answer))
					return
				}
				_, _ = w.Write([]byte(answer))
			}, Options{Deriver: tap})
			reqBody := []byte(`{"model":"claude-opus-5","max_tokens":64,"messages":[{"role":"user","content":"` +
				strings.Repeat("q", 5000) + `"}]}`)
			resp := h.post("/v1/messages", reqBody, nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			reqEv := h.sink.waitFor(t, record.KindSSLRequest, 1)[0]
			resEv := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]

			runDir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(runDir, ledger.BlobsDir), 0o700); err != nil {
				t.Fatal(err)
			}
			store := ledger.NewBlobRepository(runDir)
			reqs, ress := tap.bodies()
			if len(reqs) != 1 || len(ress) != 1 {
				t.Fatalf("derive saw %d requests and %d responses, want one exchange", len(reqs), len(ress))
			}
			for _, c := range []struct {
				half   string
				ev     *record.Event
				parsed []byte
			}{{"request", reqEv, reqs[0]}, {"response", resEv, ress[0]}} {
				onDisk := blobOf(t, store, c.ev)
				if len(onDisk) <= ledger.BlobThreshold {
					t.Fatalf("%s body is %d bytes, under the blob threshold", c.half, len(onDisk))
				}
				if sha256.Sum256(c.parsed) != sha256.Sum256(onDisk) || !bytes.Equal(c.parsed, onDisk) {
					t.Errorf("%s: derive parsed %d bytes, the blob holds %d (I10)", c.half, len(c.parsed),
						len(onDisk))
				}
			}
			if string(ress[0]) != answer {
				t.Errorf("derive's response body is not the decoded answer (%d bytes)", len(ress[0]))
			}
		})
	}
}
