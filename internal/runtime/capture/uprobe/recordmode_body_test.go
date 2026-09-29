// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecordModeGatesBodyStorageNotEvents is record-ledger.md R12's summary and full halves on the capture
// path: under `record: summary` the exchange still reaches the ledger as an ssl_request and an ssl_response
// event, but neither names a blob and the run's blob directory stays empty (so R10 never fires); under
// `record: full` the same exchange names both blobs. The mode gates body storage, never event storage.
func TestRecordModeGatesBodyStorageNotEvents(t *testing.T) {
	const reqBody = `{"model":"claude-test","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`
	request := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(messagesReply)) +
		"\r\n\r\n" + messagesReply
	for _, tc := range []struct {
		mode      agent.RecordMode
		wantBlobs bool
	}{{agent.RecordSummary, false}, {agent.RecordFull, true}} {
		t.Run(string(tc.mode), func(t *testing.T) {
			records := [][]byte{
				chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(request), false),
				chunkRecord(41, 100, 100, 0xabc, bpf.SSLRead, 9_000_000, []byte(response), false),
			}
			runDir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(runDir, ledger.BlobsDir), 0o700); err != nil {
				t.Fatal(err)
			}
			rules := &agent.RuleTable{Record: tc.mode, Contract: &agent.Contract{
				Models: []agent.ModelEndpoint{{Provider: anthropic.Provider, Host: "api.anthropic.com"}}}}
			u, sink := newTestUprobe(t, records, Options{Rules: rules, Blobs: ledger.NewBlobRepository(runDir),
				Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

			var reqs, resps int
			for _, ev := range sink.events() {
				switch ev.Kind {
				case record.KindSSLRequest:
					var p record.SSLRequestPayload
					if err := json.Unmarshal(ev.Payload, &p); err != nil {
						t.Fatal(err)
					}
					reqs++
					if (p.Blob != "") != tc.wantBlobs {
						t.Errorf("record: %s: ssl_request blob %q, want a blob %v", tc.mode, p.Blob, tc.wantBlobs)
					}
				case record.KindSSLResponse:
					var p record.SSLResponsePayload
					if err := json.Unmarshal(ev.Payload, &p); err != nil {
						t.Fatal(err)
					}
					resps++
					if (p.Blob != "") != tc.wantBlobs {
						t.Errorf("record: %s: ssl_response blob %q, want a blob %v", tc.mode, p.Blob, tc.wantBlobs)
					}
				}
			}
			if reqs != 1 || resps != 1 {
				t.Errorf("record: %s: %d ssl_request and %d ssl_response events, want one each", tc.mode, reqs, resps)
			}
			var stored int
			_ = filepath.WalkDir(filepath.Join(runDir, ledger.BlobsDir), func(_ string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					stored++
				}
				return nil
			})
			if (stored > 0) != tc.wantBlobs {
				t.Errorf("record: %s: %d blob files on disk, want blobs %v", tc.mode, stored, tc.wantBlobs)
			}
		})
	}
}
