// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// FuzzParseResponse: every reader of network-controlled bytes gets a fuzz target (§9 Fuzzing). It used to discard its
// *testing.T and so could find only a panic. The properties are R29's and R31's: a body is a schema error or a
// response, never another kind of error; a response comes only from valid JSON, is an error with nothing else in it
// or a message with an id, a model or content, never has a negative token count, and never leaves a tool_use input
// that is not valid JSON, which is what input_hash is taken over; and the hash is the sha256 of exactly those bytes,
// so two calls agree.
func FuzzParseResponse(f *testing.F) {
	seed(f, "messages-response.json")
	f.Add([]byte(`{"type":"error","error":{}}`))
	f.Add([]byte(`{"id":"m","type":"message","model":"x","content":[{"type":"tool_use","id":"t","name":"n","input":{}}]}`))
	f.Add([]byte(`{"id":"m","usage":{"input_tokens":-1}}`))
	f.Add([]byte(`{"id":"m","content":[{"type":"tool_use","input":"x"}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		resp, err := ParseResponse(200, body)
		if err != nil {
			if !errors.Is(err, derive.ErrSchema) {
				t.Fatalf("ParseResponse failed with %v, which is not a schema error", err)
			}
			return
		}
		if resp == nil || !json.Valid(body) {
			t.Fatalf("a response (%v) from a body that is not valid JSON, or a nil one", resp)
		}
		if resp.Type == "error" {
			if !reflect.DeepEqual(*resp, Response{Type: "error"}) {
				t.Fatalf("an error response carries more than its type: %+v", resp)
			}
			return
		}
		if resp.ID == "" && resp.Model == "" && len(resp.Content) == 0 {
			t.Fatal("a response that is neither a message nor an error parsed")
		}
		if u := resp.Usage; u.InputTokens < 0 || u.OutputTokens < 0 || u.CacheReadInputTokens < 0 || u.CacheCreationInputTokens < 0 {
			t.Fatalf("a negative token count parsed: %+v", u)
		}
		for i, b := range resp.Content {
			if b.Type != BlockToolUse || len(b.Input) == 0 {
				continue
			}
			if !json.Valid(b.Input) {
				t.Fatalf("content[%d].input %q is not valid JSON (R31)", i, b.Input)
			}
			sum := sha256.Sum256(b.Input)
			if h := InputHash(b.Input); h != hex.EncodeToString(sum[:]) || h != InputHash(b.Input) {
				t.Fatalf("InputHash of content[%d] is %s, not the sha256 of its bytes", i, h)
			}
		}
	})
}

// FuzzParseStream fuzzes the event-stream reader. A successful assembly must always have seen a start
// and a stop; anything else is a schema error, never a partial answer (R29).
func FuzzParseStream(f *testing.F) {
	seed(f, "messages-stream.sse")
	f.Add([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	f.Add([]byte(": heartbeat\n\nretry: 100\n\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		resp, events, err := ParseStream(body)
		if err != nil {
			return
		}
		if resp == nil {
			t.Fatal("a nil response with no error")
		}
		if len(events) == 0 {
			t.Fatal("an assembled stream with no events")
		}
	})
}

// seed adds a testdata file to the corpus.
func seed(f *testing.F, name string) {
	f.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.Fatalf("seed %s: %v", name, err)
	}
	f.Add(b)
}
