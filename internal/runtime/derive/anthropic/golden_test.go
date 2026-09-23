// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// updateGolden rewrites the frozen facts instead of comparing against them.
var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata/golden/")

// goldenFacts is the JSON shape frozen per API shape (§10 "golden per API shape"): exactly the fields
// this parser puts on an ssl_response, plus the decisions it derives.
type goldenFacts struct {
	Model         string            `json:"model"`
	ResponseID    string            `json:"response_id"`
	StopReason    string            `json:"stop_reason"`
	Usage         any               `json:"usage"`
	ParserVersion string            `json:"parser_version"`
	Stream        bool              `json:"stream"`
	Decisions     []derive.Decision `json:"decisions"`
}

// TestGoldenFacts freezes what each API shape derives. It fails when a field, a hash or the decision
// order changes — the review every consumer of ssl_response and decision needs.
func TestGoldenFacts(t *testing.T) {
	cases := []struct {
		name, file, golden, contentType string
		sse                             bool
	}{
		{name: "non-streaming", file: "messages-response.json", golden: "nonstreaming.json", contentType: "application/json"},
		{name: "streaming", file: "messages-stream.sse", golden: "streaming.json", contentType: "text/event-stream", sse: true},
	}
	p := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := response(read(t, tc.file), tc.contentType)
			resp.SSE = tc.sse
			facts, err := p.Parse(request(read(t, "messages-request.json")), resp)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := json.MarshalIndent(goldenFacts{
				Model: facts.Model, ResponseID: facts.ResponseID, StopReason: facts.StopReason,
				Usage: facts.Usage, ParserVersion: facts.ParserVersion, Stream: facts.Stream,
				Decisions: facts.Decisions,
			}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", "golden", tc.golden)
			if *updateGolden {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("wrote %s", path)
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./internal/runtime/derive/anthropic -run TestGoldenFacts -update)", err)
			}
			if !bytes.Equal(want, got) {
				t.Errorf("the frozen facts changed.\n--- want\n%s\n--- got\n%s", want, got)
			}
		})
	}
}

// TestGoldenIsCredentialFree: I5 — no credential ever reaches what this parser produces. The request
// bodies carry one in a header the parser never reads; the golden files must not contain it.
func TestGoldenIsCredentialFree(t *testing.T) {
	const credential = "sk-ant-test-credential"
	req := request(read(t, "messages-request.json"))
	req.Header.Set("x-api-key", credential)
	resp := response(read(t, "messages-response.json"), "application/json")
	facts, err := New().Parse(req, resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	blob, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(credential)) {
		t.Error("a credential reached the derived facts")
	}
	for _, name := range []string{"nonstreaming.json", "streaming.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte(credential)) || bytes.Contains(bytes.ToLower(b), []byte("x-api-key")) {
			t.Errorf("%s carries a credential", name)
		}
	}
}
