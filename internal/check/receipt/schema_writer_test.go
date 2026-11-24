// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var receiptSchema = filepath.Join("..", "..", "..", "spec", "receipt", "receipt-v1.schema.json")

// jsonOf is the receipt as `tego receipt --json` writes it.
func jsonOf(t *testing.T, rc *Receipt) map[string]any {
	t.Helper()
	var b bytes.Buffer
	if err := rc.JSON(&b); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestWriterMatchesPublishedSchema: what the builder writes validates against spec/receipt/receipt-v1.schema.json, read by
// the real validator: the receipt of every record fixture, bound (every binding this tego writes) and not, and of runs
// built to give each coverage code a gap; and the receipts the CI action keeps. A key the writer adds, drops or spells
// another way, or a value outside the schema's enums, fails here, as pkg/spec/receipt's TestSchemaMatchesTypes fails a
// type that drifts (C163).
func TestWriterMatchesPublishedSchema(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if len(files) < 15 {
		t.Fatalf("found %d record fixtures", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, bind := range []*MadeBy{nil, &testBy} {
				for _, v := range []int{1, 2} {
					r, err := ledger.OpenReader(dir)
					if err != nil {
						t.Fatal(err)
					}
					r.SkipNewerVersions()
					rc, err := Compute(context.Background(), r, Options{Bind: bind, BindVersion: v, Prices: flatPrices{}, Home: "/home/u"})
					_ = r.Close()
					if err != nil {
						t.Skipf("no receipt for %s: %v", filepath.Base(f), err)
					}
					jsonschema.Validate(t, receiptSchema, jsonOf(t, rc))
					if bind == nil {
						break
					}
				}
			}
		})
	}
	// Runs built to carry a gap of each kind the builder writes.
	gap := func(what, why string, n int) line {
		return line{kind: record.KindGap, at: time.Second, payload: record.GapPayload{What: what, Why: why, Count: n}}
	}
	req := line{kind: record.KindSSLRequest, payload: record.SSLRequestPayload{Endpoint: "messages", Method: "POST", Host: "h"}}
	resp := line{kind: record.KindSSLResponse, at: time.Second, payload: map[string]any{"request_seq": 1, "status": 200, "parser_version": "1", "model": "m", "latency_ms": 1}}
	for name, lines := range map[string][]line{
		"capture off and a lost action": {start("off", false), gap(record.GapRecord, "channel-full", 3)},
		"capture gap, unmetered and no price table": {start("forwarder", true), gap(record.GapRecord, record.GapNoPriceTable, 0),
			gap(record.GapCapture, "no-openssl", 0), req, resp, end(2*time.Second, 0)},
		"live changes": pausedAndBlockedRun(),
		"asks": {start("off", true), {kind: record.KindAsk, payload: map[string]any{"ask_id": "q", "hold": "open", "op": "open", "target": "/w/x", "ask_rule": "fs.ask[./w/]"}},
			{kind: record.KindAsk, payload: map[string]any{"ask_id": "q", "hold": "open", "op": "open", "target": "/w/y", "ask_rule": "fs.ask[./w/]"}}},
	} {
		t.Run(name, func(t *testing.T) {
			jsonschema.Validate(t, receiptSchema, jsonOf(t, compute(t, lines, Options{})))
		})
	}
	for _, f := range []string{
		"../../../action/testdata/receipt.json", "../../../action/testdata/bindings/v1/receipt.json", "../../../action/testdata/bindings/v2/receipt.json",
	} {
		t.Run(strings.TrimPrefix(f, "../../../"), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var doc any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			jsonschema.Validate(t, receiptSchema, doc)
		})
	}
}

// TestSchemaRefusesWhatTheWriterNeverWrites: the schema is the contract, so it refuses a receipt with a key the types do not
// write, a coverage code or level it does not name, a missing required key, and a wrong type.
func TestSchemaRefusesWhatTheWriterNeverWrites(t *testing.T) {
	good := func() map[string]any {
		return jsonOf(t, compute(t, []line{start("off", false), gap2("channel-full"), end(2*time.Second, 0)}, Options{}))
	}
	jsonschema.Validate(t, receiptSchema, good())
	for name, mutate := range map[string]func(m map[string]any){
		"an unknown key":         func(m map[string]any) { m["extra"] = 1 },
		"an unknown key deeper":  func(m map[string]any) { m["tokens"].(map[string]any)["extra"] = 1 },
		"a missing required key": func(m map[string]any) { delete(m, "coverage") },
		"a wrong type":           func(m map[string]any) { m["lines"] = "many" },
		"another receipt_v":      func(m map[string]any) { m["receipt_v"] = 2 },
		"a code it does not name": func(m map[string]any) {
			m["coverage"].(map[string]any)["gaps"].([]any)[0].(map[string]any)["code"] = "new-code"
		},
		"level complete on a gap": func(m map[string]any) {
			m["coverage"].(map[string]any)["gaps"].([]any)[0].(map[string]any)["level"] = "complete"
		},
	} {
		m := good()
		mutate(m)
		if err := jsonschema.Check(receiptSchema, m); err == nil {
			t.Errorf("the schema accepts a receipt with %s", name)
		}
	}
}

// gap2 is a gap line of what=record.
func gap2(why string) line {
	return line{kind: record.KindGap, at: time.Second, payload: record.GapPayload{What: record.GapRecord, Why: why}}
}
