// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var recordDir = filepath.Join("..", "..", "..", "spec", "record", "v1")

func TestBaselineRecordSchema(t *testing.T) {
	for _, mode := range []string{"applied", "not-applied", "zero"} {
		t.Run(mode, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(recordDir, "fixtures", "baseline", mode+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(bytes.Split(raw, []byte{'\n'})[0], &doc); err != nil {
				t.Fatal(err)
			}
			schema := filepath.Join(recordDir, "baseline.schema.json")
			Validate(t, schema, doc)
			delete(doc, "baseline")
			if err := Check(schema, doc); err == nil {
				t.Fatal("schema accepts missing baseline")
			}
		})
	}
}

func TestRecordUnsupportedMinorsAgainstSchemas(t *testing.T) {
	for _, minor := range []int{36, 37, 38, record.Minor + 1} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			if err := Check(filepath.Join(recordDir, "baseline.schema.json"), map[string]any{"record_minor": minor}); err == nil || !strings.Contains(err.Error(), "/record_minor/anyOf") {
				t.Fatalf("revision %d: need record_minor supported-set refusal, got %v", minor, err)
			}
		})
	}
}
