// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestBaselineWriterRawBytes(t *testing.T) {
	data, err := os.ReadFile("../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := testutil.BaselineCases(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if !strings.Contains(tc.Name, "utf8") {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			w, dir, _ := openTestWriter(t)
			for _, method := range []string{"marshal", "marshal-at", "writer"} {
				e := *tc.Event
				switch method {
				case "marshal":
					_, err = e.MarshalLine()
				case "marshal-at":
					_, err = e.MarshalLineAt(record.MinorBaseline)
				case "writer":
					err = w.Append(&e)
				}
				member := tc.Fact[strings.LastIndex(tc.Fact, ".")+1:]
				if err == nil || !strings.Contains(err.Error(), member) {
					t.Errorf("%s accepted raw %s or lost reason: %v", method, tc.Fact, err)
				}
			}
			if b, err := os.ReadFile(filepath.Join(dir, EventsFile)); err != nil || len(b) != 0 {
				t.Fatalf("refused bytes reached ledger: %q, %v", b, err)
			}
		})
	}
}
