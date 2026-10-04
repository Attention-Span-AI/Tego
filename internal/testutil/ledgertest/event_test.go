// SPDX-License-Identifier: Apache-2.0

package ledgertest

import (
	"bytes"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestTypedEventPassesRealCodecWithoutInventingChain(t *testing.T) {
	e := Event(t, record.KindFS, record.FSPayload{Path: "/fixture/out", Op: "write"}, func(e *record.Event) {
		e.Rule = "fs.write[out]"
		e.Verdict = record.VerdictAllow
		e.Authority = record.AuthorityRule
		e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
	})
	if e.ID != "" || e.Prev != "" || e.Seq != 0 {
		t.Fatal("builder fabricated a chain")
	}
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"path":"/fixture/out"`)) {
		t.Fatalf("typed payload absent: %s", line)
	}
	got := Decode[record.FSPayload](t, e)
	if got.Path != "/fixture/out" || got.Op != "write" {
		t.Fatalf("decoded: %+v", got)
	}
}
