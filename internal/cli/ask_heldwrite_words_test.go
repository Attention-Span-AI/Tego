// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
)

// A file open an fs.ask entry holds is a write, and the listing words it so (record.AskOpWord, the function the
// dashboard's linewords.AskOp is): the line said "open", which names no change the person is asked to allow. The
// machine form keeps the op as the broker has it.
func TestAskListingWordsAHeldWriteAsAWrite(t *testing.T) {
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	dir, broker := newCLIBroker(t, id, func(ask.Event) error { return nil })
	go func() {
		_, _ = broker.Request(t.Context(), ask.Request{Op: "open", Target: "/w/out/a.txt", Rule: "fs.ask[./out/]", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()})
	}()
	pendingAskID(t, id, dir)
	var out, errs bytes.Buffer
	if code := askAt(t.Context(), "ask", id, dir, "", false, false, false, "", &out, &errs); code != 0 || !strings.Contains(out.String(), " open write /w/out/a.txt") {
		t.Fatalf("the listing %q (exit %d %s) does not say write", out.String(), code, &errs)
	}
	if strings.Contains(out.String(), " open open ") {
		t.Fatalf("a held write is still worded open: %q", out.String())
	}
	out.Reset()
	if code := askAt(t.Context(), "ask", id, dir, "", false, false, true, "", &out, &errs); code != 0 {
		t.Fatal(errs.String())
	}
	var j struct {
		Pending []struct{ Op string } `json:"pending"`
	}
	if err := json.Unmarshal(out.Bytes(), &j); err != nil || len(j.Pending) != 1 || j.Pending[0].Op != "open" {
		t.Fatalf("the machine form changed: %s %v", out.String(), err)
	}
}
