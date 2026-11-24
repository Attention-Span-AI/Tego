// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestFenceRereadReportsDecoderRefusal(t *testing.T) {
	data, err := os.ReadFile("../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	for _, tc := range []struct {
		name, old, next, reason string
		index                   int
	}{
		{"baseline-null", `"plane":""`, `"plane":null`, "plane", 0},
		{"baseline-minor", `"record_minor":39`, `"record_minor":36`, "record_minor", 0},
		{"other-kind", `"v":1`, `"v":0`, "version", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, id := adjustableRun(t)
			off := ledgerEnd(dir)
			changed := bytes.Replace(lines[tc.index], []byte(tc.old), []byte(tc.next), 1)
			if bytes.Equal(lines[tc.index], changed) {
				t.Fatal("mutation did not fire")
			}
			f, err := os.OpenFile(filepath.Join(dir, ledger.EventsFile), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := f.Write(append(changed, '\n'))
			closeErr := f.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("append: %v %v", writeErr, closeErr)
			}
			appendFenceLine(t, dir, id, 2, record.GapLiveRuleLifted, record.LiveOpLift, "net", "api.stripe.com:443", 7, "")
			var out, errs bytes.Buffer
			code := reportFence(context.Background(), "lift", dir, id, liveblock.KindNet, "api.stripe.com:443", "", 7, off, &out, &errs)
			if code != identity.ExitError || !strings.Contains(errs.String(), tc.reason) || out.Len() != 0 {
				t.Fatalf("refused line was dropped: exit=%d stdout=%q stderr=%q", code, out.String(), errs.String())
			}
		})
	}
}
