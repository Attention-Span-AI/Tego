// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAPathThatDoesNotDecodeIsCorruptionNotASpecialCase is limits-check-doctor-cli.md E11. The writer
// escapes a kernel path's non-UTF-8 bytes into valid JSON, so a path this view cannot decode is a damaged
// line and takes case 3's road: a hard error naming ErrCorruptLedger, with no report guessed from the lines
// around it. A path that decodes, escapes included, is only a path.
func TestAPathThatDoesNotDecodeIsCorruptionNotASpecialCase(t *testing.T) {
	good := fsLine(1, UnmatchedRule, string(record.VerdictAllow), `/tmp/café-\udcff`)
	bad := fsLine(2, UnmatchedRule, string(record.VerdictAllow), `/tmp/broken-\x`) // \x is no JSON escape
	tail := fsLine(3, UnmatchedRule, string(record.VerdictAllow), "/tmp/after")

	if _, err := Compute(readerOver(t, []byte(good+tail)), nil); err != nil {
		t.Fatalf("a path the writer escaped is not corruption: %v", err)
	}
	_, err := Compute(readerOver(t, []byte(good+bad+tail)), nil)
	if err == nil {
		t.Fatal("a line whose path cannot be decoded produced a report")
	}
	if !errors.Is(err, ledger.ErrCorruptLedger) {
		t.Errorf("error %v does not wrap ledger.ErrCorruptLedger", err)
	}
	if !strings.Contains(err.Error(), "corrupt line 2") {
		t.Errorf("error %q does not name where it stopped", err)
	}
}
