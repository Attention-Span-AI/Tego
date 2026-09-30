// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
)

// noControl fails when out holds a byte below 0x20 (or DEL) other than one trailing newline.
func noControl(t *testing.T, what string, out []byte) {
	t.Helper()
	for _, b := range bytes.TrimSuffix(out, []byte("\n")) {
		if b < 0x20 || b == 0x7f {
			t.Errorf("%s wrote control byte %#x: %q", what, b, out)
			return
		}
	}
}

func TestDiagnosticsAndViewsEscapeLedgerText(t *testing.T) {
	const evil = "a\x1b[2Jb\rc"
	var b bytes.Buffer
	message(&b, evil, 1, 2, "x"+evil+"y\nz", "code")
	noControl(t, "message", b.Bytes())

	b.Reset()
	g := []gaps.Count{{What: "w", Why: "y", Events: 1}}
	snaps := []*status.Snapshot{{Run: evil, Agent: evil, Gaps: g}, {Run: evil + "2", Agent: evil, Gaps: g}}
	if err := writeStatusGaps(&b, snaps, true); err != nil {
		t.Fatal(err)
	}
	for _, l := range bytes.Split(bytes.TrimSuffix(b.Bytes(), []byte("\n")), []byte("\n")) {
		noControl(t, "status gaps", l)
	}

	noControl(t, "verifiedLine", []byte(verifiedLine(ledger.VerifyReport{Run: evil, Lines: 3}, "")))
}
