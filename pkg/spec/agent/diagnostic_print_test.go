// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"strings"
	"testing"
)

// TestWriteDiagnosticsEscapesControlBytes: a contract path or file name is text the operator did not
// choose; it must not reach the terminal as a control byte.
func TestWriteDiagnosticsEscapesControlBytes(t *testing.T) {
	ds := []Diagnostic{{
		Severity: SeverityWarning, File: "a\x1b[2Jb.yaml", Line: 1, Code: CodeSchema,
		Message: "fs.write \"x\": /tmp/\x1b[31mW does not exist", Fix: "create /tmp/\x1b[31mW\r",
	}}
	var b bytes.Buffer
	if err := WriteDiagnostics(&b, ds); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\x1b\r") {
		t.Fatalf("control byte reached the writer: %q", b.String())
	}
	if !strings.Contains(b.String(), `\x1b[31mW`) {
		t.Fatalf("escaped text missing: %q", b.String())
	}
}
