// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestWriteConfigDiagnosticsEscapesControlBytes(t *testing.T) {
	var b bytes.Buffer
	writeConfigDiagnostics(&b, []config.Diagnostic{{
		File: "/etc/\x1b[2Jtego.yaml", Line: 3, Message: "bad \x1b[31mvalue\r", Fix: "fix \x07it",
		Code: config.CodeIgnored, Severity: config.SeverityWarning,
	}})
	noControl(t, "config diagnostics", b.Bytes())
}
