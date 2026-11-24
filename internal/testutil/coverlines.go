// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"regexp"
	"testing"
)

// coverDiagnostic matches the whole lines a -cover build's runtime writes to stderr as the process exits: the
// warning when the process has no GOCOVERDIR (a child the launcher starts with an empty environment), and the
// two errors when the directory it has cannot be written (a target the supervisor refuses writes to, or a
// directory its uid cannot create files in). They are the instrumentation's, not the program's.
var coverDiagnostic = regexp.MustCompile(`(?m)^(warning: GOCOVERDIR not set, no coverage data emitted|error: coverage (meta-data|counter data) emit failed: .*)\n?`)

// WithoutCoverageDiagnostics is out without the coverage runtime's own stderr lines when this test binary was
// built with -cover, and out as it is otherwise: an uninstrumented child that printed one would be a finding, so
// the filter is off there. It removes those lines only, whole, and nothing else the program wrote, so a test that
// compares the program's exact output compares the program's output.
func WithoutCoverageDiagnostics(out []byte) []byte {
	if testing.CoverMode() == "" {
		return out
	}
	return stripCoverageDiagnostics(out)
}

// stripCoverageDiagnostics removes the lines whatever the build, for the test of the filter itself.
func stripCoverageDiagnostics(out []byte) []byte {
	if !bytes.Contains(out, []byte("coverage")) && !bytes.Contains(out, []byte("GOCOVERDIR")) {
		return out
	}
	return coverDiagnostic.ReplaceAll(out, nil)
}
