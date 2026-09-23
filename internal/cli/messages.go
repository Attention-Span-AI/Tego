// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Diagnostic codes this package emits in the bracketed suffix (RUN-IDENTITY.md "Messages").
// compile's codes are agent.Diagnostic's; these are the CLI's own.
const (
	codeUsage         = "usage"
	codeBug           = "bug"
	codeExists        = "exists"
	codeIO            = "io"
	codeNotFound      = "not-found"
	codeNewerRecord   = "newer-record"
	codeLedgerAnomaly = "ledger-anomaly"
	codeRunLost       = "run-lost"
)

// warnAnomalies is limits-check-doctor-cli.md §6 case 5's report: each ledger anomaly a view met (two run_end
// lines, the first kept) is one warning line and one tego.log entry, never resolved silently.
func warnAnomalies(w io.Writer, cmd, dir string, anomalies []string) {
	for _, a := range anomalies {
		line := fmt.Sprintf("warning: tego %s: %s: %s", cmd, filepath.Join(dir, ledger.EventsFile), a)
		message(w, "", 0, 0, line, codeLedgerAnomaly)
		logOwn(line + " [" + codeLedgerAnomaly + "]")
	}
}

// warnNewer is limits-check-doctor-cli.md §6 case 20's one warning: a view skipped n lines of a record version
// newer than this binary reads (ledger.Reader.SkipNewerVersions), and says how many, never silently.
func warnNewer(w io.Writer, cmd, dir string, n int) {
	if n <= 0 {
		return
	}
	message(w, "", 0, 0, fmt.Sprintf("warning: tego %s: %s: skipped %d line(s) of a record version newer than %d, "+
		"which this tego does not read; a newer tego reads them", cmd, filepath.Join(dir, ledger.EventsFile), n,
		record.Version), codeNewerRecord)
}

// message writes one diagnostic line in the shared format; embedded newlines are flattened so
// every message stays one line (R26).
func message(w io.Writer, file string, line, col int, what, code string) {
	what = record.Printable(strings.ReplaceAll(strings.TrimSpace(what), "\n", " "))
	file = record.Printable(file)
	fmt.Fprintln(w, identity.FormatMessage(file, line, col, what, code))
}

// internalError renders a recovered panic (§4 cli.Main): one line on stderr, the stack in the
// own log, exit 125.
func internalError(stderr io.Writer, r any, stack []byte) int {
	message(stderr, "", 0, 0, fmt.Sprintf("tego: internal error: %v", r), codeBug)
	logOwn(fmt.Sprintf("internal error: %v\n%s", r, stack))
	return identity.ExitError // R25: Tego's own bug
}

// logOwn appends one entry to tego.log at error level, through this process's one appender (ownlog.go:
// the invoking user's passwd home, 0600, rotated 10 MB x 5, docs/OPERATIONS.md). Every entry a command
// passes here is a failure it reports on stderr in a line or by its exit code only. Best effort: the
// log must never turn an error report into a second failure, so nothing is returned. A multi-line
// entry, a panic's stack, stays one quoted line.
func logOwn(entry string) {
	newOwnLogger(processOwnLog(), nil).Error(entry)
}
