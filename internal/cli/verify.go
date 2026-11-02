// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// codeUnverified tags a ledger that does not verify.
const codeUnverified = "ledger-corrupt"

// verifyJSON is `events --verify --json`: one object whatever the outcome, so a pipeline reads the
// same shape from a run that verifies and from one that does not.
type verifyJSON struct {
	Run       string `json:"run"`
	Verified  bool   `json:"verified"`
	Lines     uint64 `json:"lines"`
	Head      string `json:"head"`
	Started   bool   `json:"started"`
	Ended     bool   `json:"ended"`
	Anchored  bool   `json:"anchored"`
	Anchor    string `json:"anchor"`
	TornBytes int    `json:"torn_bytes"`
	Error     string `json:"error,omitempty"`
}

// runVerify is `tego events <run> --verify` (R29, record-ledger.md §11's verification command): it
// walks the run's hash chain and checks its head against the invoking user's chain.log. Exit 0 when
// the ledger verifies, 1 when it does not — a line that does not hash to its id, a broken seq or prev
// link, a line of another run (a ledger copied in from elsewhere), an anchored head the ledger does
// not end with (a truncated run), an ended run with no anchor line (E29), or an anchored run whose
// ledger is gone — and 125 when it could not be read at all (R25). The run is the one <run> names
// (resolveRunDir, ledger.RunDirPath), even when that name is a link to another run's directory, never
// one the ledger claims to be while the path names a run id; only a path that reaches none (a copy
// under another name) is verified as the id on the ledger's first line (record-ledger.md §4). A missing
// anchor is never rebuilt from the ledger: an anchor written from the file it is meant to vouch for
// attests nothing.
func runVerify(ctx context.Context, ref string, asJSON bool, stdout, stderr io.Writer) int {
	mc := &machineOnce{stderr: stderr}
	dir, err := resolveRunDir("events", ref, false, mc)
	if err != nil {
		return runRefFailed(stderr, "events", err)
	}
	m, err := mc.load()
	if err != nil {
		message(stderr, "", 0, 0, "tego events: machine config: "+err.Error(), identity.CodeConfigUntrusted)
		return identity.ExitError
	}
	anchor, err := anchorPath(m)
	if err != nil {
		// Without the anchor an ended run cannot be verified, only its chain walked; saying
		// "verified" there would claim the half that was not checked.
		message(stderr, "", 0, 0, "tego events: "+err.Error(), codeIO)
		return identity.ExitError
	}
	rep, verr := ledger.VerifyRunDir(ctx, dir, ledger.NewFileChainAnchor(anchor))
	// One reading of the result, the one the dashboard's chain check makes too (ledger.VerdictOf).
	verdict := ledger.VerdictOf(rep, verr)
	if verdict == ledger.NoVerdict {
		switch {
		case errors.Is(verr, fs.ErrNotExist):
			// Neither a ledger nor an anchor line: nothing says this run was ever recorded here. A run id
			// whose directory does not exist either is the caller's typo, the usage error every other command
			// gives it (R25); a directory the caller named that holds no record stays 125.
			if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
				message(stderr, "", 0, 0, fmt.Sprintf("tego events: %s: %v (no directory at %s and no anchor line); %s",
					filepath.Base(dir), errRunNotFound, dir, listRunsHint), codeUsage)
				return identity.ExitUsage
			}
			message(stderr, "", 0, 0, fmt.Sprintf("tego events: no run record at %s", dir), codeIO)
		case verr != nil:
			// A read failure says nothing about the ledger's integrity (E26): report it as ours.
			message(stderr, "", 0, 0, "tego events: verify "+dir+": "+verr.Error(), codeIO)
		default:
			// A ledger with no run_start that no anchor line names (an empty events.jsonl, a torn line alone)
			// verified as "0 lines": a check of nothing, where events, drift and measure answer no run record
			// (R25). An anchored run whose lines are gone is still the finding Verify returns.
			message(stderr, "", 0, 0, fmt.Sprintf("tego events: no run record at %s: %s holds no run_start", dir, ledger.EventsFile), codeIO)
		}
		return identity.ExitError
	}
	if asJSON {
		out := verifyJSON{
			Run: rep.Run, Verified: verdict == ledger.Verified, Lines: rep.Lines, Head: rep.Head, Started: rep.Started,
			Ended: rep.Ended, Anchored: rep.Anchored, Anchor: anchor, TornBytes: rep.TornBytes,
		}
		if verr != nil {
			out.Error = verr.Error()
		}
		if err := writeJSON(stdout, out); err != nil {
			message(stderr, "", 0, 0, "tego events: "+err.Error(), codeIO)
			return identity.ExitError
		}
	} else if verdict == ledger.Verified {
		fmt.Fprintln(stdout, verifiedLine(rep, anchor))
	}
	if verdict == ledger.Unverified {
		message(stderr, "", 0, 0, fmt.Sprintf("tego events: %s does not verify: %v", rep.Run, verr), codeUnverified)
		return identity.ExitFinding // R25: the ledger is not what its writer wrote
	}
	return identity.ExitOK
}

// verifiedLine is the one line a ledger that verifies gets: how much was checked, how it ends, and
// whether the head was checked against the anchor — a live run has no anchor line yet, and saying so
// keeps "verified" from claiming the half that could not be checked.
func verifiedLine(rep ledger.VerifyReport, anchor string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: verified %d lines", record.Printable(rep.Run), rep.Lines)
	switch {
	case rep.Ended:
		b.WriteString(", run_start to run_end")
	case rep.Started:
		b.WriteString(", not ended")
	}
	if rep.Head != "" {
		fmt.Fprintf(&b, ", head %s", short(rep.Head))
	}
	if rep.Anchored {
		fmt.Fprintf(&b, ", anchored in %s", record.Printable(anchor))
	} else {
		b.WriteString(", no anchor yet (the run has not ended)")
	}
	if rep.TornBytes > 0 {
		fmt.Fprintf(&b, "; a torn last line of %d bytes ignored", rep.TornBytes)
	}
	return b.String()
}
