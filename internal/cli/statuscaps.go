// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// writeStatusCapabilities prints the capability line under the table (limits-check-doctor-cli.md R-cap) for a
// single run: what the run could do, and by name what it could not. A listing leaves it out, because it is
// one long line per run and a table of runs is read for their states; `status <run>` and --json carry it.
func writeStatusCapabilities(w io.Writer, snaps []*status.Snapshot, list bool) error {
	if list && len(snaps) != 1 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "capabilities: %s\n", status.CapabilityLine(snaps[0].Tier, snaps[0].Capabilities)); err != nil {
		return err
	}
	// The command given after `--` is granted for the whole run beyond what the contract hash covers, so a
	// run that had one says so under its capabilities (agent-contract.md R8).
	if g := snaps[0].RunCommandGrant; g != "" {
		if _, err := fmt.Fprintf(w, "run command grant: %s (given on the command line, admitted for every exec of it in the run)\n", record.Printable(g)); err != nil {
			return err
		}
	}
	// A cell decided on copied syscall facts and continued (a gate cell, or the built-in deny_write set where no
	// plane decided the run) is never counted as enforced, so a run that had one says which beside what it could
	// do (ADR 0041 D1, D7).
	if cells := snaps[0].BestEffort; len(cells) != 0 {
		_, err := fmt.Fprintf(w, "best effort: %s (decisions on copied syscall facts, not enforced)\n", record.Printable(strings.Join(cells, ", ")))
		return err
	}
	return nil
}

// writeStatusResources prints the resources line under the capability line (limits-check-doctor-cli.md
// R-res) for a single run, on the same terms: what the run's cgroup said the run used, read from run_end,
// each key the record lacks "unknown". A listing leaves it out for the reason it leaves the capabilities out.
func writeStatusResources(w io.Writer, snaps []*status.Snapshot, list bool) error {
	if list && len(snaps) != 1 {
		return nil
	}
	_, err := fmt.Fprintf(w, "resources: %s\n", status.ResourcesLine(snaps[0]))
	return err
}

// writeStatusLedger prints one run's ledger line: the size of its events.jsonl and blobs and the record.max_run_bytes
// ceiling it runs under, so a run that never stops shows how far it is from the limit that ends it. A listing does
// not print it, as it prints no resources line.
func writeStatusLedger(w io.Writer, snaps []*status.Snapshot, list bool) error {
	if list && len(snaps) != 1 {
		return nil
	}
	_, err := fmt.Fprintf(w, "ledger: %s\n", status.LedgerLine(snaps[0]))
	return err
}
