// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdReceipt) }

// cmdReceipt is `tego receipt [run] [--json] [--verify]`: the run's V1 receipt (time taken, files changed, connections,
// programs run, sensitive files read, each refused action with its rule, refusals over time, stall minutes, tests
// result, times it asked, tokens and their estimated cost, and what the ledger could not cover), built from the
// ledger by internal/check/receipt, the builder tego run's end summary and the dashboard's Receipt tab use too. No run means the newest run under the ledger root. It is a
// report: exit 0 when printed, 1 only with --verify when the chain does not verify, 2 for usage, 125 for an
// unreadable ledger or no run record.
func cmdReceipt() Command {
	var asJSON, last, verify bool
	return Command{
		Name:    "receipt",
		Summary: "what a run did: time, files, connections, secrets read, refusals, asks, tokens",
		Usage:   "[<run>] [--json] [--verify]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object")
			fs.BoolVar(&verify, "verify", false, "also check the run's hash chain and its chain.log anchor, as events --verify (exit 1 when it fails)")
			fs.BoolVar(&last, "last", false, "the newest run under the ledger root (the same as giving no run)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() > 1 || (fs.NArg() == 1 && last) {
				message(stderr, "", 0, 0, "tego receipt: at most one run id or run directory; none (or --last) means the newest run", codeUsage)
				return identity.ExitUsage
			}
			if fs.NArg() == 1 && fs.Arg(0) == "" {
				// An unset "$RUN" named no run, and the receipt of whichever run was newest answered for it.
				message(stderr, "", 0, 0, "tego receipt: the run is an empty string; none (or --last) means the newest run", codeUsage)
				return identity.ExitUsage
			}
			return runReceipt(ctx, fs.Arg(0), asJSON, verify, stdout, stderr)
		},
	}
}

func runReceipt(ctx context.Context, ref string, asJSON, verify bool, stdout, stderr io.Writer) int {
	mc := &machineOnce{stderr: stderr}
	var dir string
	var err error
	if ref == "" {
		dir, err = newestRunDir(mc)
		if err != nil {
			message(stderr, "", 0, 0, "tego receipt: "+err.Error(), codeNotFound)
			return identity.ExitError
		}
	} else if dir, err = resolveRunDir(ref, true, mc); err != nil {
		return runRefFailed(stderr, "receipt", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: no run record at %s", dir), codeIO)
			return identity.ExitError
		}
		message(stderr, "", 0, 0, "tego receipt: "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	defer func() { warnNewer(stderr, "receipt", dir, r.SkippedNewer()) }()
	// The ledger does not record the run's HOME; "~" in the text is the reader's own home, as a shell reads it.
	rc, err := receipt.Compute(ctx, r, receipt.Options{NowMonoNS: liveMonoNS(r), Prices: measurePrices("receipt", mc, stderr),
		Home: os.Getenv("HOME")})
	if err != nil {
		if errors.Is(err, receipt.ErrNoRun) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: %s: %v", dir, err), codeIO)
			return identity.ExitError
		}
		return readFailed(stderr, "receipt", err)
	}
	write := rc.Text
	if asJSON {
		write = rc.JSON
	}
	if err := write(stdout); err != nil {
		message(stderr, "", 0, 0, "tego receipt: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if verify {
		return verifyReceiptChain(ctx, dir, asJSON, mc, stdout, stderr)
	}
	return identity.ExitOK
}

// verifyReceiptChain is --verify: the run's hash chain and its chain.log anchor, checked as `events --verify`
// checks them (ledger.VerifyRunDir). The receipt is recomputed from the ledger every time, so a chain that
// verifies vouches for the receipt printed above it. Exit 0 when it verifies (a live run has no anchor yet and
// says so), 1 when it does not, 125 when it could not be checked.
func verifyReceiptChain(ctx context.Context, dir string, asJSON bool, mc *machineOnce, stdout, stderr io.Writer) int {
	m, err := mc.load()
	if err != nil {
		message(stderr, "", 0, 0, "tego receipt: machine config: "+err.Error(), identity.CodeConfigUntrusted)
		return identity.ExitError
	}
	anchor, err := anchorPath(m)
	if err != nil {
		message(stderr, "", 0, 0, "tego receipt: "+err.Error(), codeIO)
		return identity.ExitError
	}
	rep, verr := ledger.VerifyRunDir(ctx, dir, ledger.NewFileChainAnchor(anchor))
	if verr != nil && !errors.Is(verr, ledger.ErrUnverified) {
		message(stderr, "", 0, 0, "tego receipt: verify "+dir+": "+verr.Error(), codeIO)
		return identity.ExitError
	}
	if verr != nil {
		message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: %s does not verify: %v", rep.Run, verr), codeUnverified)
		return identity.ExitFinding
	}
	out := stdout
	if asJSON {
		out = stderr // stdout holds exactly one JSON object
	}
	fmt.Fprintln(out, "\nChain: "+verifiedLine(rep, anchor))
	return identity.ExitOK
}

// newestRunDir is the newest run directory under the machine's ledger root (by the mint time in its id,
// ledger.CompareRunIDs) that holds an events file.
func newestRunDir(mc *machineOnce) (string, error) {
	m, err := mc.load()
	if err != nil {
		return "", fmt.Errorf("machine config: %w", err)
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		return "", err
	}
	ids, err := runIDsNewestFirst(root)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		dir := filepath.Join(root, id)
		if st, err := os.Lstat(filepath.Join(dir, ledger.EventsFile)); err == nil && st.Size() > 0 {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no run under %s yet", root)
}
