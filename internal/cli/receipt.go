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
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/check/cireceipt"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdReceipt) }

// receiptStamp names the tego making or checking a receipt (binding.receipt_by, checked_by), as `tego version` names
// it. It is a variable so this package's tests can name a released build: a test binary has no commit.
var receiptStamp = func() receipt.MadeBy {
	s := buildinfo.Resolve(debug.ReadBuildInfo)
	return receipt.MadeBy{TegoVersion: s.Version, Commit: s.Commit}
}

// cmdReceipt is `tego receipt [run] [--json] [--verify]`: the run's V1 receipt (time taken, files written, connections,
// programs run, sensitive files read, each refused action with its rule, refusals over time, stall minutes, tests
// result, times it asked, tokens and their estimated cost, and what the ledger could not cover), built from the
// ledger by internal/check/receipt, the builder tego run's end summary and the dashboard's Receipt tab use too. No run means the newest run under the ledger root. It is a
// report: exit 0 when printed, 1 only with --verify when the chain does not verify or the receipt.json kept in the run
// folder differs from the record (verifyKeptReceipt), 2 for usage, 125 for an unreadable ledger or no run record, or a
// kept receipt that could not be checked. Under --json the receipt is bound to the record it read (receipt.Binding).
//
// `tego receipt --check <receipt.json> <run folder>` compares a bound receipt with a record from the two files alone
// (receipt.Check), never reading chain.log: exit 0 when they match, 1 when they do not, 2 for usage, 125 when it could
// not check. It is a flag, not a subcommand: `tego receipt check` already names the run whose id ends in "check".
func cmdReceipt() Command {
	var asJSON, last, verify, requireEnded bool
	var check, statusFile, verifyCI, expect, checksums, trustedRoot, cosign, cosignHash, bundle string
	return Command{
		Name:    "receipt",
		Summary: "what a run did: time, files, connections, secrets read, refusals, asks, tokens",
		Usage:   "[<run> | --last] [--json] [--verify] | --check <receipt.json> <run folder> [--require-ended] [--status-file <path>] [--json] | --verify-ci <evidence> --expect <file> --checksums <file> [--json]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object")
			fs.BoolVar(&verify, "verify", false, "also check the run's hash chain and its chain.log anchor, as events --verify (exit 1 when it fails)")
			fs.BoolVar(&last, "last", false, "the newest run under the ledger root (the same as giving no run)")
			fs.StringVar(&check, "check", "", "compare this bound receipt (from receipt --json) with the run folder given, from the two files alone (exit 1 when they differ, 125 when it cannot check)")
			fs.BoolVar(&requireEnded, "require-ended", false, "require run_end, confirmed teardown and complete recorded coverage with --check")
			fs.StringVar(&statusFile, "status-file", "", "launcher status file for --check --require-ended (default run-status.json beside the record or run folder)")
			fs.StringVar(&verifyCI, "verify-ci", "", "check retained CI evidence and signatures against independent expectations")
			fs.StringVar(&expect, "expect", "", "independent tego.ci-expect/1 JSON")
			fs.StringVar(&checksums, "checksums", "", "independently authenticated release checksums, outside the evidence directory")
			fs.StringVar(&trustedRoot, "trusted-root", "", "independently trusted Sigstore root JSON, outside evidence")
			fs.StringVar(&cosign, "cosign", "", "absolute path to independently pinned cosign v3.1.3")
			fs.StringVar(&cosignHash, "cosign-sha256", "", "independent SHA-256 pin for cosign")
			fs.StringVar(&bundle, "bundle", "", "detached receipt Sigstore bundle with --check; requires --expect, --trusted-root, --cosign and --cosign-sha256")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			checking := false
			ciChecking := false
			fs.Visit(func(f *flag.Flag) {
				checking = checking || f.Name == "check"
				ciChecking = ciChecking || f.Name == "verify-ci"
			})
			if ciChecking {
				if verifyCI == "" || expect == "" || checksums == "" || fs.NArg() != 0 || checking || verify || last || requireEnded || statusFile != "" || bundle != "" {
					message(stderr, "", 0, 0, "tego receipt: use --verify-ci <evidence> --expect <file> --checksums <file> [--json]", codeUsage)
					return identity.ExitUsage
				}
				return runReceiptCI(ctx, verifyCI, expect, checksums, trustedRoot, cosign, cosignHash, asJSON, stdout, stderr)
			}
			if (bundle == "" && (expect != "" || trustedRoot != "" || cosign != "" || cosignHash != "")) || checksums != "" || (bundle != "" && (!checking || expect == "" || trustedRoot == "" || cosign == "" || cosignHash == "")) || (!checking && (requireEnded || statusFile != "")) || (statusFile != "" && !requireEnded) {
				message(stderr, "", 0, 0, "tego receipt: CI flags require --verify-ci; --require-ended and --status-file require --check", codeUsage)
				return identity.ExitUsage
			}
			if checking {
				if check == "" || fs.NArg() != 1 || fs.Arg(0) == "" || verify || last {
					message(stderr, "", 0, 0, "tego receipt: --check takes a receipt file and one run folder (or its "+
						"events.jsonl), and no --verify or --last: tego session show --check receipt.json <run folder>", codeUsage)
					return identity.ExitUsage
				}
				if bundle != "" {
					return runReceiptBundleCheck(ctx, check, fs.Arg(0), bundle, expect, trustedRoot, cosign, cosignHash, asJSON, requireEnded, statusFile, stdout, stderr)
				}
				return runReceiptCheck(ctx, check, fs.Arg(0), asJSON, requireEnded, statusFile, stdout, stderr)
			}
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
			message(stderr, "", 0, 0, "tego receipt: "+err.Error()+"; run tego rules create --preset no-secrets,repo-only-writes --write ./out, then tego run agent.yaml", codeNotFound)
			return identity.ExitError
		}
	} else if dir, err = resolveRunDir("receipt", ref, true, mc); err != nil {
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
	// The reader's home is not the run's: the receipt folds "~" only under the home the run recorded, and says so when none.
	opt := receipt.Options{NowMonoNS: liveMonoNS(r), Prices: measurePrices("receipt", mc, stderr), SayNoHome: true}
	if asJSON {
		// Only the JSON receipt is bound: it is the one a script keeps and checks later (--check). The text receipt
		// stays byte for byte what it was.
		by := receiptStamp()
		opt.Bind = &by
	}
	rc, err := receipt.Compute(ctx, r, opt)
	if err != nil {
		if errors.Is(err, receipt.ErrNoRun) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: %s: %v", dir, err), codeIO)
			return identity.ExitError
		}
		return readFailed(stderr, "receipt", err)
	}
	write := func(w io.Writer) error {
		// At a terminal the long sentences are broken at their words; to a pipe or a file the text is what it was.
		var b strings.Builder
		if err := rc.Text(&b); err != nil {
			return err
		}
		_, err := io.WriteString(w, fitTerminal(w, b.String()))
		return err
	}
	if asJSON {
		write = rc.JSON
		if b := rc.Binding; b != nil && b.Error != "" {
			message(stderr, "", 0, 0, fmt.Sprintf("warning: tego receipt: %s: the receipt is not bound to its record: %s",
				filepath.Join(dir, ledger.EventsFile), b.Error), codeUnverified)
		}
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
	return verifyKeptReceipt(ctx, dir, out, stderr)
}

// verifyKeptReceipt is the second half of --verify (ADR 0159): when the run directory holds the receipt.json that
// `tego run` placed at the run's end, compare it with the record as `tego receipt --check` does (receipt.Check; the
// price and clock a machine alone gives are not compared). The record's own chain has just verified, so every finding
// below is about the kept copy only, and the messages say so. A run with no kept receipt (a run from before it, one
// tego run was interrupted or did not place one, a watch of another machine) says nothing: the receipt printed above
// was rebuilt from the record. Exit 0 when it matches (a receipt whose coverage the record says is incomplete still
// matches: the receipt says so itself) or when only another build's figures were not compared (keptByAnotherBuild),
// 1 when it differs, naming the first check that failed, or names a maker the record does not, 125 when it could not
// be checked (an unreadable file, or a receipt or binding version this tego does not read).
func verifyKeptReceipt(ctx context.Context, dir string, out, stderr io.Writer) int {
	path := filepath.Join(dir, ledger.ReceiptFile)
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return identity.ExitOK
	}
	if err == nil && !st.Mode().IsRegular() {
		// tego run places a regular file and nothing else: a link, a pipe or a directory at the name was put there. It is
		// not opened (a pipe would block, a link would be followed).
		message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the record verified; only the kept receipt %s differs from it: "+
			"it is a %s, not the file tego run places", path, fileKind(st.Mode())), codeKeptReceipt)
		return identity.ExitFinding
	}
	res := receipt.Check(ctx, receipt.CheckInput{Receipt: path, Record: dir, By: receiptStamp()})
	switch res.Result {
	case receipt.CheckMatch, receipt.CheckMatchUnended, receipt.CheckIncomplete:
		fmt.Fprintf(out, "Kept receipt: %s matches the record.\n", path)
		return identity.ExitOK
	case receipt.CheckMismatch:
		s := firstStep(res.Checks, receipt.StepFail)
		message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the record verified; only the kept receipt %s differs from it: %s: %s",
			path, s.Name, record.Printable(s.Why)), codeKeptReceipt)
		return identity.ExitFinding
	}
	s := firstStep(res.Checks, receipt.StepNotChecked)
	if note, ok := otherBuildNote(res.Checks); ok {
		// Only the figures were left uncompared, and only because the checking tego is not the build that made the
		// copy. A copy kept by tego run was made by the tego that ran the run, which run_start names, so a copy that
		// names another maker, or one no tego can ever have kept (no exact build), was not kept by tego run: its
		// figures cannot be taken as the run's, however its seal reads.
		by, ran := res.ReceiptBy, res.RecordBy
		switch {
		case by == nil || ran == nil:
		case res.RecordMinor < record.MinorEveryLaunch:
			// A record of an older revision was made by a build that never kept a copy, however exactly that build is
			// named (an upgrade is no reason to take a file an agent of such a run could have written): the copy is not
			// tego's, and only the record's own chain is left to trust.
			message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the record verified; only the kept receipt %s differs from it: "+
				"the run was made by tego %s at record revision %d, a build that keeps no receipt",
				path, record.Printable(ran.TegoVersion), res.RecordMinor), codeKeptReceipt)
			return identity.ExitFinding
		case *by != *ran:
			message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the record verified; only the kept receipt %s differs from it: "+
				"it names tego %s (commit %s) as its maker, and this run was made by tego %s (commit %s)",
				path, record.Printable(by.TegoVersion), record.Printable(by.Commit),
				record.Printable(ran.TegoVersion), record.Printable(ran.Commit)), codeKeptReceipt)
			return identity.ExitFinding
		case !receipt.Exact(*by):
			message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the record verified; only the kept receipt %s differs from it: "+
				"it names tego %s (commit %s) as its maker, a build that keeps no receipt",
				path, record.Printable(by.TegoVersion), record.Printable(by.Commit)), codeKeptReceipt)
			return identity.ExitFinding
		default:
			fmt.Fprintf(out, "Kept receipt: %s: the record's chain, head and bytes are the ones it names; its figures were not compared: %s.\n",
				path, note)
			return identity.ExitOK
		}
	}
	why := record.Printable(s.Why)
	if s.Name == "receipt" && res.VersionNotRead() {
		// A later release's copy, which this tego cannot read: not a finding, and not a pass either (any file can claim a
		// later version), so it is the exit that says "could not check", with the way to check it.
		message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the kept receipt %s was made in a form this tego does not read (%s); "+
			"the record itself verified, so only the kept copy is unchecked: check it with the tego that ran the run, or a later one",
			path, why), codeIO)
		return identity.ExitError
	}
	if s.Name == "receipt" {
		// Whatever stands at the name and is no receipt this tego reads is not what tego run places: only the copy differs.
		message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the record verified; only the kept receipt %s differs from it: it is no receipt: %s",
			path, why), codeKeptReceipt)
		return identity.ExitFinding
	}
	message(stderr, "", 0, 0, fmt.Sprintf("tego receipt: the kept receipt %s could not be checked: %s: %s", path, s.Name, why), codeIO)
	return identity.ExitError
}

// fileKind names what mode says a file is, for a message.
func fileKind(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symbolic link"
	case m.IsDir():
		return "directory"
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device file"
	}
	return "file of another kind"
}

// otherBuildNote is made_by's own words and true when the only check that did not run is the one that needs the tego
// that made the receipt (made_by, and facts, which repeats it) and every other check passed: the kept receipt names this
// record, its chain, head and byte count, which are compared by any tego. The figures are compared only by the exact
// build that made it, so after an upgrade, or by a dirty build or one with no version stamp, they are not, which is not a
// failure of the run: the chain the line above vouched for is the record's own proof (ADR 0159 §4). The note itself
// proves nothing about who wrote the copy: the caller gives it only to a copy that names the build run_start names.
func otherBuildNote(steps []receipt.CheckStep) (string, bool) {
	note := ""
	for _, s := range steps {
		switch {
		case s.Name == "made_by" && s.Result == receipt.StepNotChecked:
			note = record.Printable(s.Why)
		case s.Name == "facts" && s.Result == receipt.StepNotChecked:
		case s.Result != receipt.StepPass:
			return "", false
		}
	}
	return note, note != ""
}

// firstStep is the first of steps with result, or the zero step.
func firstStep(steps []receipt.CheckStep, result string) receipt.CheckStep {
	for _, s := range steps {
		if s.Result == result {
			return s
		}
	}
	return receipt.CheckStep{}
}

// runReceiptCheck is `tego receipt --check <receipt.json> <record>`: receipt.Check, then its result as text or one
// JSON object, and its exit (receipt.CheckResult.ExitCode). It resolves no run id and no anchor: the record is the path
// given, and chain.log is never read.
func runReceiptCheck(ctx context.Context, receiptFile, record string, asJSON, requireEnded bool, statusFile string, stdout, stderr io.Writer) int {
	res := receipt.Check(ctx, receipt.CheckInput{Receipt: receiptFile, Record: record, By: receiptStamp(), RequireEnded: requireEnded, StatusFile: statusFile})
	write := res.Text
	if asJSON {
		write = res.JSON
	}
	if err := write(stdout); err != nil {
		message(stderr, "", 0, 0, "tego receipt: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return res.ExitCode()
}

func runReceiptCI(ctx context.Context, dir, expectPath, checksumsPath, rootPath, cosignPath, cosignHash string, asJSON bool, stdout, stderr io.Writer) int {
	paths := []string{expectPath, checksumsPath}
	if rootPath != "" {
		paths = append(paths, rootPath, cosignPath)
	}
	if err := independentCIInputs(dir, paths); err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	expect, err := readCIInput(expectPath, 64<<10)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	ex, err := cireceipt.DecodeExpect(expect)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	checksums, err := readCIInput(checksumsPath, 4<<20)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	hash, err := receipt.ExecutableSHA256()
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	by := receiptStamp()
	scratch, err := os.MkdirTemp("", "tego-ci-check-")
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = os.RemoveAll(scratch) }() // only this invocation's private copies
	var bundles cireceipt.BundleVerifier
	if rootPath != "" || cosignPath != "" || cosignHash != "" {
		root, err := readCIInput(rootPath, 4<<20)
		if err != nil {
			message(stderr, "", 0, 0, err.Error(), codeIO)
			return identity.ExitError
		}
		bundles = cireceipt.CosignVerifier{Path: cosignPath, SHA256: cosignHash, TrustedRoot: root, ScratchDir: scratch}
	}
	res, err := cireceipt.Verify(ctx, cireceipt.Input{Directory: dir, Expectation: expect, Bundles: bundles,
		ScratchDir: scratch,
		Release:    cireceipt.Release{Version: ex.Tego.Version, Commit: ex.Tego.Commit, Checksums: checksums},
		Checker:    cireceipt.Binary{Asset: "tego_" + strings.TrimPrefix(by.TegoVersion, "v") + "_linux_" + runtime.GOARCH, SHA256: hash}, By: by})
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	write := res.Text
	if asJSON {
		write = res.JSON
	}
	if err := write(stdout); err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	return res.ExitCode()
}

func readCIInput(path string, limit int64) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := openDirectoryNoLinks(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("tego receipt: CI input: %w", err)
	}
	defer func() { _ = dir.Close() }() // directory held only while reading this input
	f, err := ledger.OpenRegularAt(dir, filepath.Base(abs), path)
	if err != nil {
		return nil, fmt.Errorf("tego receipt: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only descriptor
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, fmt.Errorf("tego receipt: CI input must have exactly one link")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("tego receipt: %s exceeds %d bytes", path, limit)
	}
	return b, nil
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

// runReceiptBundleCheck freezes the receipt before both consumers read it. A
// signature check never authenticates a subsequently reopened mutable receipt.
func runReceiptBundleCheck(ctx context.Context, receiptPath, recordPath, bundlePath, expectPath, rootPath, cosignPath, cosignHash string, asJSON, requireEnded bool, statusFile string, stdout, stderr io.Writer) int {
	if err := independentCIInputs(filepath.Dir(receiptPath), []string{expectPath, rootPath, cosignPath}); err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	data, err := readCIInput(receiptPath, 64<<20)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	bundle, err := readCIInput(bundlePath, 4<<20)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	expected, err := readCIInput(expectPath, 64<<10)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	e, err := cireceipt.DecodeExpect(expected)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	root, err := readCIInput(rootPath, 4<<20)
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	scratch, err := os.MkdirTemp("", "tego-receipt-bundle-")
	if err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = os.RemoveAll(scratch) }() // this invocation owns all private copies
	frozen := filepath.Join(scratch, "receipt.json")
	if err := os.WriteFile(frozen, data, 0600); err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	res := receipt.Check(ctx, receipt.CheckInput{Receipt: frozen, Record: recordPath, By: receiptStamp(), RequireEnded: requireEnded, StatusFile: statusFile})
	verifier := cireceipt.CosignVerifier{Path: cosignPath, SHA256: cosignHash, TrustedRoot: root, ScratchDir: scratch}
	checked, err := verifier.VerifyReceipt(ctx, data, bundle, e)
	if err != nil {
		res.Checks = append(res.Checks, receipt.CheckStep{Name: "signature", Result: receipt.StepNotChecked, Why: err.Error()})
		if res.ExitCode() == 0 {
			res.Result = receipt.CheckCannot
			res.Complete = false
		}
	} else {
		pass := len(checked.Checks) == len(cireceipt.BundleChecks())/2 && len(checked.IntegratedTimes) == 1
		for _, c := range checked.Checks {
			res.Checks = append(res.Checks, receipt.CheckStep{Name: "signature." + c.Name, Result: c.Result, Why: c.Why})
			pass = pass && c.Result == receipt.StepPass
		}
		start, _ := time.Parse(time.RFC3339, e.Attempt.StartedAt)
		end, _ := time.Parse(time.RFC3339, e.Attempt.CompletedAt)
		for _, when := range checked.IntegratedTimes {
			pass = pass && !when.Before(start.Add(-60*time.Second)) && !when.After(end.Add(60*time.Second))
		}
		if !pass {
			res.Result = receipt.CheckMismatch
			res.Complete = false
			res.Checks = append(res.Checks, receipt.CheckStep{Name: "signature", Result: receipt.StepFail, Why: "signature, exact identity or integration-time comparison failed"})
		}
	}
	write := res.Text
	if asJSON {
		write = res.JSON
	}
	if err := write(stdout); err != nil {
		message(stderr, "", 0, 0, err.Error(), codeIO)
		return identity.ExitError
	}
	return res.ExitCode()
}

func independentCIInputs(evidence string, paths []string) error {
	base, err := filepath.Abs(evidence)
	if err != nil {
		return err
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return err
	}
	for _, path := range paths {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return err
		}
		for _, pair := range [][2]string{{base, abs}, {resolvedBase, resolved}} {
			rel, err := filepath.Rel(pair[0], pair[1])
			if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return errors.New("tego receipt: expectations, roots and verifier must be supplied independently outside evidence")
			}
		}
	}
	return nil
}
