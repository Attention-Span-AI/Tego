// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/pricetable"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The end-of-run summary (H08): once the agent has exited (on its own, stopped, or by a limit), tego run says
// in two lines what the run did and where to read the rest, so nobody scrapes a run id out of the agent's own output:
//
//	tego run: <run> ended (<outcome>) · tier <tier> · refused N (top rules) · asked M (a approved, d denied) · wrote K files · chain verified
//	  more: tego receipt <run>
//
// The tier is the one run_start recorded, the tier the run was started at; a run_start with none (a ledger older than
// the field) leaves the clause out. It comes after "ended", so the line still starts "tego run: <run> ended", which
// scripts read the run id from (examples/container/smoke.sh).
// The numbers are receipt.Compute's over the run's ledger, the same builder `tego receipt` and the dashboard's
// Receipt tab use, never a second counter, so the three cannot disagree. "chain verified" is said only after the
// run's hash chain and its anchor were checked here (ledger.VerifyRunDir); when they could not be, the line says
// "chain not checked (<why>)". A run whose record was off (its contract's record: off, a profile's, or --record off)
// says "record off: refusals only" before the chain clause: its ledger keeps no exec or allowed action, so nothing it
// wrote is counted. That is where a contract's own record: off is said: it is what the contract wrote and weakens no
// rule, so the run's start does not say it ("A quiet start"). --no-summary turns the
// summary off. It is printed after the agent's process tree is gone, never while it runs.

// summaryBudget bounds the summary's read of the ledger and its chain check, so a huge ledger never holds tego's exit
// long; past it the summary says what it could not do.
const summaryBudget = 5 * time.Second

// endSummary is one ended run's summary: its receipt and the state of its chain.
type endSummary struct {
	run string
	// how is how the run ended when it did not simply exit (endedHow), said when there is no receipt to say it.
	how string
	rc  *receipt.Receipt
	// chain is the chain clause: "chain verified", "chain not checked (<why>)" or "chain does not verify (<why>)".
	chain string
	// err is why the receipt could not be built; rc is nil then.
	err error
	// recordOff says the run ran under record: off: its ledger kept its refusals and no exec or allowed action, so
	// the summary says so (recordOffClause) and a watch's footer has no "seen:" line, whose counts it did not record.
	recordOff bool
	// root is the ledger root the run's record lies in, which a hint's short run id is unique under (shortRun); "" when
	// it could not be resolved.
	root string
	// machine is the machine config the run was started under, whose registries a hint's proposed agent name is
	// checked against (proposedName); nil for a summary built without one.
	machine *config.Machine
	// kept is the run's bound receipt as `tego receipt --json` prints it, built in the summary's own pass when the
	// caller asked to keep it (summarizeRunKeeping); nil otherwise, or when the receipt could not be built or bound.
	kept []byte
	// keptWhy is why kept is nil when a copy was asked for and the receipt was built: the binding's own words.
	keptWhy string
}

// recordOffClause is what the summary of a run whose record was off says, before its chain clause.
const recordOffClause = "record off: refusals only"

// summarizeRunKeeping builds the summary of the run res names, which ran under the record mode mode (its table's, after
// --record): its receipt over the run's ledger, and its chain verified against anchor. nil when there is no run (the
// run never started). With keep it also binds the receipt in the same one pass and leaves its JSON in the summary
// (endSummary.kept) for keepReceipt to place in the run directory (ADR 0159).
func summarizeRunKeeping(ctx context.Context, m *config.Machine, anchor string, res tegoruntime.Result, mode agent.RecordMode, keep bool) *endSummary {
	if res.RunID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), summaryBudget)
	defer cancel()
	s := &endSummary{run: res.RunID, how: endedHow(res.Reason), recordOff: mode == agent.RecordOff, machine: m}
	root, err := ledgerRootOf(m)
	if err != nil {
		s.err, s.chain = err, "chain not checked (no ledger root)"
		return s
	}
	s.root = root
	dir := filepath.Join(root, res.RunID)
	// No copy from a build no tego can check: receipt.Check compares a receipt's figures only for the exact build that
	// made it, and a dirty build or one with no version stamp is no exact build, so its copy could never be compared by
	// any tego, itself included. The receipt is built from the record whenever it is asked for (ADR 0159 §3).
	keep = keep && receipt.Exact(receiptStamp())
	var unbound string
	s.rc, s.chain, unbound, s.err = receiptAndChain(ctx, dir, anchor, res, m, keep)
	if unbound != "" {
		keep, s.keptWhy = false, unbound
	}
	if keep && s.rc != nil {
		s.kept, s.keptWhy = keptJSON(s.rc)
	}
	return s
}

// receiptAndChain is the receipt of the run in dir and the chain clause, from one read of the ledger: the chain check
// rides the receipt's pass (ledger.Reader.VerifyAlong), as `tego events --verify` would check the same lines, so a long
// record is read once for the summary, not once for the receipt and again for the chain. A record that cannot be opened
// has no receipt, and its chain clause says why from the check's own read. With keep it also binds the receipt, which
// needs the hash of tego's own executable: when that cannot be read the receipt is built unbound, so the summary is
// what it would be without keeping, and the third result says why no copy can be kept ("" otherwise).
func receiptAndChain(ctx context.Context, dir, anchor string, res tegoruntime.Result, m *config.Machine, keep bool) (rc *receipt.Receipt, chain, unbound string, err error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, chainClause(ctx, dir, anchor, res), "", err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	var along *ledger.Verifier
	if res.RecordErr == nil && anchor != "" {
		along = r.VerifyAlong()
	}
	opt := receipt.Options{Home: os.Getenv("HOME")}
	if keep {
		// What `tego receipt --json` binds and prices, so `tego receipt --check` takes the kept copy as it takes that
		// one. Neither changes a word of the summary. The hash is read first: Compute fails as a whole without it, and
		// the one pass over the ledger must not be lost to a binary that cannot be read (mode 0711, say).
		if sum, herr := executableSHA256(); herr != nil {
			unbound = "the receipt could not be bound: " + errText(herr)
		} else {
			by := receiptStamp()
			opt.Bind, opt.BinarySHA256 = &by, sum
			opt.Prices = pricesOf(m)
		}
	}
	rc, err = receipt.Compute(ctx, r, opt)
	chain = chainClauseOf(ctx, anchor, res, func(a ledger.ChainAnchor) (ledger.VerifyReport, error) { return along.Finish(ctx, a) })
	return rc, chain, unbound, err
}

// executableSHA256 is the hash of the running executable a bound receipt carries, a variable so a test can make it fail.
var executableSHA256 = receipt.ExecutableSHA256

// pricesOf is the price table of the machine config m, loaded when a receipt first needs a price, or nil with no
// warning (the receipt then says no table priced it, as it does for any run without one).
func pricesOf(m *config.Machine) measure.Prices {
	return pricetable.NewLazy(func() pricetable.Coster {
		if m == nil {
			return nil
		}
		table, warn := pricetable.FromMachine(m)
		if warn != nil {
			return nil // a nil *PriceTable in an interface is not a nil interface
		}
		return table
	})
}

// keptJSON is the receipt as `tego receipt --json` writes it, or, when its binding failed, nil and the binding's words:
// a receipt bound to nothing is not kept.
func keptJSON(rc *receipt.Receipt) ([]byte, string) {
	if rc.Binding == nil {
		return nil, "the receipt was not bound to its record"
	}
	if rc.Binding.Error != "" {
		return nil, "the receipt is not bound to its record: " + rc.Binding.Error
	}
	var b bytes.Buffer
	if err := rc.JSON(&b); err != nil {
		return nil, err.Error()
	}
	return b.Bytes(), ""
}

// keepReceipt places the run's bound receipt in its run directory as receipt.json, once and never over a file already
// there (ledger.PlaceRunFile), and says in one warning line on stderr why it could not. It changes no exit code: the
// run's own outcome is the exit, and the receipt is rebuilt from the record whenever it is asked for. A run that never
// started, one whose record could not be completed, one tego run was interrupted for and one with no receipt keep none.
func keepReceipt(ctx context.Context, stderr io.Writer, cmd string, res tegoruntime.Result, s *endSummary) {
	if s == nil || res.RunID == "" || res.RecordErr != nil || ctx.Err() != nil || s.root == "" {
		return
	}
	dir := filepath.Join(s.root, res.RunID)
	why := s.keptWhy
	switch {
	case s.err != nil && s.rc == nil:
		why = "the receipt could not be built: " + errText(s.err)
	case s.kept == nil && why == "":
		return
	case s.kept != nil:
		err := ledger.PlaceRunFile(dir, ledger.ReceiptFile, s.kept)
		switch {
		case err == nil:
			return
		case errors.Is(err, os.ErrExist):
			why = ledger.ReceiptFile + " is already in the run directory, and is left as it is"
		default:
			why = err.Error()
		}
	}
	message(stderr, "", 0, 0, "warning: "+cmd+": the receipt was not kept in "+dir+": "+record.Printable(why), codeIO)
}

// chainClause checks the run's chain and its anchor as `tego events --verify` does, and says the result in a few
// words. "verified" needs both: every line chained, and the head anchored in chain.log.
func chainClause(ctx context.Context, dir, anchor string, res tegoruntime.Result) string {
	return chainClauseOf(ctx, anchor, res, func(a ledger.ChainAnchor) (ledger.VerifyReport, error) {
		return ledger.VerifyRunDir(ctx, dir, a)
	})
}

// chainClauseOf is chainClause over check, the chain check against an anchor: Verify's own answer, or the one a pass
// that read the record for another reason found (Verifier.Finish).
func chainClauseOf(ctx context.Context, anchor string, res tegoruntime.Result, check func(ledger.ChainAnchor) (ledger.VerifyReport, error)) string {
	switch {
	case res.RecordErr != nil:
		return "chain not checked (the run's record is incomplete)"
	case anchor == "":
		return "chain not checked (no chain anchor)"
	}
	rep, err := check(ledger.NewFileChainAnchor(anchor))
	switch {
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
		return "chain not checked (it took too long; tego events " + res.RunID + " --verify checks it)"
	case errors.Is(err, ledger.ErrUnverified):
		return "chain does not verify (tego events " + res.RunID + " --verify says why)"
	case err != nil:
		return "chain not checked (" + record.Printable(err.Error()) + ")"
	case !rep.Anchored:
		return "chain not checked (no anchor written yet)"
	}
	return "chain verified"
}

// text is the summary's two lines, prefixed "tego run: ": only tego run prints it, a watch says the same in its footer
// (watchFooter).
func (s *endSummary) text() string {
	return s.textWithMore("tego session show")
}

// textWithMore retains the pre-terminal presentation's command spelling for pipes and -v.
func (s *endSummary) textWithMore(show string) string {
	var b strings.Builder
	run := record.Printable(s.run)
	if s.rc == nil {
		fmt.Fprintf(&b, "tego run: %s ended%s · summary not available (%s) · %s\n", run, s.ended(), record.Printable(errText(s.err)), s.tail())
	} else {
		var parts []string
		if s.rc.Tier != "" {
			parts = append(parts, "tier "+record.Printable(s.rc.Tier))
		}
		parts = append(append(parts, s.counts(false)...), s.tail())
		fmt.Fprintf(&b, "tego run: %s ended (%s) · %s\n", run, s.rc.Outcome(), strings.Join(parts, " · "))
		b.WriteString(s.disclosures())
	}
	fmt.Fprintf(&b, "  more: %s %s\n", show, run)
	return b.String()
}

// The reads line (docs/OPERATIONS.md, after `tego learn`) is a fact, not a hint, so it prints whatever TEGO_HINTS says: after the
// summary of a run whose record cannot hold a read its contract refused, the line says so, since "refused N" does not
// count such a read. It is decided from run_start.reads_notified alone, never from the record level: a run at
// record: summary under reason.reads: on, an fs.ask_read entry, a read gate or held reads records its refused reads.
const (
	readsLineReasonOff    = "  reads: not recorded at this level; a read the contract refused left no line and is not counted in \"refused N\".\n"
	readsLineNoSupervisor = "  reads: not recorded; no supervisor answered this run's read notices.\n"
	readsLineUnknown      = "  reads: this record does not say whether reads were recorded.\n"
)

// readsLine is the reads line for the run, "" when none applies: the run's every read open reached the supervisor
// (notified), a root tier's kernel record holds its refused reads (kernel), or the run enforced nothing and so refused
// no read (records-only). A summary with no receipt says nothing of reads: its line already says the summary is not
// available.
func (s *endSummary) readsLine() string {
	if s == nil || s.rc == nil {
		return ""
	}
	rn := s.rc.ReadsNotified
	switch {
	case rn == nil:
		return readsLineUnknown
	case rn.Notified:
		return ""
	case rn.Why == record.ReadsNotifiedWhyReasonOff:
		return readsLineReasonOff
	case rn.Why == record.ReadsNotifiedWhyNoSupervisor:
		return readsLineNoSupervisor
	}
	return ""
}

// runHint is the "next:" block after tego run's summary and reads line, for the run o started. A record-only run
// (--observe) has its contract: the step is to run it enforced. Otherwise, a run that refused something leads to its
// receipt; one whose record level left its refused reads unrecorded (reason-off), or whose record does not say
// (an older record), to the same run with every read recorded; and any other to the check of its record. A run no
// supervisor answered (no-supervisor) is among the others: --record full does not change that.
func (s *endSummary) runHint(o runOptions) (text, command string) {
	return s.runHintWithShow(o, "tego session show")
}

func (s *endSummary) runHintWithShow(o runOptions, show string) (text, command string) {
	if o.observe {
		return "to enforce the contract, run it again without --observe:", runAgain(o, "")
	}
	run := shortRun(s.root, s.run)
	switch line := s.readsLine(); {
	case s.rc != nil && s.rc.Refusals.Total > 0:
		return "see what it refused, under which rule:", show + " " + run
	case line == readsLineReasonOff || line == readsLineUnknown:
		return "to see a read the contract refuses, run it again recording every read:", runAgain(o, "--record full")
	}
	return "check its record against the chain anchor:", show + " " + run + " --verify"
}

// runAgain is the tego run command of o as a shell reads it, the contract and the command after it as the person
// gave them, with flags in place of tego's own (which the hint does not repeat): "tego run <contract> [flags] [--
// <command>]". Each word is quoted where a shell would read it as something else.
func runAgain(o runOptions, flags string) string {
	words := []string{"tego", "run", shellword.Quote(o.contract)}
	if flags != "" {
		words = append(words, flags)
	}
	if len(o.given) > 0 {
		words = append(words, "--")
		for _, w := range o.given {
			words = append(words, shellword.Quote(w))
		}
	}
	return strings.Join(words, " ")
}

// tail is the summary line's last clauses: the chain's, after recordOffClause for a run whose record was off. Both
// are said whether or not the receipt could be built: neither is read from it.
func (s *endSummary) tail() string {
	if s.recordOff {
		return recordOffClause + " · " + s.chain
	}
	return s.chain
}

// ended is " (<how>)" for a run that did not simply exit, else "": what the receipt's outcome would have said.
func (s *endSummary) ended() string {
	if s.how == "" {
		return ""
	}
	return " (" + record.Printable(s.how) + ")"
}

// counts is the summary's middle clauses: refused (with the top rules), asked, and files written. quiet leaves out a
// refused or asked clause that is zero (a watch with no boundary refuses and asks nothing by design).
func (s *endSummary) counts(quiet bool) []string {
	rc := s.rc
	var parts []string
	rf := rc.Refusals
	if rf.Total > 0 || !quiet {
		parts = append(parts, refusedClause(rc))
	}
	a := rc.Asks
	if a.Asked > 0 || !quiet {
		parts = append(parts, askedClause(a))
	}
	if rc.Files.Recorded {
		n := len(rc.Files.Written)
		parts = append(parts, fmt.Sprintf("wrote %d %s", n, pluralWord(n, "file", "files")))
	}
	return parts
}

// refusedClause is "refused N (rule a, rule b, …)": the count, and the refusals per rule by the rule's kind (its
// name without the entry, so the line stays short), most first, three at most.
func refusedClause(rc *receipt.Receipt) string {
	rf := rc.Refusals
	s := "refused " + strconv.Itoa(rf.Total)
	if len(rf.ByRule) == 0 {
		return s
	}
	type group struct {
		name string
		n    int
	}
	var groups []group
	at := map[string]int{}
	for _, r := range rc.RefusalGroups() { // a built-in TCP_ULP refusal is named apart from the default deny
		name := r.Kind
		if i, ok := at[name]; ok {
			groups[i].n += r.Count
			continue
		}
		at[name] = len(groups)
		groups = append(groups, group{name, r.Count})
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].n > groups[j].n })
	var top []string
	for i, g := range groups {
		if i == 3 {
			top = append(top, "…")
			break
		}
		top = append(top, record.Printable(g.name)+" "+strconv.Itoa(g.n))
	}
	return s + " (" + strings.Join(top, ", ") + ")"
}

// disclosures qualifies the action counts and explains same-file refusals. Both the full
// summary and the terminal footer use it, so a new disclosure cannot be hidden by the footer.
// Token, pricing and stall gaps concern facts absent from the short footer.
func (s *endSummary) disclosures() string {
	if s.rc == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(sameFileLines(s.rc))
	b.WriteString(devNullLine(s.rc))
	for _, g := range s.rc.Coverage.Gaps {
		if g.Field == "record" || g.Field == "refusals" {
			fmt.Fprintf(&b, "  %s: %s\n", record.Printable(g.Field), record.Printable(g.Why))
		}
	}
	return b.String()
}

// devNullLine is the one line a run that was refused /dev/null by the default deny gets (ADR 0158): a shell's
// `> /dev/null` or `2>/dev/null` outside every fs.write entry fails with "permission denied". Every table with an fs:
// section now grants the standard data devices by what they are, so this arises only where that grant did not apply (the
// host's file at the name is not the device), under a contract with no fs: section (R6: no write entry at all), or in a
// record an earlier version wrote; the line names the cause and the fix, which costs
// nothing, since the device holds no file. It reads refusals under the rule `unmatched` alone: a run whose grant
// applied has allowed opens named `builtin.standard_devices`, and a refusal an entry of the contract made (a deny_write
// on /dev/null) is not the default; neither gets a line. "" when there is none. The count is of the refusals the receipt
// lists (at most receipt.MaxRefusals).
func devNullLine(rc *receipt.Receipt) string {
	n := 0
	for _, r := range rc.Refusals.List {
		if r.Kind == string(record.KindFS) && r.Target == "/dev/null" && r.Rule == agent.UnmatchedRule {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("  /dev/null: refused, no fs.write entry covers it (%d %s); it holds no file: add /dev/null to fs.write so `> /dev/null` works\n",
		n, pluralWord(n, "time", "times"))
}

// maxSameFile is how many programs refused as another name of a blocked file the summary names.
const maxSameFile = 3

// sameFileLines is a line for each program a live block refused as another name of its program's file
// (receipt.SameFile, liveblock.SameFileNote), at most maxSameFile: "  /bin/sleep: refused, same program file as
// /bin/ls, which is blocked (404 times)". The refused line's rule names the blocked path, not the one that ran, so the
// summary says why. "" when there is none.
func sameFileLines(rc *receipt.Receipt) string {
	var b strings.Builder
	for i, s := range rc.SameFile() {
		if i == maxSameFile {
			fmt.Fprintf(&b, "  and %d more refused the same way\n", len(rc.SameFile())-maxSameFile)
			break
		}
		fmt.Fprintf(&b, "  %s: refused, %s (%d %s)\n", record.Printable(s.Path), record.Printable(s.Note), s.Count,
			pluralWord(s.Count, "time", "times"))
	}
	return b.String()
}

// askedClause is "asked M (a approved, d denied)", with the other answers named only when there are any.
func askedClause(a receipt.Asks) string {
	asked := "asked " + strconv.Itoa(a.Asked)
	if a.Asked > 0 {
		asked += fmt.Sprintf(" (%d approved, %d denied", a.Approved, a.Denied)
		if a.TimedOut > 0 {
			asked += fmt.Sprintf(", %d timed out", a.TimedOut)
		}
		if a.Alternates > 0 {
			asked += fmt.Sprintf(", %d answered with another file", a.Alternates)
		}
		if a.Unanswered > 0 {
			asked += fmt.Sprintf(", %d not answered", a.Unanswered)
		}
		asked += ")"
	}
	return asked
}

// seen is the watch footer's counts line: the connections the run made and the secret-looking files it read, the two
// things a recording shows that its refusals (none) do not. "" when the summary has no receipt, and for a run whose
// record was off: its ledger holds no connection or read it allowed, so "no connections" would claim what it did not
// record (the footer's recordOffClause says why there is no line).
func (s *endSummary) seen() string {
	if s == nil || s.rc == nil || s.recordOff {
		return ""
	}
	rc := s.rc
	// The receipt keeps routine system lookups (nscd, userdb, D-Bus, DNS) out of Connections and ConnectionTries,
	// so these counts are the receipt's "N connections to P places" and never name the nscd socket.
	tries, places := rc.ConnectionTries, len(rc.Connections)+rc.ConnectionsMore
	var conn string
	switch places {
	case 0:
		conn = "no connections"
	case 1:
		conn = fmt.Sprintf("%d %s to %s", tries, pluralWord(tries, "connection", "connections"),
			record.Printable(rc.Connections[0].Destination))
	default:
		conn = fmt.Sprintf("%d connections to %d places", tries, places)
		// "most:" names a network place: a unix socket the run used (an agent's own helper) is listed in the receipt
		// but is never the headline's "most used place".
		for _, c := range rc.Connections {
			if !strings.HasPrefix(c.Destination, "unix:") {
				conn += " (most: " + record.Printable(c.Destination) + ")"
				break
			}
		}
	}
	if rc.ConnectionsOverflowAttempts > 0 {
		conn = strings.TrimSuffix(rc.ConnectionSummary(), ".")
	}
	var read string
	switch n := len(rc.SensitiveReads); n {
	case 0:
		read = "no sensitive file read"
	case 1:
		read = "1 sensitive file read: " + record.Printable(rc.ShortPath(rc.SensitiveReads[0].Path))
	default:
		read = fmt.Sprintf("%d sensitive files read (first: %s)", n, record.Printable(rc.ShortPath(rc.SensitiveReads[0].Path)))
	}
	return "  seen: " + conn + " · " + read + "\n"
}

func errText(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
