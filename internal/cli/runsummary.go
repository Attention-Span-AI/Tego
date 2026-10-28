// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The end-of-run summary (H08): once the agent has exited (on its own, stopped, or by a limit), tego run says
// in two lines what the run did and where to read the rest, so nobody scrapes a run id out of the agent's own output:
//
//	tego run: <run> ended (<outcome>) · refused N (top rules) · asked M (a approved, d denied) · wrote K files · chain verified
//	  more: tego receipt <run>
//
// The numbers are receipt.Compute's over the run's ledger, the same builder `tego receipt` and the dashboard's
// Receipt tab use, never a second counter, so the three cannot disagree. "chain verified" is said only after the
// run's hash chain and its anchor were checked here (ledger.VerifyRunDir); when they could not be, the line says
// "chain not checked (<why>)". --no-summary turns it off. It is printed after the agent's process tree is gone,
// never while it runs.

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
}

// summarizeRun builds the summary of the run res names: its receipt over the run's ledger, and its chain verified
// against anchor. nil when there is no run (the run never started).
func summarizeRun(ctx context.Context, m *config.Machine, anchor string, res tegoruntime.Result) *endSummary {
	if res.RunID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), summaryBudget)
	defer cancel()
	s := &endSummary{run: res.RunID, how: endedHow(res.Reason)}
	root, err := ledgerRootOf(m)
	if err != nil {
		s.err, s.chain = err, "chain not checked (no ledger root)"
		return s
	}
	dir := filepath.Join(root, res.RunID)
	// The receipt's pass and the chain check are two independent reads of the same closed file, each about half
	// the cost: run side by side, the summary costs about 10 ms per 1,000 lines instead of 18 (BenchmarkEndSummary).
	// The goroutine is joined before return, and both stop at the budget's deadline.
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.chain = chainClause(ctx, dir, anchor, res)
	}()
	s.rc, s.err = receiptOf(ctx, dir)
	<-done
	return s
}

// receiptOf computes the receipt of the run in dir. No prices: the summary prints no cost, so it never reads the
// price table (or warns about one).
func receiptOf(ctx context.Context, dir string) (*receipt.Receipt, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	return receipt.Compute(ctx, r, receipt.Options{Home: os.Getenv("HOME")})
}

// chainClause checks the run's chain and its anchor as `tego events --verify` does, and says the result in a few
// words. "verified" needs both: every line chained, and the head anchored in chain.log.
func chainClause(ctx context.Context, dir, anchor string, res tegoruntime.Result) string {
	switch {
	case res.RecordErr != nil:
		return "chain not checked (the run's record is incomplete)"
	case anchor == "":
		return "chain not checked (no chain anchor)"
	}
	rep, err := ledger.VerifyRunDir(ctx, dir, ledger.NewFileChainAnchor(anchor))
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

// text is the summary's two lines, prefixed "tego run: " (watch's writer turns it into "tego watch: ").
func (s *endSummary) text() string {
	var b strings.Builder
	run := record.Printable(s.run)
	if s.rc == nil {
		fmt.Fprintf(&b, "tego run: %s ended%s · summary not available (%s) · %s\n", run, s.ended(), record.Printable(errText(s.err)), s.chain)
	} else {
		fmt.Fprintf(&b, "tego run: %s ended (%s) · %s\n", run, s.rc.Outcome(), strings.Join(append(s.counts(false), s.chain), " · "))
	}
	fmt.Fprintf(&b, "  more: tego receipt %s\n", run)
	return b.String()
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
	for _, r := range rf.ByRule {
		name, _, _ := strings.Cut(rc.RuleWords(r.Rule), "[")
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
// things a recording shows that its refusals (none) do not. "" when the summary has no receipt.
func (s *endSummary) seen() string {
	if s == nil || s.rc == nil {
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
