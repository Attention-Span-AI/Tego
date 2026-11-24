// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// `tego rules history <agent | file> [--json]` and `tego rules undo <agent | file> [<id>] [--yes]` (C130): the dashboard's
// change history and its Undo, from a terminal. Both go through rules.Service, the one reader the dashboard uses
// (History, Revert), so what a terminal lists and undoes is what the page lists and undoes: the same entries, the same
// wording (HistoryEntry.What), the same rule for which entry can be undone (HistoryEntry.Undoable) and the same
// acknowledgement for an undo that is not a narrowing. An undo is journaled under the writer "cli".
//
// The nouns tego hands off keep the terminal: tego execs this binary in place (internal/handoff Exec), so the
// confirmation word is read from the same standard input the person typed `tego rules undo` at.

// The reason codes of an undo refused as a finding, exit 1, beside codeUsage and codeIO (tego-control's own codes,
// main.go, map to exits 2 and 125 only): the file holds other text than the change wrote (a later change would be lost)
// or no change is left to undo, the person typed something other than the word (or interrupted the prompt), the caller
// is, or cannot be shown not to be, inside a run, and the older text is one the compiler no longer accepts.
const (
	codeStale        = "stale"
	codeNoChange     = "no-change"
	codeNotConfirmed = "not-confirmed"
	codeGoverned     = "governed"
	codeRefused      = "refused"
)

// findingExits is the exit of each of those codes (TestRulesUndoCodesHaveTheirExits): the table the refusals are written
// through (finding), so a code that is not here has no exit. None is a code of tego-control's own table.
var findingExits = map[string]int{
	codeStale:        identity.ExitFinding,
	codeNoChange:     identity.ExitFinding,
	codeNotConfirmed: identity.ExitFinding,
	codeGoverned:     identity.ExitFinding,
	codeRefused:      identity.ExitFinding,
}

// finding writes one refusal, "<what>; <fix> [<code>]", and returns the code's exit.
func finding(stderr io.Writer, what, code, fix string) int {
	diag(stderr, what, code, fix)
	return findingExits[code]
}

// undoWord is what a person types to confirm an undo that lets the next run do more, as `tego lift` asks for "lift".
const undoWord = "undo"

// historyLimit is how many entries the text lists; --json lists every one History returns.
const historyLimit = 20

// The seams of the commands, replaced by tests: the rule service, the terminal check, where the typed word is read
// from, the caller's own answer to "outside every run?", and the clock the entries' times are shown in.
var (
	newRulesService = ruleService
	stdinIsTerminal = func() bool {
		tty := false
		_ = sys.FileDo(os.Stdin, func(fd int) error { // a closed stdin is no terminal
			_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
			tty = err == nil
			return nil
		})
		return tty
	}
	confirmInput io.Reader = os.Stdin
	selfGoverned           = runact.SelfGoverned
	shownIn                = time.Local
)

// rulesHistoryVerb is tego rules history or tego rules undo, whichever name says.
func rulesHistoryVerb(ctx context.Context, name string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tego rules "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var asJSON, yes bool
	usage := "tego rules history <agent | file> [--json]"
	if name == "undo" {
		usage = "tego rules undo <agent | file> [<id>] [--yes]"
		fs.BoolVar(&yes, "yes", false, "confirm an undo that lets the next run do more, instead of typing "+undoWord+" (required without a terminal)")
	} else {
		fs.BoolVar(&asJSON, "json", false, "print the history as versioned JSON")
	}
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: "+usage)
		fs.PrintDefaults()
	}
	pos, err := parseMixed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return identity.ExitOK
		}
		return identity.ExitUsage
	}
	if len(pos) < 1 || len(pos) > 1 && (name == "history" || len(pos) > 2) {
		diag(stderr, "tego rules "+name+" needs "+map[string]string{"history": "one agent or rules file",
			"undo": "one agent or rules file, and at most one change id"}[name], codeUsage, "usage: "+usage)
		return identity.ExitUsage
	}
	// An undo asked from inside a run, or from a process that cannot be shown to be outside every run, cannot be told to
	// narrow until the contract's history is read, and a run's own contract may hide the ledger root that holds it. So
	// when the contract cannot be listed for such a caller, the answer is the governed refusal, not a usage error about
	// a file "no run here has run" (N112).
	var unlisted func(why string) int
	if name == "undo" {
		if a := selfGoverned(); !a.Outside() {
			unlisted = func(why string) int { return finding(stderr, notOutsideWords(a), codeGoverned, undoUnlistedFix(why)) }
		}
	}
	svc, code := rulesHistoryService(name, stderr)
	if svc == nil {
		return code
	}
	c, code := rulesContractOf(svc, name, pos[0], stderr, unlisted)
	if c == nil {
		return code
	}
	hs, err := svc.History(c.Ref)
	if err != nil {
		if unlisted != nil {
			return unlisted("its change record could not be read")
		}
		return historyFailed(name, c, err, stderr)
	}
	if name == "history" {
		return writeHistory(stdout, stderr, c, hs, asJSON)
	}
	id := ""
	if len(pos) == 2 {
		id = pos[1]
	}
	return undoChange(ctx, svc, c, hs, id, yes, stdout, stderr)
}

// parseMixed parses args with fs, flags and positional words in any order (a "--" ends the flags), as tego rules does.
func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		consumed := args[:len(args)-len(rest)]
		if len(consumed) > 0 && consumed[len(consumed)-1] == "--" {
			positional = append(positional, rest...)
			break
		}
		args = rest
		if len(args) == 0 {
			break
		}
		positional, args = append(positional, args[0]), args[1:]
	}
	return positional, nil
}

// rulesHistoryService is the rule service for this machine's ledger root, or the exit code of why it cannot be made.
func rulesHistoryService(name string, stderr io.Writer) (*rules.Service, int) {
	mr := loadMachineReport(config.TrustAbort)
	for _, d := range mr.diags {
		fmt.Fprintln(stderr, d.String())
	}
	if mr.err != nil {
		code := config.CodeInvalid
		if errors.Is(mr.err, config.ErrUntrusted) {
			code = config.CodeUntrusted
		}
		diag(stderr, "tego rules "+name+": "+mr.err.Error(), code, "repair the config layer, then run tego rules "+name+" again")
		return nil, identity.ExitError
	}
	root, err := ledgerRootOf(mr.m, mr.secure)
	if err != nil {
		diag(stderr, "tego rules "+name+": "+err.Error(), codeIO, "check ledger_root in TEGO_CONFIG")
		return nil, identity.ExitError
	}
	anchor, err := reportAnchorPath(mr)
	if err != nil {
		diag(stderr, "tego rules "+name+": "+err.Error(), codeIO, "check the chain anchor, then run tego rules "+name+" again")
		return nil, identity.ExitError
	}
	return newRulesService(root, anchor, mr.m, mr.secure), identity.ExitOK
}

// rulesContractOf is the contract of the set (rules.Service.Contracts: the rules files runs here ran) that ref names, an
// agent's name or a rules file's path, or the exit code of why it names none. A word with no slash and no .yaml ending is
// an agent first and a file in the working folder second; a path is made absolute and read as the dashboard names it.
//
// unlisted is set for an undo asked from a caller that is not shown to be outside every run: when the contract cannot be
// listed or named, it answers instead of the usage error (the caller says why in the governed refusal's words).
func rulesContractOf(svc *rules.Service, name, ref string, stderr io.Writer, unlisted func(why string) int) (*rules.ContractRef, int) {
	cs, err := svc.Contracts()
	if err != nil {
		if unlisted != nil {
			return nil, unlisted("the rules files runs here ran could not be listed")
		}
		diag(stderr, "tego rules "+name+": the rules files the runs here ran could not be listed: "+record.Printable(err.Error()), codeIO,
			"tego events <session> --verify checks a record")
		return nil, identity.ExitError
	}
	pathLike := strings.ContainsRune(ref, '/') || strings.HasSuffix(ref, ".yaml") || strings.HasSuffix(ref, ".yml")
	if !pathLike {
		var named []rules.ContractRef
		for _, c := range cs {
			if c.Agent == ref {
				named = append(named, c)
			}
		}
		switch len(named) {
		case 1:
			return &named[0], identity.ExitOK
		case 0:
		default:
			var paths []string
			for _, c := range named[:min(len(named), 5)] {
				paths = append(paths, record.Printable(c.Path))
			}
			diag(stderr, fmt.Sprintf("tego rules %s: %d rules files here are named %s (%s)", name, len(named), record.Printable(ref),
				strings.Join(paths, ", ")), codeUsage, "give the file: tego rules "+name+" <file>")
			return nil, identity.ExitUsage
		}
	}
	abs, err := filepath.Abs(ref)
	if err == nil {
		if r := rules.Ref(abs); r != "" {
			for i := range cs {
				if cs[i].Ref == r {
					return &cs[i], identity.ExitOK
				}
			}
		}
	}
	var agents []string
	for _, c := range cs {
		if len(agents) < 8 && !slices.Contains(agents, c.Agent) {
			agents = append(agents, record.Printable(c.Agent))
		}
	}
	if unlisted != nil {
		return nil, unlisted("no rules file or agent here is named " + record.Printable(ref) + " in what this process can list")
	}
	known := "no run here has run a rules file yet"
	if len(agents) > 0 {
		known = "the agents here: " + strings.Join(agents, ", ")
	}
	diag(stderr, "tego rules "+name+": no rules file or agent here is named "+record.Printable(ref)+": only a file a session here ran can be listed",
		codeUsage, known)
	return nil, identity.ExitUsage
}

// undoUnlistedFix is the fix line of the governed refusal of an undo whose contract could not be listed: why it could
// not, and that only a process outside every run can undo it, since from here tego cannot tell whether it would narrow.
func undoUnlistedFix(why string) string {
	return "from this process " + why + " (a run's own rules can hide the ledger root), so tego cannot show that this undo only narrows"
}

// historyFailed words a History that could not be read: a guard or an I/O failure, exit 125.
func historyFailed(name string, c *rules.ContractRef, err error, stderr io.Writer) int {
	diag(stderr, "tego rules "+name+": the change record of "+record.Printable(c.Path)+" could not be read: "+record.Printable(err.Error()),
		codeIO, "check the file and its folder, then run tego rules "+name+" again")
	return identity.ExitError
}

// when is an entry's time as the history shows it.
func when(t time.Time) string { return t.In(shownIn).Format("2006-01-02 15:04") }

// historyJSON is `tego rules history --json`: version 1, the contract and its entries, newest first, each as the service
// reads it (the dashboard's list) with the same wording (what) and whether an Undo of it is offered now (can_undo).
type historyJSON struct {
	V        int                `json:"v"`
	Contract historyContract    `json:"contract"`
	Entries  []historyEntryJSON `json:"entries"`
}

type historyContract struct {
	Agent string `json:"agent"`
	Path  string `json:"path"`
}

type historyEntryJSON struct {
	ID        string    `json:"id"`
	Op        string    `json:"op"`
	At        time.Time `json:"at"`
	Via       string    `json:"via,omitempty"`
	Run       string    `json:"run,omitempty"`
	What      string    `json:"what"`
	Sentences []string  `json:"sentences,omitempty"`
	Direction string    `json:"direction,omitempty"`
	Reverts   string    `json:"reverts,omitempty"`
	UndoneBy  string    `json:"undone_by,omitempty"`
	CanUndo   bool      `json:"can_undo"`
}

// writeHistory is the history of contract c, newest first: JSON every entry, text the newest historyLimit. It exits 0.
func writeHistory(stdout, stderr io.Writer, c *rules.ContractRef, hs []rules.HistoryEntry, asJSON bool) int {
	if asJSON {
		out := historyJSON{V: 1, Contract: historyContract{Agent: c.Agent, Path: c.Path}, Entries: make([]historyEntryJSON, 0, len(hs))}
		for _, h := range hs {
			out.Entries = append(out.Entries, historyEntryJSON{ID: h.ID, Op: h.Op, At: h.At.UTC(), Via: h.Via, Run: h.Run, What: h.What(),
				Sentences: h.Sentences, Direction: h.Direction, Reverts: h.Reverts, UndoneBy: h.UndoneBy, CanUndo: h.Undoable(c.Base)})
		}
		if err := json.NewEncoder(stdout).Encode(out); err != nil {
			diag(stderr, "tego rules history: "+err.Error(), codeIO, "check the output destination")
			return identity.ExitError
		}
		return identity.ExitOK
	}
	p := record.Printable
	var b strings.Builder
	if len(hs) == 0 {
		fmt.Fprintf(&b, "No change to %s (%s) has been recorded.\n", p(c.Agent), p(c.Path))
	} else {
		fmt.Fprintf(&b, "Changes to %s (%s), newest first:\n", p(c.Agent), p(c.Path))
	}
	undoable := ""
	for i, h := range hs {
		if h.Undoable(c.Base) && undoable == "" {
			undoable = h.ID
		}
		if i >= historyLimit {
			continue
		}
		fmt.Fprintf(&b, "  %s  %s", p(h.ID), when(h.At))
		if h.Via != "" {
			fmt.Fprintf(&b, "  %s", p(h.Via))
		}
		fmt.Fprintf(&b, "  %s", p(h.What()))
		if h.Direction != "" {
			fmt.Fprintf(&b, "  [%s]", p(h.Direction))
		}
		if h.UndoneBy != "" {
			fmt.Fprintf(&b, "  (undone by %s)", p(h.UndoneBy))
		}
		b.WriteString("\n")
	}
	if len(hs) > historyLimit {
		fmt.Fprintf(&b, "  and %d older; tego rules history %s --json lists them all\n", len(hs)-historyLimit, shellWord(c.Path))
	}
	if undoable != "" {
		fmt.Fprintf(&b, "Undo the newest change: tego rules undo %s\n", shellWord(c.Path))
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		diag(stderr, "tego rules history: "+err.Error(), codeIO, "check the output destination")
		return identity.ExitError
	}
	return identity.ExitOK
}

// undoChange undoes the change id (empty: the newest one the file still holds) of contract c, whose history is hs.
// An undo that only narrows needs no confirmation. One that lets the next run do more (a widening, a mixed change or a
// free edit) prints what it does and asks for undoWord to be typed at a terminal, as `tego lift` asks for its word; with
// no terminal it needs --yes, and exits 2 without it. From inside a run, or from a process that cannot be shown to be
// outside every run, such an undo is refused, exit 1. A file that holds other text than the entry wrote is "changed
// since", exit 1. A guard or an I/O failure is exit 125.
func undoChange(ctx context.Context, svc *rules.Service, c *rules.ContractRef, hs []rules.HistoryEntry, id string, yes bool, stdout, stderr io.Writer) int {
	p := record.Printable
	var h *rules.HistoryEntry
	switch {
	case id != "":
		i := slices.IndexFunc(hs, func(h rules.HistoryEntry) bool { return h.ID == id })
		if i < 0 {
			diag(stderr, "tego rules undo: "+p(c.Path)+" has no recorded change "+p(id), codeUsage, "tego rules history "+shellWord(c.Path)+" lists them")
			return identity.ExitUsage
		}
		h = &hs[i]
	default:
		i := slices.IndexFunc(hs, func(h rules.HistoryEntry) bool { return h.Undoable(c.Base) })
		if i < 0 {
			why, code := "no change to it has been recorded", codeNoChange
			if len(hs) > 0 {
				why, code = "it has changed since its last recorded change was written, or that change is undone already", codeStale
			}
			return finding(stderr, "tego rules undo: nothing to undo in "+p(c.Path)+": "+why+"; nothing was changed", code,
				"tego rules history "+shellWord(c.Path)+" shows what was recorded")
		}
		h = &hs[i]
	}
	switch {
	case h.Op == rulefile.OpCreate:
		diag(stderr, "tego rules undo: "+p(h.ID)+" created "+p(c.Path)+", so there is no older text to give back", codeUsage, "nothing was changed")
		return identity.ExitUsage
	case h.UndoneBy != "":
		return finding(stderr, "tego rules undo: "+p(h.ID)+" was undone already, by "+p(h.UndoneBy)+"; nothing was changed", codeStale,
			"tego rules history "+shellWord(c.Path)+" shows what was recorded")
	case !h.Undoable(c.Base):
		return changedSince(stderr, c, h.ID)
	}
	narrows := h.UndoDirection() == string(rule.Narrows)
	if !narrows && !yes && !stdinIsTerminal() {
		diag(stderr, fmt.Sprintf("tego rules undo: undoing %s lets the next run do more, so it asks for %q to be typed at a terminal; "+
			"without one, add --yes", p(h.ID), undoWord), codeUsage, "nothing was changed")
		return identity.ExitUsage
	}
	if !narrows {
		if a := selfGoverned(); !a.Outside() {
			return finding(stderr, notOutsideWords(a), codeGoverned, "nothing was changed")
		}
	}
	fmt.Fprint(stdout, undoSummary(c, h, narrows))
	if !narrows && !yes {
		fmt.Fprintf(stderr, "Type %s to confirm: ", undoWord)
		line, typed := readWord(ctx, confirmInput)
		if !typed || strings.TrimSpace(line) != undoWord {
			if !typed {
				fmt.Fprintln(stderr)
			}
			return finding(stderr, "tego rules undo: not confirmed, so nothing was undone", codeNotConfirmed, "run it again and type "+undoWord)
		}
	}
	r, err := svc.Revert(ctx, rules.RevertReq{ID: h.ID, Base: c.Base, Ack: h.Ack, Via: rules.ViaCLI})
	if err != nil {
		return undoFailed(stdout, stderr, c, h, r, err)
	}
	fmt.Fprint(stdout, undone(c, h, r))
	return identity.ExitOK
}

// undoSummary is what an undo will do, before it is confirmed: which change, in the words the history uses, which text
// comes back, and whether the next run may do more.
func undoSummary(c *rules.ContractRef, h *rules.HistoryEntry, narrows bool) string {
	p := record.Printable
	var b strings.Builder
	fmt.Fprintf(&b, "Undo %s on %s (%s)\n", p(h.ID), p(c.Agent), p(c.Path))
	fmt.Fprintf(&b, "The change: %s\n", p(h.What()))
	if narrows {
		b.WriteString("Undoing it only narrows the rules: the next run can do no more than it can now.\n")
	} else {
		b.WriteString("Undoing it lets the next run do more: the file gets its text from before this change back.\n")
	}
	return b.String()
}

// undone is what a written undo says: the journal entry it made, when it applies, and the live blocks it left in force.
func undone(c *rules.ContractRef, h *rules.HistoryEntry, r *rules.Reverted) string {
	p := record.Printable
	var b strings.Builder
	fmt.Fprintf(&b, "Undone: %s\n", p(h.What()))
	fmt.Fprintf(&b, "%s has its text from before %s back; the journal records the undo as %s (via %s).\n", p(r.Contract), p(h.ID), p(r.ID), rules.ViaCLI)
	fmt.Fprintf(&b, "It applies from the next run of %s; a run that is running keeps the rules it started with.\n", p(c.Agent))
	if len(r.Kept) > 0 {
		b.WriteString("Live blocks this change placed on running runs stay in force (an undo from a terminal does not lift them):\n")
		for _, o := range r.Kept {
			fmt.Fprintf(&b, "  %s  %s\n", p(o.Run), p(o.Block))
			if cmd := unblockCommand(o); cmd != "" {
				fmt.Fprintf(&b, "    end it: %s\n", cmd)
			}
		}
	}
	return b.String()
}

// unblockCommand is the tego unblock command that ends the live block o, "" when its value is not plain printable text
// (a command line that held it could be read as something else).
func unblockCommand(o rules.LiftOption) string {
	if o.Run == "" || o.Kind == "" || o.Value == "" || o.Value != record.Printable(o.Value) {
		return ""
	}
	return fmt.Sprintf("tego unblock %s %s -- %s", shellWord(o.Run), shellWord(o.Kind), shellWord(o.Value))
}

// changedSince is the refusal of an undo of a change whose text the file no longer holds: a later change or an edit by
// hand came after it, and giving the older text back would lose it.
func changedSince(stderr io.Writer, c *rules.ContractRef, id string) int {
	return finding(stderr, "tego rules undo: "+record.Printable(c.Path)+" has changed since "+record.Printable(id)+" wrote it, so nothing was undone (that "+
		"would lose the later change)", codeStale, "tego rules history "+shellWord(c.Path)+" shows what was recorded")
}

// undoFailed words an error of Revert, with the exit it takes: a file that changed since (ErrStale), an undo that was not
// acknowledged (ErrNeedsAck: the service wanted more than the word) or an older text the compiler no longer accepts
// (ErrNotCompiled, nothing written) are exit 1; a contract no run here ran, or a change the journal does not hold, is
// exit 2; anything else (a write the guards or the system refuse, a cancelled context), is exit 125 [io]. A
// revert that was written and not journaled (rulefile.ErrJournal) is exit 125 with what is on disk said.
func undoFailed(stdout, stderr io.Writer, c *rules.ContractRef, h *rules.HistoryEntry, r *rules.Reverted, err error) int {
	p := record.Printable
	switch {
	case errors.Is(err, rulefile.ErrJournal) && r != nil:
		fmt.Fprintf(stdout, "%s was written with its text from before %s, but the journal does not hold the undo.\n", p(r.Contract), p(h.ID))
		diag(stderr, "tego rules undo: "+p(err.Error()), codeIO, "check the ledger root's rules journal; the file itself was changed")
		return identity.ExitError
	case errors.Is(err, rules.ErrStale), errors.Is(err, rulefile.ErrStale):
		return changedSince(stderr, c, h.ID)
	case errors.Is(err, rules.ErrNeedsAck):
		return finding(stderr, "tego rules undo: the service did not accept the confirmation: "+p(err.Error()), codeNotConfirmed, "nothing was changed")
	case errors.Is(err, rules.ErrNotCompiled):
		return finding(stderr, "tego rules undo: refused, nothing was changed: "+p(err.Error()), codeRefused,
			"tego rules check "+shellWord(c.Path)+" shows what the file holds")
	case errors.Is(err, rulefile.ErrNoChange):
		diag(stderr, "tego rules undo: "+p(err.Error()), codeUsage, "tego rules history "+shellWord(c.Path)+" lists the recorded changes")
		return identity.ExitUsage
	case errors.Is(err, rules.ErrNoContract):
		diag(stderr, "tego rules undo: "+p(err.Error()), codeUsage, "nothing was changed")
		return identity.ExitUsage
	}
	diag(stderr, "tego rules undo: "+p(err.Error()), codeIO, "check the file and its folder, then run tego rules history "+shellWord(c.Path))
	return identity.ExitError
}

// notOutsideWords is the refusal of an undo that lets the next run do more, asked from a process that is inside a run or
// cannot be shown to be outside every run (runscope), in the words `tego lift` uses.
func notOutsideWords(a runscope.Answer) string {
	advice := runscope.Advice(a)
	if advice != "" {
		advice = "; " + advice
	}
	switch {
	case runscope.SaysGoverned(a):
		return "tego rules undo: a governed agent cannot widen its own rules, nor another run's: " + runscope.Why(a) + "; nothing was changed" + advice
	case runscope.PlainFirst(a):
		return "tego rules undo: " + runscope.Why(a) + "; until then tego cannot show that this process is outside every tego run, so the undo was refused"
	}
	return "tego rules undo: the undo was refused: this process cannot be shown to be outside every tego run: " + runscope.Why(a) + advice
}

// shellWord quotes s for a shell when it holds anything but plain path characters.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+=:@%,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// readWord reads the line the person types at the prompt from in, at most 256 bytes of it. An interrupt (ctx done)
// ends the wait at once and is not a word, and so is a line that arrives after it: the second result is false.
func readWord(ctx context.Context, in io.Reader) (string, bool) {
	ch := make(chan string, 1)
	go func() { // a read of a terminal cannot be cancelled: it ends with the process
		line, _ := bufio.NewReader(io.LimitReader(in, 256)).ReadString('\n')
		ch <- line
	}()
	select {
	case line := <-ch:
		return line, ctx.Err() == nil
	case <-ctx.Done():
		return "", false
	}
}
