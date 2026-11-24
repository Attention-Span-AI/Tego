// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livetime"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func init() {
	register(cmdLift)
	register(cmdGrant)
	register(cmdRestore)
}

// The diagnostics of a lift, a grant or a restore refused before it is asked (ADR 0125 decision 5), beside
// codeNotRunning, codeOldLauncher and codeGoverned. A refusal by the run's launcher carries its record.LiveRefused
// value instead (mac, outside-fence, locked, until).
const (
	codeLocked       = "locked"
	codeOutsideFence = "outside-fence"
	codeNoKey        = "no-key"
	// codeStarting: the run's run_start cannot be read yet, so a change that depends on its mode or its launcher's
	// facts is refused as not known (liveblock.ErrStarting), never as [locked].
	codeStarting = "starting"
	// codeStartUnreadable: the run's first record line is there and is not a run_start this tego can read, so such a
	// change is refused as not known (liveblock.ErrStartUnreadable), with no "try again": waiting does not change it.
	codeStartUnreadable = "start-unreadable"
	// codeNotConfirmed: at a terminal, the person typed something other than the command's word.
	codeNotConfirmed = "not-confirmed"
)

// liftClock is the clock a lift's time limit is read and checked on; tests replace it.
var liftClock = time.Now

// liftWait bounds how long a lift, a grant or a restore waits for the run's launcher to record what took effect; the
// launcher polls its overlay every 500 ms. Tests shorten it.
var liftWait = 3 * time.Second

// stdinIsTerminal reports whether standard input is a terminal, where a lift asks for its word to be typed; tests
// replace it.
var stdinIsTerminal = func() bool {
	tty := false
	_ = sys.FileDo(os.Stdin, func(fd int) error { // a closed stdin is no terminal
		_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		tty = err == nil
		return nil
	})
	return tty
}

// confirmInput is where the typed word is read from; tests replace it.
var confirmInput io.Reader = os.Stdin

// liveKinds are the kinds a fence entry, and so a lift, a grant or a restore, is of.
const liveKinds = "read|net|exec"

// modesNote ends the usage line of lift, grant and restore: which runs they apply to, in the two modes' names (ADR
// 0125).
const modesNote = "  (Adjustable runs only, inside their fence; a Locked run loosens from its next run)"

// cmdLift is `tego lift <run> <read|net|exec> <value> [--for D | --until T] [--note TEXT] [--yes]`: on a running Adjustable run (ADR
// 0125), allow a fence entry that is one of the contract's refusals, for the rest of the run or until the limit. It
// loosens, so it is refused from inside any run ([governed]) and asks for "lift" to be typed at a terminal (--yes
// without one). The run's launcher checks the request (its MAC under the run's key, the fence, the limit) and records
// what took effect; tego lift waits up to 3 s for that line. A Locked run ([locked]), an entry outside the run's fence
// ([outside-fence]), a run that is not running ([not-running]), a run started by a tego with no time limits given one
// ([launcher-too-old]) and a run key that cannot be read ([no-key]) are refused, exit 1. Whatever is allowed this way
// is enforced by Tego's live layer, not the kernel: the kernel holds the run to its fence. --note gives the lift a short
// text for the record (at most liveblock.MaxNote bytes of printable text): it is signed with the lift, written on the
// launcher's line and shown, never acted on; a run whose launcher does not read one refuses it in words ([launcher-too-old])
// and nothing is asked.
func cmdLift() Command { return fenceCommand("lift") }

// cmdGrant is `tego grant <run> <read|net|exec> <value> [--for D | --until T] [--note TEXT] [--yes]`: tego lift worded for a fence
// entry that is new access, which the contract does not have. It is the same request, with the same checks.
func cmdGrant() Command { return fenceCommand("grant") }

// fenceCommand is lift or grant, by name.
func fenceCommand(name string) Command {
	var lim liveLimit
	var yes bool
	var note string
	summary := map[string]string{
		"lift":  "allow one of an Adjustable run's fenced refusals while it runs, for a while or for the rest of the run",
		"grant": "give an Adjustable run access its fence lists while it runs, for a while or for the rest of the run",
	}[name]
	return Command{
		Name:    name,
		Summary: summary,
		Usage:   "<run> <" + liveKinds + "> <value> [--for D | --until T] [--note TEXT] [--yes]" + modesNote,
		Flags: func(fs *flag.FlagSet) {
			lim.flags(fs, "it is refused again")
			fs.StringVar(&note, "note", "", "a short text for the record, shown beside the "+name+" (at most 200 bytes, printable text only)")
			fs.BoolVar(&yes, "yes", false, "do not ask for the word to be typed (required without a terminal)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			return runLift(ctx, name, lim, yes, note, fs, stdout, stderr)
		},
	}
}

// cmdRestore is `tego restore <run> <read|net|exec> <value>`: on a running Adjustable run, refuse a lifted or granted
// fence entry again, now. It narrows, so it needs no confirmation, and from inside a run it may name only that same
// run (refuseCrossRun, as tego block).
func cmdRestore() Command {
	return Command{
		Name:    "restore",
		Summary: "refuse a lifted or granted fence entry of an Adjustable run again, now",
		Usage:   "<run> <" + liveKinds + "> <value>" + modesNote,
		Run:     runRestore,
	}
}

// fenceArgs reads <run> <kind> <value> of a lift, a grant or a restore: a kind a fence entry may be of, and the value
// normalized as the run's fence lists it (a relative read path made absolute). ok false wrote a usage error.
func fenceArgs(name string, fs *flag.FlagSet, stderr io.Writer) (ref string, kind liveblock.Kind, value string, ok bool) {
	if fs.NArg() != 3 {
		message(stderr, "", 0, 0, "tego "+name+": exactly <run> <"+liveKinds+"> <value>", codeUsage)
		return "", "", "", false
	}
	kind, err := liveblock.ParseKind(fs.Arg(1))
	if err == nil && !slices.Contains(liveblock.FenceKinds, kind) {
		err = fmt.Errorf("a fence entry is of kind read, net or exec, not %s", kind)
	}
	raw := fs.Arg(2)
	if err == nil && kind == liveblock.KindRead {
		raw, err = absPathValue(raw)
	}
	if err == nil {
		value, err = liveblock.Normalize(kind, raw)
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
		return "", "", "", false
	}
	return fs.Arg(0), kind, value, true
}

// fenceRun finds the run ref names and checks what a lift and a restore both need (liveblock.CheckFence, as runact
// checks it for the dashboard): it is running, its launcher reads until (a lift's time limit; zero for none, and for
// a restore), it is Adjustable, and its fence lists kind:value. It returns the run's directory, its id and the fence
// entry, or the exit code of the refusal it wrote.
func fenceRun(name, ref string, kind liveblock.Kind, value string, until time.Time, stderr io.Writer) (dir, run string, e record.LiveFenceEntry, code int) {
	dir, run, code = blockRun(name, ref, stderr)
	if code != identity.ExitOK {
		return "", "", e, code
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		return "", "", e, liveRunFailed(name, dir, err, stderr)
	}
	facts := startFacts(dir)
	t := liveTarget(run, held, facts)
	e, t.Fenced = facts.InFence(string(kind), value)
	if err := liveblock.CheckFence(t, kind, value, until); err != nil {
		return "", "", e, fenceRefused(name, err, stderr)
	}
	return dir, run, e, identity.ExitOK
}

// fenceRefused writes the refusal of a lift, a grant or a restore (liveblock.CheckFence, LiftKey), or of an MCP switch or
// a model route on a Locked run (liveblock.CheckLoosening), in its words naming the run, with what to do instead where
// the terminal has something to offer, and returns exit 1.
func fenceRefused(name string, err error, stderr io.Writer) int {
	hint := ""
	switch {
	case errors.Is(err, liveblock.ErrLocked):
		hint = "; to loosen live, choose Adjustable for the next run (live.mode: adjustable, ADR 0125)"
	case errors.Is(err, liveblock.ErrOutsideFence):
		hint = "; change the rules (tego rule) and it applies from the next run"
	}
	message(stderr, "", 0, 0, "tego "+name+": "+liveblock.RunWords(err)+hint, liveCode(err))
	return identity.ExitFinding
}

// runLift is the body of lift and grant.
func runLift(ctx context.Context, name string, lim liveLimit, yes bool, note string, fs *flag.FlagSet, stdout, stderr io.Writer) int {
	ref, kind, value, ok := fenceArgs(name, fs, stderr)
	if !ok {
		return identity.ExitUsage // R25: usage error
	}
	note = strings.TrimSpace(note)
	if err := liveblock.ValidNote(note); err != nil {
		message(stderr, "", 0, 0, "tego "+name+": --note: "+plainNoteErr(err), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	until, err := lim.until(liftClock())
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	if !yes && !stdinIsTerminal() {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: this loosens a running run, so it asks for %q to be typed at a terminal; "+
			"without one, add --yes", name, name), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	if refuseGoverned(name, stderr) { // a lift loosens: never from inside a run
		return identity.ExitFinding
	}
	dir, run, entry, code := fenceRun(name, ref, kind, value, until, stderr)
	if code != identity.ExitOK {
		return code
	}
	if err := liveblock.CheckNote(dir, run, note); err != nil {
		return fenceRefused(name, err, stderr)
	}
	key, err := liveblock.LiftKey(dir, run)
	if err != nil {
		return fenceRefused(name, err, stderr)
	}
	fmt.Fprint(stdout, liftSummary(name, run, kind, value, entry.Source, until, note))
	if !yes {
		fmt.Fprintf(stderr, "Type %s to confirm: ", name)
		line, _ := bufio.NewReader(io.LimitReader(confirmInput, 256)).ReadString('\n')
		if strings.TrimSpace(line) != name {
			message(stderr, "", 0, 0, "tego "+name+": not confirmed, so nothing was asked", codeNotConfirmed)
			return identity.ExitFinding
		}
		if until, code = limitAfterConfirm(name, lim, until, stdout, stderr); code != identity.ExitOK {
			return code
		}
	}
	var serial uint64
	off := ledgerEnd(dir) // the launcher's answer is appended after this
	_, err = liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		c, err := o.LiftNote(kind, value, liveblock.By("cli"), note, time.Now(), until, key)
		serial = c.Serial
		return err == nil, err
	})
	if code := updateFailed(name, err, stderr); code != identity.ExitOK {
		return code
	}
	return reportFence(ctx, name, dir, run, kind, value, note, serial, off, stdout, stderr)
}

// plainNoteErr is a note's refusal (liveblock.ValidNote) without its package prefix.
func plainNoteErr(err error) string {
	return strings.TrimPrefix(err.Error(), liveblock.ErrInvalid.Error()+": ")
}

// limitAfterConfirm reads a lift's time limit again once the person confirmed it, since typing the word takes time: a
// --for span counts from the confirmation (said when it moved by a second or more), and a --until instant must still
// be at least liveblock.MinSpan ahead, or nothing is asked. With no limit it returns until unchanged.
func limitAfterConfirm(name string, lim liveLimit, until time.Time, stdout, stderr io.Writer) (time.Time, int) {
	if until.IsZero() {
		return until, identity.ExitOK
	}
	now := liftClock()
	if lim.forArg != "" {
		again, err := lim.until(now)
		if err != nil {
			message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
			return time.Time{}, identity.ExitUsage // R25: usage error
		}
		if again.Sub(until).Abs() >= time.Second {
			fmt.Fprintf(stdout, "Confirmed; the limit counts from now: %s.\n", livetime.Describe(again, now, time.Local))
		}
		return again, identity.ExitOK
	}
	if err := liveblock.CheckUntil(now, until); err != nil {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: the limit %s passed, or came within a minute, while waiting for "+
			"confirmation, so nothing was asked; ask again with a later --until", name,
			until.Local().Format("Mon 2 Jan 15:04")), codeUsage)
		return time.Time{}, identity.ExitUsage // R25: usage error
	}
	return until, identity.ExitOK
}

// liftSummary is what a lift or a grant tells the person before they confirm it: what the run will be able to do,
// for how long, and what enforces it.
func liftSummary(name, run string, kind liveblock.Kind, value, source string, until time.Time, note string) string {
	var b strings.Builder
	v := record.Printable(value)
	can := map[liveblock.Kind]string{
		liveblock.KindRead: "read " + v + " and everything beneath it",
		liveblock.KindNet:  "connect to " + v,
		liveblock.KindExec: "run " + v,
	}[kind]
	fmt.Fprintf(&b, "%s %s on run %s (%s)\n", map[string]string{"lift": "Lift", "grant": "Grant"}[name],
		liveblock.FenceRule(kind, value), run, map[string]string{
			record.LiveFenceSourceDeny: "one of the contract's refusals, which its fence lets you lift",
			record.LiveFenceSourceNew:  "access the contract does not have, which its fence lets you grant",
		}[source])
	fmt.Fprintf(&b, "The run will be able to %s, ", can)
	if until.IsZero() {
		b.WriteString("for the rest of the run (tego restore refuses it again).\n")
	} else {
		fmt.Fprintf(&b, "%s; then it is refused again.\n", describeUntil(until))
	}
	b.WriteString("Enforced by Tego's live layer, not the kernel. A time limit stops new access; what was already read or " +
		"copied, open files and live connections stay.\n")
	if note != "" {
		fmt.Fprintf(&b, "Note for the record: %s\n", record.LiveNoteShown(note))
	}
	if kind == liveblock.KindExec {
		b.WriteString("Best effort for a program: refused again, it is matched by name and file, so a copy under another " +
			"name runs wherever the agent can write and execute.\n")
	}
	return b.String()
}

// runRestore is the body of restore.
func runRestore(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
	const name = "restore"
	ref, kind, value, ok := fenceArgs(name, fs, stderr)
	if !ok {
		return identity.ExitUsage // R25: usage error
	}
	dir, run, _, code := fenceRun(name, ref, kind, value, time.Time{}, stderr)
	if code != identity.ExitOK {
		return code
	}
	if refuseCrossRun(name, run, stderr) { // a restore narrows: an agent may ask it of its own run only
		return identity.ExitFinding
	}
	var serial uint64
	off := ledgerEnd(dir) // the launcher's answer is appended after this
	_, err := liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		c, err := o.Restore(kind, value, liveblock.By("cli"), time.Now())
		serial = c.Serial
		return err == nil, err
	})
	if code := updateFailed(name, err, stderr); code != identity.ExitOK {
		return code
	}
	return reportFence(ctx, name, dir, run, kind, value, "", serial, off, stdout, stderr)
}

// updateFailed writes an overlay write's error, a usage error when the overlay refused the change itself.
func updateFailed(name string, err error, stderr io.Writer) int {
	switch {
	case err == nil:
		return identity.ExitOK
	case errors.Is(err, liveblock.ErrInvalid):
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
	return identity.ExitError
}

// reportFence waits for the launcher's line answering the change numbered serial and says what took effect: the
// first line keeps the form "<run>: <word> live.fence[<kind>:<value>]", as tego block's does. A refusal by the
// launcher exits 1 with its reason in brackets; no line within liftWait says the request is asked.
func reportFence(ctx context.Context, name, dir, run string, kind liveblock.Kind, value, note string, serial uint64, off int64, stdout, stderr io.Writer) int {
	rule := liveblock.FenceRule(kind, value)
	why, c, ok, err := awaitFenceLine(ctx, dir, serial, off, liftWait)
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": cannot read the launcher's answer: "+err.Error(), codeIO)
		return identity.ExitError
	}
	switch {
	case !ok:
		fmt.Fprintf(stdout, "%s: %s asked %s\n", run, name, rule)
		fmt.Fprintf(stdout, "Asked; the launcher applies it within a second (check: tego events %s --kind gap).\n", run)
		if note != "" {
			fmt.Fprintf(stdout, "Note: %s\n", record.LiveNoteShown(note))
		}
		return identity.ExitOK
	case why == record.GapLiveLiftRefused:
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s's launcher refused %s: %s; nothing was loosened", name, run, rule,
			refusedWords(c.Refused)), c.Refused)
		return identity.ExitFinding
	}
	word := map[string]string{"lift": "lifted", "grant": "granted", "restore": "restored"}[name]
	fmt.Fprintf(stdout, "%s: %s %s\n", run, word, rule)
	switch {
	case name == "restore":
		fmt.Fprintln(stdout, "Refused again from the agent's next action; what it already read or opened stays.")
	case !c.Until.IsZero():
		fmt.Fprintf(stdout, "In force now, %s; then it is refused again (live-lift-expired).\n", describeUntil(c.Until))
	default:
		fmt.Fprintf(stdout, "In force now, for the rest of the run (tego restore %s %s %s refuses it again).\n", run, kind, record.Printable(value))
	}
	// The note is what the launcher's line carries, which is what the record and the dashboard show.
	if n := record.LiveNoteShown(c.Note); n != "" && name != "restore" {
		fmt.Fprintf(stdout, "Note: %s\n", n)
	}
	if note != "" && c.Note != note && name != "restore" {
		message(stderr, "", 0, 0, "tego "+name+": the launcher's line does not carry the note that was signed, so the record "+
			"does not hold it; the lift itself is in force as asked", codeIO)
	}
	return identity.ExitOK
}

// refusedWords says a launcher's record.LiveRefused reason.
func refusedWords(r string) string {
	switch r {
	case record.LiveRefusedMAC:
		return "its MAC did not check under the run's key"
	case record.LiveRefusedOutsideFence:
		return "the entry is outside the run's fence"
	case record.LiveRefusedLocked:
		return "the run is Locked"
	case record.LiveRefusedUntil:
		return "its time limit had already passed"
	}
	return "reason " + record.Printable(r)
}

// fenceWhys are the launcher's lines that answer a lift or a restore.
var fenceWhys = []string{record.GapLiveRuleLifted, record.GapLiveLiftRefused, record.GapLiveRuleRestored}

// ledgerEnd is the length of the run's ledger in dir now (0 when it cannot be read): the launcher's answer to a change
// written after this is appended past it, so the wait reads only what follows.
func ledgerEnd(dir string) int64 {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return 0
	}
	defer func() { _ = rd.Close() }() // read-only
	n, err := rd.Size()
	if err != nil {
		return 0
	}
	return n
}

// awaitFenceLine reads the run's ledger in dir from byte off, as tego events reads it, until a launcher's gap line
// answering the change numbered serial appears (fenceWhys) or wait passes; ok false when none did. Reading on from off
// keeps each poll to the lines appended since the change, however long the run's ledger is.
func awaitFenceLine(ctx context.Context, dir string, serial uint64, off int64, wait time.Duration) (why string, c record.LiveBlockChange, ok bool, err error) {
	deadline := time.Now().Add(wait)
	for {
		if why, c, ok, err = findFenceLine(dir, serial, off); err != nil || ok {
			return why, c, ok, err
		}
		if !time.Now().Before(deadline) {
			return "", c, false, nil
		}
		select {
		case <-ctx.Done():
			return "", c, false, nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// findFenceLine is the launcher's gap line answering the change numbered serial,
// if the ledger in dir holds one at or after byte off. Every reread line is decoded
// before filtering; an unreadable or refused line returns its reason.
func findFenceLine(dir string, serial uint64, off int64) (string, record.LiveBlockChange, bool, error) {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return "", record.LiveBlockChange{}, false, err
	}
	defer func() { _ = rd.Close() }() // read-only
	for line, err := range rd.LinesFrom(off) {
		if err != nil {
			return "", record.LiveBlockChange{}, false, err
		}
		e, err := record.Decode(line)
		if err != nil {
			return "", record.LiveBlockChange{}, false, fmt.Errorf("ledger line after byte %d: %w", off, err)
		}
		if e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			return "", record.LiveBlockChange{}, false, fmt.Errorf("ledger gap after byte %d: %w", off, err)
		}
		if p.What != record.GapEnforce || p.LiveBlock == nil || p.LiveBlock.Serial != serial || !slices.Contains(fenceWhys, p.Why) {
			continue
		}
		return p.Why, *p.LiveBlock, true, nil
	}
	return "", record.LiveBlockChange{}, false, nil
}
