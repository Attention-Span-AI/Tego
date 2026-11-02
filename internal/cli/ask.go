// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() {
	register(cmdAsk)
	register(cmdApprove)
	register(cmdDeny)
	register(cmdAlternate)
}

// cmdAsk is `tego ask [run] [ask_id] [--json]`. With no argument it lists the pending asks of every running run under
// the ledger root, one line each led by its run id, so a person answering in a terminal never has to find the run
// first. With one ask id (q-...) it shows that request from whichever running run holds it; with a run id, whole or
// abbreviated (runIDUnder), that run's pending asks; with both, that request.
func cmdAsk() Command {
	var asJSON bool
	return Command{Name: "ask", Summary: "list or inspect pending human approvals (no argument: every running run)", Usage: "[run] [ask_id] [--json]", Flags: func(f *flag.FlagSet) { f.BoolVar(&asJSON, "json", false, "one JSON object") }, Run: func(ctx context.Context, f *flag.FlagSet, out, errs io.Writer) int {
		switch {
		case f.NArg() == 0:
			return runAskAll(ctx, asJSON, out, errs)
		case f.NArg() == 1 && ask.ValidID(f.Arg(0)):
			return runAskByID(ctx, "ask", f.Arg(0), false, false, asJSON, "", out, errs)
		case f.NArg() == 1 && (strings.HasPrefix(f.Arg(0), "q-") || runIDArg(f.Arg(0)) != nil):
			// One argument is either kind (QG-11): calling it only "not a run id" hid that an ask id works alone. One
			// that begins q- is an ask id mistyped, never taken for the end of a run id ("q-" and six more could be).
			message(errs, "", 0, 0, fmt.Sprintf("tego ask: %q is neither a run id (r-…) nor an ask id (q-…); "+
				"tego ask alone lists every running run's asks", f.Arg(0)), codeUsage)
			return identity.ExitUsage
		case f.NArg() > 2:
			message(errs, "", 0, 0, "tego ask: at most a run id and an ask id; tego ask alone lists every running run's asks", codeUsage)
			return identity.ExitUsage
		}
		return runAskCommand(ctx, "ask", f.Arg(0), f.Arg(1), false, false, asJSON, "", out, errs)
	}}
}

func cmdApprove() Command { return cmdAnswer("approve", true) }
func cmdDeny() Command    { return cmdAnswer("deny", false) }
func cmdAnswer(name string, approve bool) Command {
	var asJSON, always bool
	return Command{Name: name, Summary: name + " one pending held operation", Usage: "[run] <ask_id> [--always] [--json]", Flags: func(f *flag.FlagSet) {
		f.BoolVar(&asJSON, "json", false, "one JSON object")
		f.BoolVar(&always, "always", false, "also "+name+" every later request for the same operation, rule and exact target in this run")
	}, Run: func(ctx context.Context, f *flag.FlagSet, out, errs io.Writer) int {
		switch {
		case f.NArg() == 1 && ask.ValidID(f.Arg(0)):
			return runAskByID(ctx, name, f.Arg(0), approve, always, asJSON, "", out, errs)
		case f.NArg() != 2:
			message(errs, "", 0, 0, "tego "+name+": an ask id (q- and 32 hex digits), or a run id and an ask id; tego ask lists the pending ones", codeUsage)
			return identity.ExitUsage
		}
		return runAskCommand(ctx, name, f.Arg(0), f.Arg(1), approve, always, asJSON, "", out, errs)
	}}
}

// cmdAlternate is `tego alternate <run> <ask_id> --file <path> [--always] [--json]` (ADR 0057): the third answer to
// a held file open. The agent's open gets a descriptor of the named file in place of the one it asked for. This
// command opens the file itself, now, with no symbolic link anywhere on the way (ask.OpenAlternateFile), and passes
// that descriptor to the run's broker, so the file delivered is the one the person named, whatever the path names
// later; the supervisor checks and reopens that descriptor as the agent (SEMANTICS §6): read-only for a held read,
// with the agent's write flags for a held write, never a file in tego's own state or one the contract protects. A
// relative path is taken from this command's directory; the file must exist.
func cmdAlternate() Command {
	var asJSON, always bool
	var file string
	return Command{Name: "alternate", Summary: "answer one pending held file open with another file", Usage: "[run] <ask_id> --file <path> [--always] [--json]", Flags: func(f *flag.FlagSet) {
		f.StringVar(&file, "file", "", "the existing regular file the agent's open gets in place of the one it asked for")
		f.BoolVar(&asJSON, "json", false, "one JSON object")
		f.BoolVar(&always, "always", false, "also give the same file to every later request for the same operation, rule and exact target in this run")
	}, Run: func(ctx context.Context, f *flag.FlagSet, out, errs io.Writer) int {
		byID := f.NArg() == 1 && ask.ValidID(f.Arg(0))
		if (f.NArg() != 2 && !byID) || file == "" {
			message(errs, "", 0, 0, "tego alternate: an ask id, or a run id and an ask id, and --file", codeUsage)
			return identity.ExitUsage
		}
		if len(file) > ask.MaxAlternate || !ask.ValidAlternate(filepath.Join("/", file)) {
			message(errs, "", 0, 0, fmt.Sprintf("tego alternate: --file %q: name a file by a path of at most %d bytes with no control character", file, ask.MaxAlternate), codeUsage)
			return identity.ExitUsage
		}
		if byID {
			return runAskByID(ctx, "alternate", f.Arg(0), false, always, asJSON, file, out, errs)
		}
		return runAskCommand(ctx, "alternate", f.Arg(0), f.Arg(1), false, always, asJSON, file, out, errs)
	}}
}

// runAskCommand is ask, approve, deny or alternate given a run, whole id or abbreviated (runIDUnder): its pending
// asks, or the one ask id names. The arguments are checked before the machine config is read; the abbreviation is
// expanded under the ledger root it names, and everything after it, the lines printed included, uses the whole id.
func runAskCommand(ctx context.Context, name, ref, id string, approve, always, asJSON bool, alternate string, out, errs io.Writer) int {
	if err := runIDArg(ref); err != nil {
		message(errs, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
		return identity.ExitUsage
	}
	if (id == "" && name != "ask") || (id != "" && !ask.ValidID(id)) {
		message(errs, "", 0, 0, fmt.Sprintf("tego %s: %q is not an ask id (q- and 32 hex digits); tego ask %s lists the run's pending asks", name, id, ref), codeUsage)
		return identity.ExitUsage
	}
	root, code := askRoot(name, errs)
	if code != identity.ExitOK {
		return code
	}
	runID, err := runIDUnder(ref, root)
	if err != nil {
		return runRefFailed(errs, name, err) // R25: a usage error, or the root's errno, 125 [io]
	}
	dir := filepath.Join(root, runID)
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			message(errs, "", 0, 0, fmt.Sprintf("tego %s: %s: %v under %s; %s", name, runID, errRunNotFound, root, listRunsHint), codeUsage)
			return identity.ExitUsage
		}
		message(errs, "", 0, 0, "tego "+name+": "+err.Error(), readCode(err))
		return identity.ExitError
	}
	return askAt(ctx, name, runID, dir, id, approve, always, asJSON, alternate, out, errs)
}

// askRoot is the ledger root the ask commands read, from the machine config as every run command loads it.
func askRoot(name string, errs io.Writer) (string, int) {
	m, diagnostics, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(errs, diagnostics)
	if err != nil {
		message(errs, "", 0, 0, "tego "+name+": machine config: "+err.Error(), identity.CodeConfigUntrusted)
		return "", identity.ExitError
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		message(errs, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	return root, identity.ExitOK
}

// runAskAll is `tego ask` with no argument: every running run's pending asks, newest run first.
func runAskAll(ctx context.Context, asJSON bool, out, errs io.Writer) int {
	root, code := askRoot("ask", errs)
	if code != identity.ExitOK {
		return code
	}
	return askAcross(ctx, root, asJSON, out, errs)
}

// runAskByID is ask, approve, deny or alternate given only an ask id: the run is the running one whose broker holds
// it (findAsk); the exchange is then askAt's, exactly as with the run id given.
func runAskByID(ctx context.Context, name, id string, approve, always, asJSON bool, alternate string, out, errs io.Writer) int {
	root, code := askRoot(name, errs)
	if code != identity.ExitOK {
		return code
	}
	return askByIDUnder(ctx, root, name, id, approve, always, asJSON, alternate, out, errs)
}

// askByIDUnder is runAskByID under the ledger root root.
func askByIDUnder(ctx context.Context, root, name, id string, approve, always, asJSON bool, alternate string, out, errs io.Writer) int {
	runID, dir, err := findAsk(ctx, root, id)
	if err != nil {
		message(errs, "", 0, 0, "tego "+name+": "+err.Error(), readCode(err))
		return identity.ExitError
	}
	if runID == "" {
		message(errs, "", 0, 0, fmt.Sprintf("tego %s: no running run under %s holds ask %s (it may have been answered, "+
			"timed out, or its run ended); tego ask lists the pending ones", name, root, id), codeNotFound)
		return identity.ExitFinding
	}
	return askAt(ctx, name, runID, dir, id, approve, always, asJSON, alternate, out, errs)
}

// listRunsHint is the next step after a run id that names no run.
const listRunsHint = "tego status --all lists the runs"

// runningRuns is every run under root whose lock a live launcher holds, newest first. A run whose lock cannot be
// probed is left out: the ask commands reach a broker only through a verified launcher (askclient.Launcher).
func runningRuns(root string) ([]string, error) {
	ids, err := runIDsNewestFirst(root)
	if err != nil {
		return nil, err
	}
	var live []string
	for _, id := range ids {
		if held, _, err := runlock.ProbeLock(filepath.Join(root, id)); err == nil && held {
			live = append(live, id)
		}
	}
	return live, nil
}

// findAsk is the running run under root whose broker holds ask id, "" when none does. Each broker is reached as
// `tego ask <run> <id>` reaches it, through the run's verified launcher and the broker's own peer check, so finding a
// run by its ask id reaches no broker the caller could not already reach by the run id. An ask id is 128 random
// bits, so at most one run holds a given one.
func findAsk(ctx context.Context, root, id string) (runID, dir string, err error) {
	runs, err := runningRuns(root)
	if err != nil {
		return "", "", err
	}
	for _, r := range runs {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		d := filepath.Join(root, r)
		target, err := askclient.Launcher(d)
		if err != nil {
			continue // ended between the probe and now, or not one this caller can reach
		}
		_, err = ask.DetailFor(ctx, d, target.PID(), id)
		_ = target.Close() // askAt verifies the launcher again for the exchange itself
		if err == nil {
			return r, d, nil
		}
	}
	return "", "", nil
}

// askPending is one running run's pending asks in `tego ask --json` with no run.
type askPending struct {
	Run     string        `json:"run"`
	Pending []ask.Summary `json:"pending"`
}

// noAskSocket reports whether err says the run directory serves no ask socket: a run whose contract has no ask
// rule, or a watched run, never binds one, and a run that ended took its socket (or its directory) with it. Such a
// run holds no asks; it is not a failure to reach a broker.
func noAskSocket(err error) bool {
	return errors.Is(err, askclient.ErrNoBroker) || errors.Is(err, os.ErrNotExist)
}

// askAcross lists the pending asks of every running run under root: one line per ask, "<run> <ask_id> <hold> <op>
// <target>", or one line saying there are none. A run with no ask socket (no ask rule, a watched run) holds none and
// is passed over. A run whose broker is there but cannot be reached (a refused peer check, a protocol error, a
// timeout) is named on stderr and the listing goes on; the command then exits 125, so a script never takes a partial
// list for the whole.
func askAcross(ctx context.Context, root string, asJSON bool, out, errs io.Writer) int {
	runs, err := runningRuns(root)
	if err != nil {
		message(errs, "", 0, 0, "tego ask: "+err.Error(), readCode(err))
		return identity.ExitError
	}
	all := []askPending{}
	failed := false
	brokers := 0 // running runs whose broker answered: the ones that could hold an ask
	for _, r := range runs {
		d := filepath.Join(root, r)
		target, err := askclient.Launcher(d)
		var pending []ask.Summary
		if err == nil {
			pending, err = ask.ListFor(ctx, d, target.PID())
			_ = target.Close()
		}
		if noAskSocket(err) {
			continue // it takes no approvals, or it ended after the probe
		}
		if err != nil {
			message(errs, "", 0, 0, fmt.Sprintf("tego ask: %s: %v", r, err), codeIO)
			failed = true
			continue
		}
		brokers++
		if len(pending) > 0 {
			all = append(all, askPending{Run: r, Pending: pending})
		}
	}
	var werr error
	switch {
	case asJSON:
		werr = json.NewEncoder(out).Encode(struct {
			Root string       `json:"root"`
			Runs []askPending `json:"runs"`
		}{root, all})
	case len(all) == 0 && brokers == 0:
		_, werr = fmt.Fprintf(out, "no pending approvals: no running run under %s takes approvals\n", root)
	case len(all) == 0:
		_, werr = fmt.Fprintf(out, "no pending approvals in the %d running run(s) under %s that take approvals\n", brokers, root)
	default:
		for _, p := range all {
			for _, request := range p.Pending {
				suffix := ""
				if request.TargetTruncated {
					suffix = " (truncated; tego ask " + request.AskID + " shows the whole target)"
				}
				if _, werr = fmt.Fprintf(out, "%s %s %s %s %s%s%s\n", p.Run, request.AskID, record.Printable(request.Hold),
					record.Printable(request.Op), record.Printable(request.Target), askTarget2(request.Request), suffix); werr != nil {
					break
				}
			}
		}
		if werr == nil {
			_, werr = fmt.Fprintln(out, "answer one with: tego approve <ask_id>, or tego deny <ask_id>")
		}
	}
	if werr != nil || failed {
		return identity.ExitError
	}
	return identity.ExitOK
}

func askAt(ctx context.Context, name, runID, dir, id string, approve, always, asJSON bool, alternate string, out, errs io.Writer) int {
	target, err := askclient.Launcher(dir) // the verified launcher pidfd stays open through the exchange
	if errors.Is(err, askclient.ErrNoBroker) {
		// No live launcher holds the run's lock: the run has ended, and every request it held ended with it. Asked
		// about one request, say what became of it from the ledger (QG-11).
		if name == "ask" && id != "" {
			if found, werr := writeRecordedAsk(runID, dir, id, true, asJSON, out); werr != nil {
				return identity.ExitError
			} else if found {
				return identity.ExitOK
			}
		}
		message(errs, "", 0, 0, fmt.Sprintf("tego %s: %s has ended; nothing waits for an answer", name, runID), codeNotRunning)
		return identity.ExitFinding
	}
	if err != nil {
		message(errs, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = target.Close() }()
	if name == "ask" {
		if id != "" {
			request, e := ask.DetailFor(ctx, dir, target.PID(), id)
			err = e
			if errors.Is(err, ask.ErrNotPending) {
				// Answered or timed out already: say how, from the ledger (QG-11).
				found, werr := writeRecordedAsk(runID, dir, id, false, asJSON, out)
				if werr != nil {
					return identity.ExitError
				}
				if found {
					return identity.ExitOK
				}
			}
			if err == nil {
				if asJSON {
					err = json.NewEncoder(out).Encode(struct {
						Run     string      `json:"run"`
						Request ask.Request `json:"request"`
					}{runID, request})
				} else {
					_, err = fmt.Fprintf(out, "%s %s %s %s%s\n", request.AskID, record.Printable(request.Hold), record.Printable(request.Op), record.Printable(request.Target), askTarget2(request))
				}
			}
		} else {
			pending, e := ask.ListFor(ctx, dir, target.PID())
			err = e
			if errors.Is(err, os.ErrNotExist) && !asJSON {
				// No ask socket: the run takes no approvals. Say why, rather than "no pending approvals", which reads
				// as a run that could hold one (QG-11).
				_, werr := fmt.Fprintln(out, noApprovals(runID, dir))
				if werr != nil {
					return identity.ExitError
				}
				return identity.ExitOK
			}
			if errors.Is(err, os.ErrNotExist) {
				err = nil // no ask socket: the run takes no approvals, so none is pending
			}
			if err == nil {
				if pending == nil {
					pending = []ask.Summary{}
				}
				switch {
				case asJSON:
					err = json.NewEncoder(out).Encode(struct {
						Run     string        `json:"run"`
						Pending []ask.Summary `json:"pending"`
					}{runID, pending})
				case len(pending) == 0:
					_, err = fmt.Fprintf(out, "%s: no pending approvals\n", runID)
				default:
					for _, request := range pending {
						suffix := ""
						if request.TargetTruncated {
							suffix = " (truncated; inspect ask_id for full target)"
						}
						if _, err = fmt.Fprintf(out, "%s %s %s %s%s%s\n", request.AskID, record.Printable(request.Hold), record.Printable(request.Op), record.Printable(request.Target), askTarget2(request.Request), suffix); err != nil {
							break
						}
					}
				}
			}
		}
	} else {
		var decision ask.Decision
		var e error
		if alternate != "" {
			// The file is opened only now, after every account and run check passed, so its identity is fixed at
			// the last moment before the answer goes, and held by descriptor from here on.
			alt, oe := ask.OpenAlternateFile(alternate)
			if oe != nil {
				code, exit := codeIO, identity.ExitError
				if errors.Is(oe, ask.ErrAlternateSymlink) {
					code, exit = codeUsage, identity.ExitUsage
				}
				message(errs, "", 0, 0, "tego "+name+": --file: "+record.Printable(oe.Error())+"; the request is still pending", code)
				return exit
			}
			defer func() { _ = alt.Close() }()
			decision, e = ask.AlternateFor(ctx, dir, target.PID(), id, alt, always)
		} else {
			decision, e = ask.AnswerFor(ctx, dir, target.PID(), id, approve, always)
		}
		err = e
		if err == nil {
			word := answerWord(decision, always)
			if alternate != "" {
				word = alternateWord(decision, always)
			}
			if asJSON {
				err = json.NewEncoder(out).Encode(struct {
					Run      string       `json:"run"`
					Decision ask.Decision `json:"decision"`
				}{runID, decision})
			} else {
				_, err = fmt.Fprintf(out, "%s: %s\n", decision.AskID, word)
			}
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		// The run is live but serves no ask socket: its contract has no ask rule, or it is a watched run.
		message(errs, "", 0, 0, fmt.Sprintf("tego %s: %s; nothing waits for an answer", name, noApprovals(runID, dir)), codeNotFound)
		return identity.ExitFinding
	}
	if err != nil {
		code := codeIO
		exit := identity.ExitError
		if errors.Is(err, ask.ErrProtocol) {
			code = codeUsage
			exit = identity.ExitUsage
		}
		switch {
		case errors.Is(err, ask.ErrNotRememberable) || errors.Is(err, ask.ErrStandingFull):
			// The request is still held: the same command without --always answers it once.
			err = fmt.Errorf("%w; it is still pending, so answer it without --always", err)
		case errors.Is(err, ask.ErrStandingBusy):
			err = fmt.Errorf("%w; it is still pending: look again in a moment, or answer it without --always", err)
		case errors.Is(err, ask.ErrBadAlternate):
			// The supervisor's reason follows the sentinel's text; the request is still held.
			err = fmt.Errorf("%w; it is still pending: name another file, or approve or deny it", err)
		case errors.Is(err, ask.ErrNoAlternate):
			err = fmt.Errorf("%w (only a held file open takes one); it is still pending: approve or deny it", err)
		case errors.Is(err, ask.ErrUnauthorized):
			// Either end refused the other: the broker serves a person only (ADR 0008, amended 2026-10-25), and this
			// client the run's own broker only (askclient.Call). Neither changes what the run holds.
			err = fmt.Errorf("%w: the run's broker serves only its owner or root, from outside every run and adoption and in "+
				"its own cgroup namespace (not from inside a run, a watched or adopted agent, or a container), and this "+
				"client only the run's own broker; what the run holds is still pending", err)
		}
		message(errs, "", 0, 0, "tego "+name+": "+err.Error(), code)
		return exit
	}
	return identity.ExitOK
}

// endedFirst ends the word for an --always that stands although the request it answered ended (was cancelled) after
// the answer line was recorded and before its operation was done.
const endedFirst = "this request itself ended after your answer was recorded, so its operation was refused"

// alternateWord is answerWord for `tego alternate`: what became of an alternate, in words of what happened. Only a
// decision that names the alternate gave it; one that does not was overtaken (a timeout, a shutdown, a ledger that
// refused its line) and gave nothing, the operation refused.
func alternateWord(d ask.Decision, asked bool) string {
	switch {
	case d.Alternate == "" && d.Always:
		return "recorded, and gives the file for every later request for the same operation, rule and target in this run; " + endedFirst
	case d.Alternate == "" && d.Reason == ask.ReasonTimeout:
		return "not given: the hold timed out first, so the operation was refused"
	case d.Alternate == "":
		return "not given: the answer could not be kept (the run ended, was cancelled, or its ledger refused the line), so the operation was refused"
	}
	word := "gave " + record.Printable(d.Alternate) + " in place of the file the agent asked for"
	switch {
	case d.Always:
		word += ", and gives it again for every later request for the same operation, rule and target in this run"
	case asked:
		word += ", for this request only: the answer could not be made to stand for later requests"
	}
	return word
}

// answerWord says what became of an answer in words of what happened, not of what was asked for: an approval that
// lost to the timeout, to a shutdown or to a ledger that refused its line approved nothing, and is not a person's
// "denied" either. A standing answer is claimed only for a decision that is one (the broker clears Always on a
// decision that did not stand), and an --always that did not stand says so: the answer then applied once only. An
// --always whose line was recorded stands even when its own request ended just after (the broker keeps Always on
// that refused decision), and the word says both.
func answerWord(d ask.Decision, asked bool) string {
	word := "approved"
	switch {
	case d.Approved:
	case d.Reason == ask.ReasonDenied:
		word = "denied"
	case d.Always:
		return "recorded, and stands for every later request for the same operation, rule and target in this run; " + endedFirst
	case d.Reason == ask.ReasonTimeout:
		return "not approved: the hold timed out first, so the operation was refused"
	default:
		return "not approved: the answer could not be kept (the run ended, was cancelled, or its ledger refused the line), so the operation was refused"
	}
	switch {
	case d.Always:
		word += ", and every later request for the same operation, rule and target in this run"
	case asked:
		word += ", for this request only: the answer could not be made to stand for later requests"
	}
	return word
}

// askTarget2 is a held mutation's second name as the person reads it after the first (ADR 0047): " -> " and a rename's or
// a link's new name, or a symlink's stored target; nothing for every other request.
func askTarget2(r ask.Request) string {
	if r.Target2 == "" {
		return ""
	}
	return " -> " + record.Printable(r.Target2)
}
