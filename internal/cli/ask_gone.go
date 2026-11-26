// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The end of a run takes its broker with it: the answer that lets the held operation finish ends the run, the run's
// broker closes its connections and removes its socket, and only then does the launcher release the run's lock and
// exit. A command that reaches the broker in that interval meets a socket that is gone, or a connection closed under
// it, while the run still counts as live. What it says then comes from the run's record at that moment (what the
// ledger holds for the ask, whether the run's lock is still held) and from nothing it only supposes: an answer is
// never reported as delivered unless the ledger holds it, and "no ask rule" is never said of a run whose start record
// says it served approvals.

// askLauncherAgain is the second look at the run's launcher that a command whose broker went away takes, a variable
// only so a test can end the run between the dial and this look without waiting for it.
var askLauncherAgain = askclient.Launcher

// socketAbsent says err is a dial that found no broker to connect to: the socket is not there (ENOENT) or no one
// listens on it (ECONNREFUSED). Nothing was sent.
func socketAbsent(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// brokerWentAway says err is the run's broker not being there for the exchange: its socket is absent, or it closed the
// connection under the call (a reset, a broken pipe, a close with no reply, which the client reads as io.EOF). It is no protocol violation and no
// refusal: the broker said nothing.
func brokerWentAway(err error) bool {
	return socketAbsent(err) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, io.EOF)
}

// lostBroker is what a second look at a run whose broker went away finds. The launcher is looked at first and the
// ledger second, so a ledger read after the lock was seen free is the run's last.
type lostBroker struct {
	ended bool      // no live launcher holds the run's lock
	rec   askRecord // the ledger's lines for the ask, zero for no id
}

func lookAgain(dir, id string) lostBroker {
	var l lostBroker
	switch target, err := askLauncherAgain(dir); {
	case err == nil:
		_ = target.Close()
	case errors.Is(err, askclient.ErrNoBroker):
		l.ended = true
	}
	if id != "" {
		l.rec = recordedAsk(dir, id)
	}
	return l
}

// lostWords is what a command whose broker went away reports: the diagnostic's text and code and the exit status.
type lostWords struct {
	text, code string
	exit       int
}

// settleLost reports a command (name) whose exchange about ask id failed with cause, the broker having gone away, from
// the record. The answer the ledger holds for the ask comes first, since it says what became of the request; then
// the run's end; then what is left of the run's start record. Where none of them proves what happened, the report is a
// failure that says so, never an answer delivered and never a refusal the record does not hold.
func settleLost(name, runID, dir, id string, cause error) lostWords {
	l := lookAgain(dir, id)
	switch {
	case id != "" && l.rec.AnswerSeq != 0 && l.rec.answeredBy(os.Geteuid(), os.Getpid()):
		// This command's own answer is the ledger's; only its reply was lost with the connection.
		return lostWords{fmt.Sprintf("tego %s: your answer was recorded on line #%d (%s), but the run's broker closed the connection before its reply reached "+
			"this command", name, l.rec.AnswerSeq, l.rec.pairedWords(false)), codeIO, identity.ExitError}
	case id != "" && l.rec.AnswerSeq != 0:
		// Another answer (or the timeout, a cancellation) came first: the loser of the race is told what a loser is told
		// when the broker is there to say it.
		return lostWords{"tego " + name + ": " + ask.ErrNotPending.Error(), codeIO, identity.ExitError}
	case l.ended:
		return lostWords{fmt.Sprintf("tego %s: %s has ended; nothing waits for an answer", name, runID), codeNotRunning, identity.ExitFinding}
	case socketAbsent(cause) && id != "" && l.rec.AskSeq != 0 && name == "ask":
		return lostWords{fmt.Sprintf("tego ask: %s's ask socket is not there now, so %s cannot be shown; the ledger holds no answer to it yet; the run has ended or is ending (%s)", runID, id, endedWords(runID)),
			codeIO, identity.ExitError}
	case socketAbsent(cause) && id != "" && l.rec.AskSeq != 0:
		return lostWords{fmt.Sprintf("tego %s: %s's ask socket is not there now, so this answer was not delivered; the ledger holds no answer to %s yet, "+
			"and tego ask %s shows whether it can still be answered", name, runID, id, runID), codeIO, identity.ExitError}
	case socketAbsent(cause):
		words, none := noApprovalsWords(runID, dir)
		switch {
		case none:
			words += "; nothing waits for an answer"
		case id != "":
			words += fmt.Sprintf("; its ledger shows no ask %s, so nothing was answered", id)
		}
		return lostWords{"tego " + name + ": " + words, codeNotFound, identity.ExitFinding}
	}
	if name == "ask" {
		return lostWords{fmt.Sprintf("tego ask: the run's broker closed the connection with no reply, so nothing is shown of %s; "+
			"look again, or tego status %s says whether the run is still running", runID, runID), codeIO, identity.ExitError}
	}
	return lostWords{fmt.Sprintf("tego %s: the run's broker closed the connection with no reply, so this answer may not have been delivered: "+
		"the request may still be pending, and tego ask %s shows whether it is", name, runID), codeIO, identity.ExitError}
}
