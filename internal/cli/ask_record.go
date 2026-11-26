// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/askpair"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// askRecord is what a run's ledger holds of one ask (QG-11): the ask line and, once it was answered, the answer line,
// for `tego ask <run> <ask_id>` after the request stopped waiting.
type askRecord struct {
	record.AnswerAuthority
	// AskSeq is the ask line's seq, 0 when the ledger holds none for the id.
	AskSeq uint64 `json:"ask_seq,omitempty"`
	// AnswerSeq is the answer line's seq, 0 while there is none; the fields below are that line's.
	AnswerSeq    uint64  `json:"answer_seq,omitempty"`
	Approved     bool    `json:"approved"`
	By           string  `json:"by,omitempty"`
	AfterS       float64 `json:"after_s,omitempty"`
	AnswerReason string  `json:"answer_reason,omitempty"`
	Alternate    string  `json:"alternate,omitempty"`
	// Repeated counts the ask lines that repeated this id and Unpaired the answer lines that pair with no ask (askpair):
	// malformed lines, which are no second question and no answer.
	Repeated int `json:"repeated_asks,omitempty"`
	Unpaired int `json:"unpaired_answers,omitempty"`
}

// recordedAsk reads ask id's lines from the run's ledger in dir. A ledger that cannot be read, or holds no line for the
// id, gives the zero record. The run_start revision and lines naming the id are decoded.
func recordedAsk(dir, id string) askRecord {
	var out askRecord
	minor, floor := 0, false
	book := askpair.NewBook[struct{}](0, 0) // the one pairing of an ask with its answer
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return out
	}
	defer func() { _ = rd.Close() }() // read-only
	for line, err := range rd.Lines() {
		if err != nil {
			break
		}
		if !bytes.Contains(line, []byte(id)) && !bytes.Contains(line, []byte(`"run_start"`)) {
			continue
		}
		e, err := record.Decode(line)
		if err != nil {
			continue
		}
		if e.Kind == record.KindRunStart {
			minor, _ = e.RunStartMinor()                                     // malformed or absent revision grants no attribution
			floor = record.ValidatedLocalApprovalAuthority(e.Payload) != nil // the root-only floor: an answer is root's only under it
			continue
		}
		if e.Kind != record.KindAsk && e.Kind != record.KindAnswer {
			continue
		}
		var p struct {
			record.AnswerAuthority
			AskID        string  `json:"ask_id"`
			Approved     bool    `json:"approved"`
			By           string  `json:"by"`
			AfterS       float64 `json:"after_s"`
			AnswerReason string  `json:"answer_reason"`
			Alternate    string  `json:"alternate"`
		}
		if e.DecodePayload(&p) != nil || p.AskID != id {
			continue
		}
		if e.Kind == record.KindAsk {
			if book.Ask(id, struct{}{}, 0) == askpair.Opened {
				out.AskSeq = e.Seq
			} else {
				out.Repeated++ // the first ask line opened the question
			}
			continue
		}
		if _, r := book.Answer(id); r != askpair.Paired {
			out.Unpaired++ // an answer with no open ask answers nothing
			continue
		}
		out.AnswerAuthority = record.AnswerAuthorityOf(e.Payload, minor, floor)
		out.AnswerSeq, out.Approved, out.By, out.AfterS, out.AnswerReason, out.Alternate =
			e.Seq, p.Approved, p.By, p.AfterS, p.AnswerReason, p.Alternate
	}
	return out
}

// words is the record in a sentence: "denied by uid:1000 after 77 ms, line #18", or, for an ask with no answer line,
// when it was asked and, with ended, that its run ended first. "" for an id the ledger does not hold.
func (a askRecord) words(ended bool) string {
	s := a.pairedWords(ended)
	if a.Repeated > 0 {
		s += "; " + askpair.RepeatedWords + ", and only its first line counts"
	}
	if a.Unpaired > 0 {
		s += "; " + askpair.UnpairedWords + ", and it is not counted as an answer"
	}
	return strings.TrimPrefix(s, "; ")
}

// pairedWords is words for the ask and the answer that pair, without the malformed lines.
func (a askRecord) pairedWords(ended bool) string {
	switch {
	case a.AnswerSeq == 0 && a.AskSeq == 0:
		return ""
	case a.AnswerSeq == 0 && ended:
		return fmt.Sprintf("asked on line #%d and never answered: its run ended while it waited, so the operation was refused", a.AskSeq)
	case a.AnswerSeq == 0:
		return fmt.Sprintf("asked on line #%d; its answer line is not in the ledger yet (tego events shows it once written)", a.AskSeq)
	}
	var what string
	switch {
	case a.Alternate != "":
		what = "answered with another file, " + record.Printable(a.Alternate) + ","
	case a.Approved:
		what = "approved"
		if a.Actor != nil {
			what = "approval recorded (operation completion is separate)"
		}
	case a.AnswerReason == ask.ReasonDenied:
		what = "denied"
	case a.AnswerReason == ask.ReasonTimeout:
		what = "timed out (refused)"
	case a.AnswerReason != "":
		what = "refused (" + record.Printable(a.AnswerReason) + ")"
	default:
		what = "not approved"
	}
	s := what
	if a.Actor != nil || a.SystemCause != "" {
		s += " by " + receipt.ApprovalIdentity(a.AnswerAuthority)
	} else if a.By != "" {
		s += " by " + record.Printable(askproto.ByWords(a.By))
	}
	return s + " after " + afterWords(a.AfterS) + fmt.Sprintf(", line #%d", a.AnswerSeq)
}

// afterWords is an answer's wait in plain units: milliseconds under ten seconds, seconds after.
func afterWords(s float64) string {
	if s < 10 {
		return fmt.Sprintf("%d ms", int64(math.Round(s*1000)))
	}
	return fmt.Sprintf("%.0f s", s)
}

// writeRecordedAsk prints what became of ask id when it no longer waits, from the run's ledger, and reports whether
// the ledger held it; ended says the run has ended. The text form is "<ask_id>: no longer waits: <words>"; --json is
// {"run","ask_id","recorded"}.
func writeRecordedAsk(runID, dir, id string, ended, asJSON bool, out io.Writer) (bool, error) {
	rec := recordedAsk(dir, id)
	if rec.AskSeq == 0 && rec.AnswerSeq == 0 && rec.Repeated == 0 && rec.Unpaired == 0 {
		return false, nil
	}
	if asJSON {
		return true, json.NewEncoder(out).Encode(struct {
			Run      string    `json:"run"`
			AskID    string    `json:"ask_id"`
			Recorded askRecord `json:"recorded"`
		}{runID, id, rec})
	}
	_, err := fmt.Fprintf(out, "%s: no longer waits: %s\n", id, rec.words(ended))
	return true, err
}

// answeredBy says the answer line this record holds is the one the process pid, running as uid, gave: the broker
// records an answer's "by" as "uid:<uid> pid:<pid>", then " always" or the dashboard's word.
func (a askRecord) answeredBy(uid, pid int) bool {
	who := fmt.Sprintf("uid:%d pid:%d", uid, pid)
	return a.AnswerSeq != 0 && (a.By == who || strings.HasPrefix(a.By, who+" "))
}

// startsServingApprovals reads what the run's start record says of its ask broker: serves is capabilities.ask, true
// for a run whose broker was available when it started; known is false when the start line cannot be read or carries
// no such capability, in which case nothing is said of the run's contract.
func startsServingApprovals(dir string) (serves, known bool) {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return false, false
	}
	defer func() { _ = rd.Close() }() // read-only
	for line, err := range rd.Lines() {
		if err != nil {
			return false, false
		}
		e, err := record.Decode(line)
		if err != nil || e.Kind != record.KindRunStart {
			return false, false
		}
		var p struct {
			Capabilities map[string]bool `json:"capabilities"`
		}
		if e.DecodePayload(&p) != nil {
			return false, false
		}
		serves, known = p.Capabilities["ask"]
		return serves, known
	}
	return false, false
}

// endedWords points a person at the run's record for what a run that ended, or is ending, did: its ask socket is gone
// and no request of it can be shown or answered.
func endedWords(runID string) string { return "tego events " + runID + " shows what it did" }

// noApprovalsWords says why a live run serves no ask socket, in a sentence led by its id; none is true for the two runs
// that hold nothing for an answer, a watch run (tego watch records only) and an enforced run whose start record says
// its broker was not available because its contract has no ask rule. A run whose start record says it served approvals
// has lost its socket since, which is not "no ask rule"; a run whose start record cannot be read is not said to have
// one either way.
func noApprovalsWords(runID, dir string) (words string, none bool) {
	if startFacts(dir).Observe {
		return runID + " is a watch run, and a watch run takes no approvals: tego watch records what the agent does and holds nothing for an answer", true
	}
	serves, known := startsServingApprovals(dir)
	switch {
	case known && !serves:
		return runID + " takes no approvals: its contract has no ask rule", true
	case known:
		return runID + " takes approvals, but its ask socket is not there now, so nothing can be answered: the run has ended or is ending (" + endedWords(runID) + ")", false
	}
	return runID + " has no ask socket now, and its start record does not say whether its contract has an ask rule", false
}
