// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// askRecord is what a run's ledger holds of one ask (QG-11): the ask line and, once it was answered, the answer line,
// for `tego ask <run> <ask_id>` after the request stopped waiting.
type askRecord struct {
	// AskSeq is the ask line's seq, 0 when the ledger holds none for the id.
	AskSeq uint64 `json:"ask_seq,omitempty"`
	// AnswerSeq is the answer line's seq, 0 while there is none; the fields below are that line's.
	AnswerSeq    uint64  `json:"answer_seq,omitempty"`
	Approved     bool    `json:"approved"`
	By           string  `json:"by,omitempty"`
	AfterS       float64 `json:"after_s,omitempty"`
	AnswerReason string  `json:"answer_reason,omitempty"`
	Alternate    string  `json:"alternate,omitempty"`
}

// recordedAsk reads ask id's lines from the run's ledger in dir. A ledger that cannot be read, or holds no line for the
// id, gives the zero record. Only lines naming the id are decoded.
func recordedAsk(dir, id string) askRecord {
	var out askRecord
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return out
	}
	defer func() { _ = rd.Close() }() // read-only
	for line, err := range rd.Lines() {
		if err != nil {
			break
		}
		if !bytes.Contains(line, []byte(id)) {
			continue
		}
		e, err := record.Decode(line)
		if err != nil || (e.Kind != record.KindAsk && e.Kind != record.KindAnswer) {
			continue
		}
		var p struct {
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
			out.AskSeq = e.Seq
			continue
		}
		out.AnswerSeq, out.Approved, out.By, out.AfterS, out.AnswerReason, out.Alternate =
			e.Seq, p.Approved, p.By, p.AfterS, p.AnswerReason, p.Alternate
	}
	return out
}

// words is the record in a sentence: "denied by uid:1000 after 77 ms, line #18", or, for an ask with no answer line,
// when it was asked and, with ended, that its run ended first. "" for an id the ledger does not hold.
func (a askRecord) words(ended bool) string {
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
	if a.By != "" {
		s += " by " + record.Printable(a.By)
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
	if rec.AskSeq == 0 && rec.AnswerSeq == 0 {
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

// noApprovals says why a live run serves no ask socket, in a sentence led by its id: a watch run holds nothing for an
// answer (tego watch records only), and an enforced run whose contract has no ask rule never binds one.
func noApprovals(runID, dir string) string {
	if startFacts(dir).Observe {
		return runID + " is a watch run, and a watch run takes no approvals: tego watch records what the agent does and holds nothing for an answer"
	}
	return runID + " takes no approvals: its contract has no ask rule"
}
