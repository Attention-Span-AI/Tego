// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/linewords"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

// The line page's facts column (templates/evfacts.tmpl), built on ledgerview.Explain: the line in one sentence, the
// program that did it and the programs above it, when it came to the millisecond, the decision with the contract line
// it came from (rulesview.RuleSource, cached per run), the question it belongs to, every field of the line in words,
// and its place in the hash chain beside the run's (cached) chain verdict. Every value a person reads here is masked
// (linewords.Mask); the exact bytes are only in the closed raw fold and a masked field's own "show" fold. The page
// decides and writes nothing: it reads the ledger through ledgerview and the contract through rulesview.

// maxBlobDownload is the largest blob the line page serves as a download: far past any command line or body the
// writer moves to a blob, and small enough that one request never holds much memory.
const maxBlobDownload = 16 << 20

// factsView is the facts column's model; nil fields are sections the line has nothing for.
type factsView struct {
	// LV is the line explained; nil when it could not be (Err says why), and the page then shows the row's facts.
	LV  *ledgerview.LineView
	Err string
	// Steps are the programs from the run's root down to the one that wrote the line ("codex → bash → curl"):
	// LV.Chain reversed, then LV.Proc.
	Steps []procStep
	// MoreAbove is how many programs further up the chain Steps leaves out (maxAbove).
	MoreAbove int
	// ChainHead is the line above the chain: from the run's root down, or the nearest few of how many.
	ChainHead string
	// Logs is the Logs query for every line of this process in this run.
	Logs string
	// When.
	Local, UTC, Into, SincePrev string
	// Decision: Verdict and By in words; Rule the contract line the rule came from (Found); Reason and Errno in words;
	// Tier and Mechanism when the line or run names them.
	Verdict, By string
	Rule        rulesview.RuleOrigin
	// RuleKey is the line's rule key as the column shows it, the run's home written ~ and its working directory .
	// (runText); RuleKeyFull the key as the ledger has it, for the title, "" when RuleKey is the same.
	RuleKey, RuleKeyFull string
	RuleFound            bool
	RuleFile             string // Rule.File's base name
	Reason, ReasonKey    string
	Errno                string
	Tier, Mechanism      string
	// Ask is the question card, nil for a line that belongs to none.
	Ask *askCard
	// Chain is the run's chain verdict (ledgerview.VerifyRun, cached for ended runs) in words; ChainState its state.
	Chain, ChainState string
	// LineChain is this line's place against a break (lineChainWords); LineChainAt "before" or "here".
	LineChain, LineChainAt string
}

// maxAbove is how many programs above the line's own the chain shows; the Processes tab shows the whole tree.
const maxAbove = 6

// procStep is one program of the line's process chain.
type procStep struct {
	ledgerview.ProcRef
	// Self marks the program that wrote the line.
	Self bool
	// Path is ProcRef.Path masked; Label what the crumb says.
	Path, Label string
}

// askCard is the question the line belongs to, with the times of its ask and answer lines.
type askCard struct {
	*ledgerview.AskFacts
	AskedAt, AnsweredAt string
	// Outcome is the answer in words; Pending says no answer is in the record.
	Outcome string
	Pending bool
	// Rule is the rule key that asked, written as runText writes it; RuleFull the key as the ledger has it, for the
	// title, "" when Rule is the same.
	Rule, RuleFull string
}

// buildFacts explains line seq of rr for the page. It never fails the page: a line Explain cannot read leaves the
// facts the row holds.
func (s *Server) buildFacts(ctx context.Context, rr *ledgerview.Run, at *ledgerview.Event) *factsView {
	f := &factsView{}
	home := ledgerview.RunHome(rr)
	f.RuleKey, f.RuleKeyFull = shownKey(at.Rule, home, rr.Cwd)
	lv, err := ledgerview.Explain(s.cfg.Ledger, rr, at.Seq)
	if err != nil {
		f.Err = "Line unreadable · showing its row only"
		return f
	}
	f.LV = lv
	env := &lv.Envelope
	if lv.Proc != nil {
		for i := len(lv.Chain) - 1; i >= 0; i-- {
			f.Steps = append(f.Steps, stepOf(lv.Chain[i], false))
		}
		f.Steps = append(f.Steps, stepOf(*lv.Proc, true))
		if n := len(f.Steps) - (maxAbove + 1); n > 0 {
			// A deep tree (a shell loop, make) would print dozens of ancestors on one line (r9 QG-8): keep the
			// nearest ones and say how many more the Processes tab shows.
			f.MoreAbove, f.Steps = n, f.Steps[n:]
		}
		f.ChainHead = "The programs above it, from the run's root down"
		if f.MoreAbove > 0 {
			f.ChainHead = "The programs above it: the nearest " + strconv.Itoa(len(f.Steps)-1) + " of " + strconv.Itoa(len(f.Steps)-1+f.MoreAbove)
		}
	}
	if pid := env.PID; pid > 0 {
		f.Logs = "run:" + rr.ID + " pid:" + strconv.Itoa(pid)
	}

	if !env.TS.IsZero() {
		f.Local = env.TS.Local().Format("Mon 2 Jan 2006, 15:04:05.000 MST")
		f.UTC = env.TS.UTC().Format("2006-01-02 15:04:05.000000000 UTC")
	}
	if !rr.Start.IsZero() && env.SinceStart >= 0 {
		f.Into = linewords.Duration(env.SinceStart)
	}
	if env.Position > 1 && env.SincePrev >= 0 {
		f.SincePrev = msWords(env.SincePrev)
	}

	f.Verdict, f.By = decisionWords(at)
	if lv.Decision != "" {
		// A refusal a question ended in: a person's no, or no answer in time, never "Refused by a rule".
		f.Verdict, f.By = lv.Decision, lv.DecidedBy
	}
	if at.Rule != "" && at.Rule != "unmatched" {
		f.Rule, f.RuleFound = rulesview.RuleSource(ctx, s.cfg.Ledger, rr.ID, at.Rule,
			rulesview.Options{Machine: s.cfg.Machine, Anchor: s.cfg.Anchor, Profiles: s.cfg.Profiles, Run: rr})
		f.RuleFile = path.Base(f.Rule.File)
		f.Rule.Sentence = runText(f.Rule.Sentence, home, rr.Cwd)
	}
	f.By = runText(f.By, home, rr.Cwd)
	if at.Reason != "" {
		f.Reason, f.ReasonKey = reasonText(at.Reason), at.Reason
	}
	for _, fd := range lv.Fields {
		switch fd.Key {
		case "errno", "syscall_errno":
			if f.Errno == "" && fd.Raw != "0" {
				f.Errno = fd.Value
			}
		case "mechanism":
			f.Mechanism = fd.Value
		}
	}
	if t, ok := linewords.Tier(rr.Tier); ok {
		f.Tier = t
	} else {
		f.Tier = rr.Tier
	}

	if lv.Ask != nil {
		f.Ask = askCardOf(rr, lv.Ask)
	}
	c := ledgerview.VerifyRun(ctx, s.cfg.Ledger, rr.ID, s.cfg.Anchor, rr)
	f.Chain, f.ChainState = ledgerview.ChainWords(c), c.State
	f.LineChain, f.LineChainAt = lineChainWords(c, at.Seq)
	return f
}

// runText is s with the run's home written ~ and its working directory . wherever s names them, in full or from the
// dashboard user's home: the line page's left column (Decided by, Rule, The question) then says ~/.config/telemetry/
// as its headline, the Act panel and Logs do (ledgerview.RunHome), never ~/<checkout>/…/with/home/.config/telemetry/
// beside it; one "~" on the page, never two. Display only: titles and the raw fold keep the ledger's text.
func runText(s, home, cwd string) string {
	if s == "" {
		return s
	}
	s = shortener{cwd: cwd, home: home}.text(s)
	// The dashboard user's ~/ form of each, the longer (inner) one first, as shortener.text orders them.
	roots := []struct{ dir, as string }{{cwd, "."}, {home, "~"}}
	if len(home) > len(cwd) {
		roots[0], roots[1] = roots[1], roots[0]
	}
	for _, r := range roots {
		if t := tilde(r.dir); t != r.dir {
			s = strings.ReplaceAll(s, t+"/", r.as+"/")
		}
	}
	return s
}

// shownKey is a rule key as the line page shows it (runText) and the key in full for its title, "" when the two are
// the same.
func shownKey(key, home, cwd string) (shown, full string) {
	shown = runText(key, home, cwd)
	if shown != key {
		full = key
	}
	return shown, full
}

// lineChainWords is where line seq stands in a chain that breaks at a line (r9 QG-10): before the break, it and every
// line before it hash correctly; on the break line, its own bytes are what fails. at is "before" or "here"; both
// are "" for a chain that verifies, was not checked, breaks after the last line, or breaks before seq (the run's
// sentence says it all there).
func lineChainWords(c ledgerview.Chain, seq uint64) (words, at string) {
	if c.State != ledgerview.ChainBroken || !c.AtLine {
		return "", ""
	}
	switch {
	case seq < c.Line:
		return "Verified up to here · broken later at #" + strconv.FormatUint(c.Line, 10), "before"
	case seq == c.Line && strings.Contains(c.Reason, "id does not match"):
		return "Changed after it was written", "here"
	case seq == c.Line:
		return "The chain breaks at this line: " + c.Reason + ".", "here"
	}
	return "", ""
}

// stepOf is one crumb of the process chain.
func stepOf(p ledgerview.ProcRef, self bool) procStep {
	st := procStep{ProcRef: p, Self: self, Path: linewords.Mask(p.Path)}
	switch {
	case p.Launcher:
		st.Label = "tego launcher"
	case p.Unrecorded:
		st.Label = "pid " + strconv.Itoa(p.PID)
	case p.Name != "":
		st.Label = p.Name
	default:
		st.Label = "pid " + strconv.Itoa(p.PID)
	}
	return st
}

// decisionWords is a line's verdict and who decided it, in words.
func decisionWords(e *ledgerview.Event) (verdict, by string) {
	switch {
	case e.Refused():
		verdict = "Blocked"
	case e.Verdict != "":
		w, ok := linewords.Verdict(e.Verdict)
		if !ok {
			w = e.Verdict
		}
		verdict = capFirst(w)
	case e.Kind == "ask":
		verdict = "Held for a person: the agent waited for an answer"
	case e.Kind == "answer":
		verdict = "A person's answer to a question"
	default:
		verdict = "Recorded, nothing to decide"
	}
	if e.Authority != "" {
		w, ok := linewords.Authority(e.Authority)
		if !ok {
			w = e.Authority
		}
		by = w
	}
	return verdict, by
}

// msWords is a short gap in milliseconds ("1.204 ms", "312 ms"), a long one in linewords' words.
func msWords(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return strconv.FormatFloat(float64(d.Microseconds())/1000, 'f', 3, 64) + " ms"
	case d < 10*time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + " ms"
	}
	return linewords.Duration(d)
}

// askCardOf is a's card: the times of its ask and answer lines read from the run, and its outcome in words.
func askCardOf(rr *ledgerview.Run, a *ledgerview.AskFacts) *askCard {
	c := &askCard{AskFacts: a, Pending: !a.Answered}
	c.Rule, c.RuleFull = shownKey(a.Rule, ledgerview.RunHome(rr), rr.Cwd)
	evs := rr.AllEvents()
	at := func(seq uint64) string {
		i := sort.Search(len(evs), func(k int) bool { return evs[k].Seq >= seq })
		if i < len(evs) && evs[i].Seq == seq {
			return evs[i].TS.Local().Format("15:04:05.000")
		}
		return ""
	}
	if a.HasAsk {
		c.AskedAt = at(a.AskSeq)
	}
	if a.Answered {
		c.AnsweredAt = at(a.AnswerSeq)
	}
	switch {
	case !a.Answered:
		c.Outcome = "No answer is in the record"
	case a.Alternate != "":
		c.Outcome = "Answered with another file"
	case a.Approved != nil && *a.Approved && strings.HasSuffix(a.By, " always"):
		c.Outcome = "Allowed for the rest of the run"
	case a.Approved != nil && *a.Approved:
		c.Outcome = "Allowed once"
	case a.AnswerReason == "ask-timeout":
		c.Outcome = "Nobody answered in time, so it was refused"
	case a.AnswerReason == "ask-unavailable":
		c.Outcome = "The question could not be asked, so it was refused"
	default:
		c.Outcome = "Denied"
	}
	return c
}

// noActKinds are the lines nobody can make a rule from: the run's own start and end, a note about what the record
// lacks, a limit and a person's answer. The page shows no Act panel on them (LG-F12).
var noActKinds = map[string]bool{"run_start": true, "run_end": true, "gap": true, "limit": true, "answer": true}

// actErrWords is an Act panel error in words: a contract file that is gone reads as moved, never as lstat's text.
func actErrWords(msg string) string {
	if strings.Contains(msg, "no such file or directory") || strings.Contains(msg, "not a directory") {
		return "the contract file has moved since this run"
	}
	return msg
}

// askActWords is the Act panel's line on an ask line: a question is not an action, so a rule is made from the line
// its answer let through or refused, named when the record has it.
func askActWords(f *factsView) string {
	out := "A question, not an action · no rule from it"
	if f != nil && f.Ask != nil && len(f.Ask.ConsequenceSeqs) > 0 {
		return out + " Make the rule from line #" + strconv.FormatUint(f.Ask.ConsequenceSeqs[0], 10) + ", the action its answer decided."
	}
	return out + " Once it is answered, make the rule from the action its answer decided."
}

// serveBlob answers GET /runs/<run>/lines/<seq>?blob=<sha>: the blob this line names, as a download. Only a sha one
// of the line's blob fields names (ledgerview marks them Blob) is served: 400 for a value that is not a sha256 name,
// 404 for one the line does not name. The blob is the agent's own bytes, so it is read as ReadBlob reads one (no link
// followed, no FIFO, a regular file of at most maxBlobDownload bytes whose sha256 is its name) and served as an
// attachment of type application/octet-stream with nosniff, never rendered.
func (s *Server) serveBlob(w http.ResponseWriter, rr *ledgerview.Run, seq uint64, sha string) {
	if !hexSHA(sha) {
		s.fail(w, http.StatusBadRequest, "Not a blob name", "A blob is named by 64 lower-case hexadecimal digits.")
		return
	}
	lv, err := ledgerview.Explain(s.cfg.Ledger, rr, seq)
	if err != nil {
		s.fail(w, http.StatusNotFound, "No such line", "Run "+rr.ID+" has no line #"+strconv.FormatUint(seq, 10)+".")
		return
	}
	key := ""
	for _, f := range lv.Fields {
		if f.Blob != nil && f.Blob.SHA == sha {
			key = f.Key
			break
		}
	}
	if key == "" {
		s.fail(w, http.StatusNotFound, "No such blob", "Line #"+strconv.FormatUint(seq, 10)+" names no blob "+sha[:12]+"….")
		return
	}
	b, err := readBlobFile(filepath.Join(s.cfg.Ledger, rr.ID), sha, maxBlobDownload)
	if err != nil {
		s.fail(w, http.StatusNotFound, "The blob is not served", "The blob of "+key+" fails its checks: "+err.Error()+".")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", `attachment; filename="`+rr.ID+"-line"+strconv.FormatUint(seq, 10)+"-"+safeName(key)+`.bin"`)
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b) // a client that went away is not the page's error
}

// hexSHA reports whether s is a sha256 name: 64 lower-case hexadecimal digits.
func hexSHA(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// safeName is a field key fit for a file name: letters, digits, dot, dash and underscore.
func safeName(k string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, k)
}

// factsFuncs are the facts column's template functions.
var factsFuncs = template.FuncMap{
	"bytes":    linewords.Bytes,
	"hexSHA":   hexSHA,
	"capFirst": capFirst,
	"deref":    func(b *bool) bool { return b != nil && *b },
	"kindWords": func(k string) string {
		if w, ok := linewords.Kind(k); ok {
			return w
		}
		return k
	},
	"sourceWords": func(src string) string {
		if w, ok := linewords.Source(src); ok {
			return w
		}
		return src
	},
	// blobArgs hands evblob the line's run and seq with one blob.
	"blobArgs": func(run string, seq uint64, b *ledgerview.BlobRef) map[string]any {
		return map[string]any{"Run": run, "Seq": seq, "Blob": b}
	},
}

// errBlobFile is a blob the download refuses.
var errBlobFile = errors.New("refused")

// readBlobFile reads <runDir>/blobs/<sha> as ledgerview.ReadBlob does, with the download's larger bound: the blobs
// folder is a real directory, the file is opened read-only with O_NOFOLLOW|O_NONBLOCK, is a regular file of at most
// max bytes, and its content hashes to sha. ReadBlob itself stops at the row's 256 KiB.
func readBlobFile(runDir, sha string, max int64) ([]byte, error) {
	dir := filepath.Join(runDir, "blobs")
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%w: the run has no blobs folder", errBlobFile)
	}
	f, err := os.OpenFile(filepath.Join(dir, sha), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: the blob file is missing", errBlobFile)
		}
		return nil, fmt.Errorf("%w: the blob file cannot be opened", errBlobFile)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: the blob is not a regular file", errBlobFile)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%w: the blob is larger than %d MiB", errBlobFile, max>>20)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fmt.Errorf("%w: the blob could not be read whole", errBlobFile)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != sha {
		return nil, fmt.Errorf("%w: the blob's content does not match its hash", errBlobFile)
	}
	return b, nil
}
