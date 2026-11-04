// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/linewords"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Explain is everything the record says about one ledger line, in plain words, for the line page: the envelope and
// where the line sits in the hash chain, the process that wrote it and its parents (proc.go), every key of the line
// with a label and words (linewords), each blob it names read back and checked (blobs.go), the question it belongs
// to with that question's answer and outcome, the refusal it mirrors or is mirrored by (pair.go), and one sentence.
// It reads the line and the one before it by their offsets, and builds the run's process and ask index once per
// published version (runMemo), so a line of a resident run costs a few hundred microseconds.
//
// Explain does not check the chain; the page shows VerifyRun's (cached) verdict beside it, in ChainWords.

// LineView is one line explained.
type LineView struct {
	Run  string
	Seq  uint64
	Kind string
	// Envelope is the line's common fields and its place in the chain.
	Envelope Envelope
	// Proc is the program the line's process was running at the line; nil when the record does not say (the pid
	// started no program at or before the line), and ProcNote says so.
	Proc     *ProcRef
	ProcNote string
	// Chain is Proc's parents, nearest first, up to tego's launcher or the first parent the run did not record;
	// ChainNote says why it stops short of the launcher, "" when it reaches it.
	Chain     []ProcRef
	ChainNote string
	// Cwd is the run's working folder (run_start's cwd). CwdPerProcess is false: no line records a process's own.
	Cwd           string
	CwdPerProcess bool
	// Fields is every key of the line after the envelope (kind, source, the decision, the attribution, the
	// payload), in the order the line writes them, nested objects flattened as a.b.
	Fields []Field
	// Ask is the question this line belongs to: an ask line, its answer, or the line the answer let through or
	// refused.
	Ask *AskFacts
	// MirrorOf is the seq of the refused action this kind=refused line mirrors; MirroredBy the seq of the line that
	// mirrors this refused action. Nil when there is none.
	MirrorOf, MirroredBy *uint64
	// Sentence is the line in one plain sentence.
	Sentence string
	// Decision and DecidedBy are the verdict and who decided it, in words, for a refusal a question ended in: "Refused:
	// a person said no" by "somebody, asked by fs.ask_read[…]", or "Refused: nobody answered in time". Both are ""
	// for every other line, whose verdict the page words from the line's own fields.
	Decision, DecidedBy string
	// Raw is the line exactly as written; Pretty is it indented ("" when it does not decode).
	Raw, Pretty string
}

// Envelope is a line's common fields and its place in the hash chain.
type Envelope struct {
	V   int
	Seq uint64
	// Position is the line's place among the run's lines read, from 1; Total is how many were read.
	Position, Total int
	// ID is the line's hash; Prev the hash it names as the line before. PrevSeq is the seq of the line before it in
	// the file, and PrevOK says Prev equals that line's id (for the first line: Prev is empty).
	ID, Prev string
	PrevSeq  uint64
	PrevOK   bool
	TS       time.Time
	MonoNS   uint64
	Run      string
	Agent    string
	// SinceStart is the time from the run's first line; SincePrev from the line before; SincePrevSameProc from the
	// last earlier line of the same pid (HasPrevSameProc).
	SinceStart, SincePrev, SincePrevSameProc time.Duration
	HasPrevSameProc                          bool
	PID, TID                                 int
	Cgroup                                   uint64
	Source, SourceWords                      string
}

// Field is one key of a line.
type Field struct {
	// Key is the key as the line writes it, a nested one as a dotted path (resources.memory_peak).
	Key string
	// Label is what the page calls it; the key itself when Unknown.
	Label string
	// Value is the value in plain words, credential-looking values hidden; the value as written when the glossary
	// has no words for it.
	Value string
	// Raw is the value as the line writes it (JSON), unmasked: the line page shows the whole line as written too.
	Raw string
	// Masked says Value hides something Raw holds.
	Masked bool
	// Unknown marks a key this dashboard has no label for ("a field this dashboard does not know").
	Unknown bool
	// Blob is the blob a *_blob or blob key names, read back and checked; Splice marks a request body's splice
	// hash (body_sha256, frame, messages), which is named and not read.
	Blob   *BlobRef
	Splice bool
}

// AskFacts is one question: what was asked, how it was answered and what followed.
type AskFacts struct {
	AskID string
	// AskSeq is the ask line's seq (HasAsk); AnswerSeq the answer line's (Answered).
	AskSeq, AnswerSeq uint64
	HasAsk, Answered  bool
	// Op, Target and Rule are what was asked and the rule that asked; Hold what the agent was held at.
	Op, Target, Rule, Hold string
	// Approved is the answer, nil when there is none.
	Approved *bool
	// By is who answered as the line wrote it; ByWords in words ("somebody, from the dashboard").
	By, ByWords string
	// AfterS is how long the agent waited, in seconds; After in words.
	AfterS float64
	After  string
	// AnswerReason is the answer's reason code (ask-denied, ask-timeout ...); Alternate the file a person gave in
	// place of the target.
	AnswerReason, Alternate string
	// ConsequenceSeqs are the lines the answer let through or refused (the action and its mirror).
	ConsequenceSeqs []uint64
	// Sentence is the question in words: "asked to read ~/proj/confidential/plan.md · allowed once by somebody
	// after 41.7 s".
	Sentence string
}

// ExplainLine is Explain of line seq of run under root, read through the root's Store.
func ExplainLine(root, run string, seq uint64) (*LineView, error) {
	r, err := LoadRun(root, run)
	if err != nil {
		return nil, err
	}
	return Explain(root, r, seq)
}

// Explain explains line seq of r, whose run directory is under root. A seq r does not hold is os.ErrNotExist.
func Explain(root string, r *Run, seq uint64) (*LineView, error) {
	evs := r.AllEvents()
	if findSeq(evs, seq) < 0 && r.Cut && seq < ^uint64(0)-consequenceWindow-1 {
		window, err := WindowBefore(root, r, seq+consequenceWindow+1)
		if err != nil {
			return nil, err
		}
		r = window
		evs = r.Events
	}
	i := findSeq(evs, seq)
	if i < 0 {
		return nil, os.ErrNotExist
	}
	e := &evs[i]
	x := r.lineIndexOf()
	runDir := filepath.Join(root, r.ID)
	lv := &LineView{Run: r.ID, Seq: seq, Kind: e.Kind, Cwd: r.Cwd}

	cur, prev := readLines(root, r.ID, evs, i)
	if cur == nil {
		return nil, os.ErrNotExist
	}
	lv.Raw = string(cur.raw)
	var buf bytes.Buffer
	if json.Indent(&buf, cur.raw, "", "  ") == nil {
		lv.Pretty = buf.String()
	}
	env := &lv.Envelope
	env.V, env.Seq, env.Position, env.Total = cur.V, seq, i+1, r.Lines
	if cur.Seq > 0 && env.Position == 1 {
		env.Position = 2
	} // the window boundary is not the first ledger line
	env.ID, env.Prev, env.TS, env.MonoNS, env.Run, env.Agent = cur.ID, cur.Prev, e.TS, cur.MonoNS, e.Run, e.Agent
	env.PID, env.TID, env.Cgroup, env.Source = cur.PID, cur.TID, cur.Cgroup, e.Source
	env.SourceWords, _ = linewords.Source(e.Source)
	if cur.Seq == 0 {
		env.PrevOK = cur.Prev == ""
	} else if prev != nil {
		env.PrevSeq, env.PrevOK = prev.Seq, cur.Prev == prev.ID
		if i > 0 {
			env.SincePrev = e.TS.Sub(evs[i-1].TS)
		}
	}
	if !r.Start.IsZero() {
		env.SinceStart = e.TS.Sub(r.Start)
	}
	for k := i - 1; k >= 0; k-- {
		if evs[k].pid == e.pid {
			env.SincePrevSameProc, env.HasPrevSameProc = e.TS.Sub(evs[k].TS), true
			break
		}
	}

	lv.procFacts(evs, x, int32(i)) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
	names := func(uid string) string { return x.users[uid] }
	lv.Fields = lineFields(cur.raw, runDir, names)
	if id, ok := x.askOf[int32(i)]; ok { //nolint:gosec // as above
		if a := x.asks[id]; a != nil {
			lv.Ask = askFacts(evs, a, names, RunHome(r))
		}
	}
	if a, ok := x.mirrorOf[int32(i)]; ok { //nolint:gosec // as above
		s := evs[a].Seq
		lv.MirrorOf = &s
	}
	if m, ok := x.mirroredBy[int32(i)]; ok { //nolint:gosec // as above
		s := evs[m].Seq
		lv.MirroredBy = &s
	}
	lv.Sentence = sentence(lv, e, r, x, names)
	lv.Decision, lv.DecidedBy = askDecision(e, lv.Ask)
	return lv, nil
}

// askDecision is the verdict and who decided it for a refusal a question ended in: the line's authority
// alone reads "Refused by a rule" on a line a person refused. A person's no names that person and the rule that asked;
// a question nobody answered, or that could not be asked, says so. Both are "" for any other line.
func askDecision(e *Event, a *AskFacts) (decision, by string) {
	if !e.Refused() {
		return "", ""
	}
	rule := e.Rule
	if a != nil && a.Rule != "" {
		rule = a.Rule
	}
	asked := ""
	if rule != "" && rule != "unmatched" {
		asked = "asked by " + rule
	}
	join := func(who string) string {
		switch {
		case who == "":
			return asked
		case asked == "":
			return who
		}
		return who + ", " + asked
	}
	switch e.Reason {
	case string(record.ReasonAskDenied):
		who := ""
		if a != nil {
			who = a.ByWords
		}
		if who == "" {
			who = "a person"
		}
		return "Refused: a person said no", join(who)
	case string(record.ReasonAskTimeout):
		return "Refused: nobody answered in time", join("the time limit")
	case string(record.ReasonAskUnavailable):
		return "Refused: the question could not be asked", join("Tego")
	}
	return "", ""
}

// findSeq is the index of the line with seq in evs (file order, seq rising), -1 when there is none.
func findSeq(evs []Event, seq uint64) int {
	i := sort.Search(len(evs), func(k int) bool { return evs[k].Seq >= seq })
	if i < len(evs) && evs[i].Seq == seq {
		return i
	}
	for k := range evs { // a file whose seqs do not rise (a damaged ledger): look at every line
		if evs[k].Seq == seq {
			return k
		}
	}
	return -1
}

// lineHead is a line's envelope as written, and the line itself.
type lineHead struct {
	V      int    `json:"v"`
	Seq    uint64 `json:"seq"`
	ID     string `json:"id"`
	Prev   string `json:"prev"`
	MonoNS uint64 `json:"mono_ns"`
	PID    int    `json:"pid"`
	TID    int    `json:"tid"`
	Cgroup uint64 `json:"cgroup"`
	raw    []byte
}

// readLines reads line i of evs and the line before it from the run's events file at the offsets the read model
// recorded, checking each is the seq it should be; a line not found there (a Run not read by the store, a file
// replaced since) is looked for by Line's scan.
func readLines(root, run string, evs []Event, i int) (cur, prev *lineHead) {
	f, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		defer func() { _ = f.Close() }()
		cur = headAt(f, evs[i].off, evs[i].Seq)
		if i > 0 {
			prev = headAt(f, evs[i-1].off, evs[i-1].Seq)
		}
	}
	if cur == nil {
		if lf, err := Line(root, run, evs[i].Seq); err == nil {
			cur = headOf([]byte(lf.Raw), evs[i].Seq)
		}
	}
	if prev == nil && i > 0 {
		if lf, err := Line(root, run, evs[i-1].Seq); err == nil {
			prev = headOf([]byte(lf.Raw), evs[i-1].Seq)
		}
	}
	if prev == nil && evs[i].Seq > 0 {
		if lf, err := Line(root, run, evs[i].Seq-1); err == nil {
			prev = headOf([]byte(lf.Raw), evs[i].Seq-1)
		}
	}
	return cur, prev
}

// headAt is the line at off in f when it is line seq, else nil.
func headAt(f *os.File, off int64, seq uint64) *lineHead {
	br := bufio.NewReaderSize(io.NewSectionReader(f, off, maxLineBytes+1), 64<<10)
	b, err := br.ReadBytes('\n')
	if err != nil {
		return nil
	}
	return headOf(b[:len(b)-1], seq)
}

func headOf(b []byte, seq uint64) *lineHead {
	h := &lineHead{}
	if json.Unmarshal(b, h) != nil || h.Seq != seq {
		return nil
	}
	h.raw = b
	return h
}

// envelopeKeys are the common fields Envelope holds; every other key of a line is a Field.
var envelopeKeys = map[string]bool{"v": true, "seq": true, "id": true, "prev": true, "ts": true, "mono_ns": true,
	"run": true, "agent": true, "pid": true, "tid": true, "cgroup": true}

// lineFields is every key of the line raw after the envelope, in written order, nested objects flattened.
func lineFields(raw []byte, runDir string, names func(string) string) []Field {
	var out []Field
	var meta struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(raw, &meta) // the reader already checked the record JSON
	walkObject("", raw, func(key string, v json.RawMessage) {
		if envelopeKeys[key] {
			return
		}
		f := field(key, v, runDir, names)
		if meta.Kind == "exec" && key == "dropped" {
			f.Label, _ = linewords.Label("exec.dropped")
		}
		out = append(out, f)
	})
	return out
}

// walkObject calls leaf for each key of the JSON object raw in written order, descending into a non-empty object
// value with the key as a dotted prefix. A value that is not an object is one leaf under prefix.
func walkObject(prefix string, raw []byte, leaf func(string, json.RawMessage)) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		leaf(prefix, raw)
		return
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return
		}
		k, _ := t.(string)
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return
		}
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if len(v) > 2 && v[0] == '{' && bytes.ContainsRune(v[1:len(v)-1], ':') {
			walkObject(key, v, leaf)
			continue
		}
		leaf(key, v)
	}
}

// field is one leaf key with its label and words.
func field(key string, v json.RawMessage, runDir string, names func(string) string) Field {
	f := Field{Key: key, Raw: string(v)}
	var known bool
	f.Label, known = linewords.Label(key)
	f.Unknown = !known
	leaf := key[strings.LastIndexByte(key, '.')+1:]
	var s string
	isStr := json.Unmarshal(v, &s) == nil
	switch {
	case isStr && isBlobKey(leaf):
		f.Blob = resolveBlobRef(runDir, s)
		f.Value = blobWords(f.Blob)
		return f
	case isStr && spliceKeys[leaf]:
		f.Splice = true
		f.Value = "stored as a splice; not shown here"
		return f
	case isStr && (leaf == "by" || leaf == "stopped_by"):
		f.Value = linewords.Who(s, names)
		return f
	}
	plain, _ := linewords.Value(key, v)
	f.Value = linewords.Mask(plain)
	f.Masked = f.Value != plain
	return f
}

// blobWords is a blob in words: "stored apart, 17.0 KiB, checked", or why it is not shown.
func blobWords(b *BlobRef) string {
	size := ""
	if b.Size > 0 {
		size = ", " + linewords.Bytes(b.Size)
	}
	switch {
	case !b.Verified:
		return "stored apart" + size + "; not shown: " + b.Why
	case b.Binary:
		return "stored apart" + size + ", checked; not text, so not shown"
	}
	return "stored apart" + size + ", checked against its hash"
}

// procFacts fills Proc, Chain and their notes for line index i.
func (lv *LineView) procFacts(evs []Event, x *lineIndex, i int32) {
	e := &evs[i]
	var parent string
	switch f, isExec := x.execs[i]; {
	case isExec && f.id != "" && x.procs[f.id] != nil:
		// An exec line: its process is the one that made the call. A refused exec changes nothing it runs.
		pi := x.procs[f.id]
		_, exec, refused, _ := x.procAtIn(pi, i)
		ref := x.ref(evs, pi, exec, refused)
		lv.Proc, parent = &ref, pi.parent
	default:
		pi, exec, refused, ok := x.procAt(e.pid, i)
		switch {
		case ok:
			ref := x.ref(evs, pi, exec, refused)
			lv.Proc, parent = &ref, pi.parent
		case x.launcherPID > 0 && e.pid == x.launcherPID:
			lv.Proc = &ProcRef{PID: e.pid, ExecID: x.launcherID, Launcher: true, Name: "tego launcher"}
		default:
			lv.ProcNote = "pid " + strconv.Itoa(e.pid) + " started no program before this line, so the record does not say what it ran or who started it"
		}
	}
	if parent != "" {
		lv.Chain = x.chain(evs, parent, i)
	}
	if n := len(lv.Chain); n > 0 && lv.Chain[n-1].Unrecorded {
		lv.ChainNote = "The chain stops at pid " + strconv.Itoa(lv.Chain[n-1].PID) +
			": it forked without starting a program, so the record does not say what it ran or who started it."
	} else if n == 0 && lv.Proc != nil && !lv.Proc.Launcher && parent == "" {
		lv.ChainNote = "The record names no parent for this process."
	}
	all := make([]*ProcRef, 0, len(lv.Chain)+1)
	if lv.Proc != nil {
		all = append(all, lv.Proc)
	}
	for k := range lv.Chain {
		all = append(all, &lv.Chain[k])
	}
	for k := len(all) - 1; k >= 0; k-- {
		p := all[k]
		if p.Path == "/proc/self/exe" && k+1 < len(all) && all[k+1].Name != "" {
			// A program that starts itself again (Codex sets up each command this way) is its parent's program.
			p.Name = all[k+1].Name
		}
		p.ArgvMasked = linewords.Mask(p.Argv)
		p.Words = procWords(p)
	}
}

// procAtIn is procAt for a known process.
func (x *lineIndex) procAtIn(pi *procInfo, at int32) (*procInfo, int32, int32, bool) {
	exec, refused := int32(-1), int32(-1)
	for _, i := range pi.execs {
		if i > at {
			break
		}
		if x.execs[i].refused {
			refused = i
		} else {
			exec = i
		}
	}
	return pi, exec, refused, true
}

// procWords is p in a few words.
func procWords(p *ProcRef) string {
	pid := strconv.Itoa(p.PID)
	switch {
	case p.Launcher:
		if p.PID > 0 {
			return "tego launcher (pid " + pid + ")"
		}
		return "tego launcher"
	case p.Unrecorded:
		return "pid " + pid + ", forked, no exec recorded"
	case !p.HasExec:
		return "pid " + pid + ", no program recorded yet at this line"
	case p.Refused:
		return "pid " + pid + ", which tried to start " + p.Name + " and was refused, so it still ran its parent's program"
	}
	return p.Name + " (pid " + pid + ")"
}

// askFacts is a's facts, its paths shown under home as ~/.
func askFacts(evs []Event, a *askEntry, names func(string) string, home string) *AskFacts {
	af := &AskFacts{AskID: a.id, HasAsk: a.hasAsk, Answered: a.hasAnswer, Op: a.op, Target: a.target, Rule: a.rule,
		Hold: a.hold, Approved: a.approved, By: a.by, AfterS: a.afterS, AnswerReason: a.reason, Alternate: a.alternate}
	if a.hasAsk {
		af.AskSeq = evs[a.askIdx].Seq
	}
	if a.hasAnswer {
		af.AnswerSeq = evs[a.answerIdx].Seq
	}
	for _, c := range a.consequences {
		af.ConsequenceSeqs = append(af.ConsequenceSeqs, evs[c].Seq)
	}
	af.ByWords = linewords.Who(a.by, names)
	if a.afterS > 0 {
		af.After = linewords.Duration(time.Duration(a.afterS * float64(time.Second)))
	}
	what := "asked a person"
	if a.target != "" {
		what = "asked to " + strings.TrimSpace(opVerb(a.op, false)+" "+shortPath(linewords.Mask(a.target), home))
	} else if h, ok := linewords.Hold(a.hold); ok {
		what = "asked a person to let " + h + " go on"
	}
	af.Sentence = what + " · " + answerWords(af)
	return af
}

// answerWords is how a question was answered: "allowed once by somebody after 41.7 s", "not answered yet".
func answerWords(af *AskFacts) string {
	if !af.Answered {
		return "not answered"
	}
	if af.By == linewords.WithdrawnBy && (af.Approved == nil || !*af.Approved) {
		return strings.ToLower(linewords.Withdrawn[:1]) + linewords.Withdrawn[1:]
	}
	var out string
	switch {
	case af.Alternate != "":
		out = "answered with another file, " + af.Alternate
	case af.Approved != nil && *af.Approved && strings.HasSuffix(af.By, " always"):
		out = "allowed for the rest of the run"
	case af.Approved != nil && *af.Approved:
		out = "allowed once"
	case af.AnswerReason == string(record.ReasonAskTimeout):
		out = "nobody answered in time, so it was refused"
	case af.AnswerReason == string(record.ReasonAskUnavailable):
		out = "the question could not be asked, so it was refused"
	default:
		out = "denied"
	}
	if af.ByWords != "" && af.AnswerReason != string(record.ReasonAskTimeout) && af.AnswerReason != string(record.ReasonAskUnavailable) {
		out += " by " + af.ByWords
	}
	if af.After != "" {
		out += " after " + af.After
	}
	return out
}

// shortPath is p with home shown as ~/.
func shortPath(p, home string) string {
	if home != "" && strings.HasPrefix(p, home+"/") {
		return "~/" + p[len(home)+1:]
	}
	return p
}

// maxSentenceTarget is how much of a command or path a sentence holds; the fields hold the rest.
const maxSentenceTarget = 160

func clip(s string) string {
	if len(s) <= maxSentenceTarget {
		return s
	}
	cut := maxSentenceTarget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// opVerb is an operation as a verb: past tense for what happened, the plain form after "tried to".
func opVerb(op string, past bool) string {
	type forms struct{ plain, past string }
	v, ok := map[string]forms{
		"read": {"read", "read"}, "write": {"write to", "wrote to"}, "open": {"open", "opened"},
		"unlink": {"delete", "deleted"}, "rmdir": {"delete the folder", "deleted the folder"}, "rename": {"rename", "renamed"},
		"mkdir": {"create the folder", "created the folder"}, "chmod": {"change permissions on", "changed permissions on"},
		"link": {"link", "linked"}, "symlink": {"make a symbolic link", "made a symbolic link"},
		"truncate": {"cut", "cut"}, "mknod": {"create a device file", "created a device file"},
		"connect": {"connect to", "connected to"}, "send": {"send to", "sent to"}, "sendto": {"send to", "sent to"},
		"sendmsg": {"send to", "sent to"}, "bind": {"listen on", "listened on"}, "listen": {"listen on", "listened on"},
		"request": {"request", "requested"}, "exec": {"start", "started"}, "first_write": {"send to", "sent to"},
	}[op]
	if !ok {
		return op
	}
	if past {
		return v.past
	}
	return v.plain
}

// sentence is the line in one plain sentence.
func sentence(lv *LineView, e *Event, r *Run, x *lineIndex, names func(string) string) string {
	home := RunHome(r)
	subj := subjectWords(lv, e)
	target := clip(shortPath(linewords.Mask(e.Target), home))
	switch e.Kind {
	case string(record.KindRunStart):
		who := r.User
		if who == "" {
			who = "Someone"
		}
		out := who + " started the run"
		if r.Command != "" {
			out += ": " + clip(linewords.Mask(r.Command))
		}
		if r.Cwd != "" {
			out += ", in " + shortPath(r.Cwd, home)
		}
		if t, ok := linewords.Tier(r.Tier); ok {
			out += ", at " + t
		}
		return out
	case string(record.KindRunEnd):
		w, ok := linewords.Reason(r.EndReason)
		if !ok {
			w = "the run ended"
		}
		out := "The run ended: " + w
		switch r.EndReason {
		case "exit":
			out += " with code " + strconv.Itoa(r.ExitCode)
		case "stopped":
			if r.StoppedBy != "" {
				out = "The run ended: " + linewords.Who(r.StoppedBy, names) + " stopped it"
			}
		}
		return out
	case string(record.KindGap):
		var p struct {
			What string `json:"what"`
			Why  string `json:"why"`
		}
		_ = json.Unmarshal([]byte(e.Raw), &p) // a gap that does not decode is still a gap
		if w, ok := linewords.GapWhy(p.Why); ok {
			return capFirst(w)
		}
		if w, ok := linewords.GapWhat(p.What); ok {
			return capFirst(w) + ": " + p.Why
		}
		return "A note about what the record lacks: " + strings.TrimSpace(p.What+" "+p.Why)
	case string(record.KindLimit):
		return "The run reached a limit: " + target
	case string(record.KindAsk):
		if lv.Ask != nil {
			return subj + " " + lv.Ask.Sentence
		}
		return subj + " asked a person"
	case string(record.KindAnswer):
		if lv.Ask != nil {
			a := lv.Ask
			return capFirst(answerWords(a)) + ": " + strings.TrimSpace(opVerb(a.Op, false)+" "+clip(shortPath(linewords.Mask(a.Target), home)))
		}
		return "A person answered a question"
	case string(record.KindExec):
		cmd := clip(shellTail(shortPath(linewords.Mask(e.Target), home)))
		if e.Refused() {
			return subj + " tried to start " + cmd + outcome(lv, e)
		}
		return subj + " started " + cmd + outcome(lv, e)
	case string(record.KindFS), string(record.KindNet), string(record.KindRefused), string(record.KindMCP):
		op := e.Op
		if e.Kind == string(record.KindNet) && op == "" {
			op = "connect"
		}
		pre := ""
		if lv.MirrorOf != nil {
			pre = "Tego's record of the refusal on line #" + strconv.FormatUint(*lv.MirrorOf, 10) + ": "
		}
		if e.Refused() {
			return pre + subj + " tried to " + strings.TrimSpace(opVerb(op, false)+" "+target) + outcome(lv, e)
		}
		return pre + subj + " " + strings.TrimSpace(opVerb(op, true)+" "+target) + outcome(lv, e)
	}
	k, _ := linewords.Kind(e.Kind)
	return capFirst(strings.TrimSpace(k + ": " + target))
}

// subjectWords is the process a sentence is about: "bash (pid 4037090, child of codex)", "Process 4036305". It
// starts the sentence as written: a program's name keeps its case.
func subjectWords(lv *LineView, e *Event) string {
	p := lv.Proc
	pid := strconv.Itoa(lv.Envelope.PID)
	if lv.Envelope.PID == 0 {
		pid = strconv.Itoa(e.pid)
	}
	child := ""
	if len(lv.Chain) > 0 {
		if c := lv.Chain[0]; c.Name != "" && !c.Unrecorded {
			child = ", child of " + c.Name
		} else if c.Unrecorded {
			child = ", child of pid " + strconv.Itoa(c.PID)
		}
	}
	switch {
	case p == nil:
		return "Process " + pid
	case p.Launcher:
		return "Tego's launcher"
	case e.Kind == string(record.KindExec) || !p.HasExec || p.Refused:
		// An exec line is about the call, so the process is named by its pid and parent, not by what it ran.
		return "Process " + pid + strings.Replace(child, ", ", " (", 1) + closeIf(child)
	}
	return p.Name + " (pid " + pid + child + ")"
}

// shellTail is a command line from the shell that runs its script on ("bash -c <script>"), the launcher in front of
// it (Codex's "/proc/self/exe --codex-run-as-process-setup … /bin/bash -c …") left out, as a row shows it.
func shellTail(cmd string) string {
	f := strings.Split(cmd, " ")
	for i := 1; i+1 < len(f); i++ {
		switch path.Base(f[i]) {
		case "bash", "sh", "dash", "zsh", "ksh":
			if f[i+1] == "-c" || f[i+1] == "-lc" || f[i+1] == "-ic" {
				return strings.Join(f[i:], " ")
			}
		}
	}
	return cmd
}

func closeIf(s string) string {
	if s == "" {
		return ""
	}
	return ")"
}

// outcome is what Tego did with an action: "; Tego refused it: a read the rules refuse, and the agent got EACCES".
func outcome(lv *LineView, e *Event) string {
	switch {
	case e.Refused():
		out := "; Tego refused it"
		if e.Authority == string(record.AuthorityHuman) {
			out = "; a person refused it"
		}
		if w, ok := linewords.Reason(e.Reason); ok {
			out += ": " + w
		} else if e.Reason != "" {
			out += ": " + e.Reason
		}
		if n := errnoOf(lv.Fields); n != "" {
			out += ", and the agent got " + n
		}
		return out
	case e.Verdict == string(record.VerdictObserved):
		return "; recorded only, nothing was decided"
	case e.Authority == string(record.AuthorityHuman):
		return "; a person allowed it"
	case e.Verdict == string(record.VerdictAllow) && e.Rule != "" && e.Rule != "unmatched":
		return "; allowed by " + e.Rule
	case e.Verdict == string(record.VerdictAllow):
		return "; allowed"
	}
	return ""
}

// errnoOf is the error the line says the agent got ("EACCES"), "" when it names none.
func errnoOf(fs []Field) string {
	for _, f := range fs {
		switch f.Key {
		case "errno", "syscall_errno":
			if n, err := strconv.ParseInt(f.Raw, 10, 64); err == nil && n > 0 {
				if name := linewords.ErrnoName(n); name != "" {
					return name
				}
				return "error " + f.Raw
			}
		case "syscall_ret":
			if n, err := strconv.ParseInt(f.Raw, 10, 64); err == nil && n < 0 {
				if name := linewords.ErrnoName(-n); name != "" {
					return name
				}
			}
		}
	}
	return ""
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ChainWords is a run's chain verdict (VerifyRun) in words, for the line page's integrity block. A chain proves no line
// was changed or cut after the run closed, never that the lines are all the run did: a run that lost its supervisor
// closes over what survived, and its gap says so.
func ChainWords(c Chain) string {
	switch c.State {
	case ChainVerified:
		out := fmt.Sprintf("The run's record has not been changed: all %d lines hash into one chain", c.Lines)
		if c.Anchored {
			out += ", and its last line matches the anchor kept outside the run"
		}
		return out + "."
	case ChainBroken:
		if c.AtLine {
			return fmt.Sprintf("The run's record does not verify: the chain breaks at line #%d (%s).", c.Line, c.Reason)
		}
		return "The run's record does not verify: " + c.Reason + "."
	}
	if c.Reason != "" {
		return "The run's record was not checked here: " + c.Reason + "."
	}
	return "The run's record was not checked here."
}
