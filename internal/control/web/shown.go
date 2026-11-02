// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/linewords"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// How a ledger line reads in a timeline or log row. The row is for a person at a glance; the line page keeps the
// line exactly as written. So a row masks what looks like a credential in a command line (an Authorization header,
// a --token flag, a key=value secret, a password in a URL), names people instead of "uid:1000 pid:…", says what an
// answer or a live block did, and drops a host name that only repeats the address.
//
// A row is an operation (shownOp, in plain words, never a ledger kind such as run_start) and the agent's text
// (shown: a path, a command, a destination). A line with no agent text, such as a recording gap or the run's end,
// is one sentence in shownOp and an empty shown. Both feed the Logs rows and the run timeline (tlrows), so the two
// say the same thing.

func init() {
	funcs["pathWords"] = pathWords
	funcs["pathWordsIn"] = pathWordsIn
	funcs["reasonWords"] = reasonWords
	funcs["pieces"] = breakPieces
	funcs["pathPieces"] = pathPieces
	funcs["hasHidden"] = hasHidden
}

// visibleText is s with each invisible character written as a visible literal, "⟦U+202E⟧": every format character (a
// bidi override, embedding, isolate or mark; a zero-width character; a soft hyphen; a tag character) and the line and
// paragraph separators (record.Invisible, the rule `tego ask` and the other CLI views escape by, as \u202e), but for
// the zero-width joiner, which emoji sequences need and which reorders nothing (a variation selector is a mark, never
// one of them). A name the agent chose can otherwise show as another: "a\u202etxt.exe" reads "aexe.txt", and the
// words Tego writes after it run backwards (QA BR-1). Every other byte, invalid UTF-8 included, stays as it is.
func visibleText(s string) string {
	i := strings.IndexFunc(s, hidden)
	if i < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	b.WriteString(s[:i])
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		if hidden(r) {
			b.WriteString(hiddenLiteral(r))
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// hidden reports a rune visibleText writes as a literal.
func hidden(r rune) bool { return r != '\u200d' && record.Invisible(r) }

// hiddenLiteral is r as visibleText writes it: ⟦U+202E⟧, ⟦U+E0041⟧.
func hiddenLiteral(r rune) string { return fmt.Sprintf("⟦U+%04X⟧", r) }

// hasHidden reports whether s holds a rune visibleText writes as a literal (the line page says so above the line).
func hasHidden(s string) bool { return strings.IndexFunc(s, hidden) >= 0 }

// visibleHTML is page, an HTML page or fragment html/template rendered, with visibleText applied to everything a
// person reads in it: text, a title, a label. Every response that carries agent text as HTML goes through it as it is
// written (renderPage, renderRegions, writeFragment), so no template and no helper has to remember to. It leaves
// alone what is sent back or copied exactly: a form's value="…" (the path a Never allow posts), a <textarea>'s text
// (a contract being edited) and a <template data-exact>'s (the line a Copy button copies as written). It reads the
// markup by bytes, which is sound for html/template's output: data never yields a raw '"' or '<' there (each is
// escaped in every context, and this package converts nothing to a trusted type), so each of those spans opens and
// closes only in the templates' own text, and Tego's templates hold no invisible character. A page with nothing to
// write is returned as it is.
func visibleHTML(page []byte) []byte {
	if hiddenIn(page) < 0 {
		return page
	}
	var out []byte
	done := 0 // page[:done] is in out
	for i := 0; i < len(page); {
		c := page[i]
		if c < utf8.RuneSelf {
			if c == ' ' || c == '\t' || c == '\n' || c == '<' {
				if end := exactEnd(page, i); end > i {
					i = end
					continue
				}
			}
			i++
			continue
		}
		r, n := utf8.DecodeRune(page[i:])
		if hidden(r) {
			if out == nil {
				out = make([]byte, 0, len(page)+64)
			}
			out = append(append(out, page[done:i]...), hiddenLiteral(r)...)
			done = i + n
		}
		i += n
	}
	if out == nil {
		return page // every hidden rune was in a span kept as written
	}
	return append(out, page[done:]...)
}

// hiddenIn is the offset of page's first hidden rune, -1 when it has none: the check every page pays, so ASCII, most of
// a page, costs one comparison a byte.
func hiddenIn(page []byte) int {
	for i := 0; i < len(page); {
		if page[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, n := utf8.DecodeRune(page[i:])
		if hidden(r) {
			return i
		}
		i += n
	}
	return -1
}

// The spans visibleHTML keeps as written, each from its opening text to the end of its closing one (an unclosed span
// runs to the end of the page). A form value's opening is the attribute's name after white space, so "data-value=" is
// not one.
var (
	valueOpen, valueClose       = []byte(`value="`), []byte(`"`)
	textareaOpen, textareaClose = []byte("<textarea"), []byte("</textarea>")
	exactOpen, exactClose       = []byte("<template data-exact"), []byte("</template>")
)

// exactEnd is the end of the span kept as written that starts at page[i] (white space or '<'), or i when none starts
// there.
func exactEnd(page []byte, i int) int {
	from, closing := 0, valueClose
	switch rest := page[i:]; {
	case rest[0] != '<':
		if !bytes.HasPrefix(rest[1:], valueOpen) {
			return i
		}
		from = i + 1 + len(valueOpen)
	case bytes.HasPrefix(rest, textareaOpen):
		from, closing = i+len(textareaOpen), textareaClose
	case bytes.HasPrefix(rest, exactOpen):
		from, closing = i+len(exactOpen), exactClose
	default:
		return i
	}
	if k := bytes.Index(page[from:], closing); k >= 0 {
		return from + k + len(closing)
	}
	return len(page)
}

// mask is s with credential-looking values replaced by "••••" (linewords.Mask, which the line page uses too), its
// result remembered for a long text.
func mask(s string) string { return linewords.Mask(s) }

// maskNow is mask without the memo; maskMemoMin is the shortest text the memo keeps.
func maskNow(s string) string { return linewords.MaskNow(s) }

const maskMemoMin = linewords.MaskMemoMin

// sameHost matches a net target that names its address twice: "127.0.0.1 (127.0.0.1:59465)".
var sameHost = regexp.MustCompile(`^(\S+) \((\S+):(\d+)\)$`)

// rowPayload is what shown reads from an answer, a gap, a live-block gap or an ask line.
type rowPayload struct {
	Approved *bool   `json:"approved"`
	By       string  `json:"by"`
	After    float64 `json:"after_s"`
	Reason   string  `json:"answer_reason"`
	What     string  `json:"what"`
	Why      string  `json:"why"`
	Op       string  `json:"op"`
	Target   string  `json:"target"`
	// Host and Endpoint name a model request's or answer's server (ssl_request, ssl_response).
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
	// Binary is the file a gap names: of a mode tego gave back to its owner, the file (own-state-mode-restored).
	Binary string `json:"binary"`
	Block  *struct {
		Op      string `json:"op"`
		Kind    string `json:"kind"`
		Value   string `json:"value"`
		By      string `json:"by"`
		Refused string `json:"refused"`
	} `json:"live_block"`
}

// shown is a row's target in words, masked: see the file comment.
func shown(e ledgerview.Event) string {
	switch e.Kind {
	case "answer":
		var p rowPayload
		if json.Unmarshal([]byte(e.Raw), &p) == nil && p.Approved != nil {
			// shownOp says what the answer was; the row's text is what it answered, both of a held mutation's names.
			return mask(e.AskTarget())
		}
	case "ask":
		// What it asks about. An ask line written without a target names only its id, which says nothing to a
		// person, so shownOp carries the whole row.
		return mask(e.AskTarget())
	case "run_end":
		return ""
	case "exec":
		if e.ArgvMissing() {
			return mask(e.Target) + " (command in blob could not be read)"
		}
		return shellTail(mask(e.Target))
	case "gap":
		var p rowPayload
		decoded := json.Unmarshal([]byte(e.Raw), &p) == nil
		if decoded && p.Block != nil {
			what := blockWhat(p.Block.Kind, mask(p.Block.Value))
			// ADR 0125's ops (record minor 26) are no block: a lift allows, a restore refuses again, an expiry is the
			// time limit's (no person made it), and a refused lift loosened nothing.
			switch {
			case p.Block.Op == "remove":
				return "block on " + what + " removed by " + who(p.Block.By)
			case p.Block.Op == "lift" && p.Block.Refused != "":
				return what + ", asked by " + who(p.Block.By)
			case p.Block.Op == "lift":
				return what + ", allowed live by " + who(p.Block.By)
			case p.Block.Op == "restore":
				return what + ", refused again by " + who(p.Block.By)
			case p.Block.Op == "expire":
				return what
			}
			return what + ", blocked live by " + who(p.Block.By)
		}
		// A mode tego gave back to its owner (gaps.Restored) names its file; shownOp says what tego did.
		if decoded && p.What == record.GapRecord && p.Why == record.GapOwnStateModeRestored {
			return mask(p.Binary)
		}
		return ""
	case "ssl_request", "ssl_response":
		return mask(modelServer(e))
	case "net":
		if m := sameHost.FindStringSubmatch(e.Target); m != nil && m[1] == m[2] {
			return m[2] + ":" + m[3]
		}
	}
	return mask(e.Target)
}

// shells are the programs whose "-c <script>" is the command a person wants to read.
var shells = map[string]bool{"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true}

// shellTail is a command line that runs a shell script read from the shell on: a launcher in front of it (Codex starts
// every command as "/proc/self/exe --codex-run-as-process-setup <n> <pid> pipe <cwd> /bin/bash /bin/bash -c <script>")
// is elided as "… ", so a three-line row shows the script, not the launcher. The line page shows the whole line.
func shellTail(cmd string) string {
	f := strings.Split(cmd, " ")
	for i := 1; i+1 < len(f); i++ {
		if shells[path.Base(f[i])] && (f[i+1] == "-c" || f[i+1] == "-lc" || f[i+1] == "-ic") {
			return "… " + strings.Join(f[i:], " ")
		}
	}
	return cmd
}

// shownOp is a row's operation in plain words: "Run started:", "Asked to read", "Allowed once by alice after 27 s:",
// a gap's sentence, a live block's "block" or "unblock"; an action keeps its verb (read, write, connect), and exec
// reads "run".
func shownOp(e ledgerview.Event) string {
	switch e.Kind {
	case "gap":
		// A time limit's end (record minor 26) is no block: it reads as its own sentence below.
		if strings.HasPrefix(e.Target, "enforce live-block-") && !strings.HasSuffix(e.Target, "expired") {
			if strings.HasSuffix(e.Target, "removed") {
				return "unblock"
			}
			return "block"
		}
		var p rowPayload
		_ = json.Unmarshal([]byte(e.Raw), &p) // a gap that does not decode reads as a gap with no name
		return gapWords(p.What, p.Why)
	case "run_start":
		if e.Target == "" {
			return "Run started"
		}
		return "Run started:"
	case "run_end":
		return endWords(e.Raw)
	case "ask":
		var p rowPayload
		_ = json.Unmarshal([]byte(e.Raw), &p) // the hold (e.Op) is known whether or not the rest decodes
		if e.AskTarget() == "" {
			if e.Op != "" {
				return "Asked a person to let a held " + e.Op + " go on"
			}
			return "Asked a person"
		}
		return "Asked to " + askVerb(p.Op, e.Rule, e.Op)
	case "answer":
		var p rowPayload
		if json.Unmarshal([]byte(e.Raw), &p) == nil && p.Approved != nil {
			out := capFirst(answerPhrase(*p.Approved, p.Reason, p.By, p.After))
			if i := strings.LastIndex(out, " after "); i >= 0 {
				// "1 m 29 s" wraps as a whole, never as "after 41" / "s".
				out = out[:i+7] + strings.ReplaceAll(out[i+7:], " ", " ")
			}
			if p.Target != "" {
				out += ":"
			}
			return out
		}
		return "Answered"
	case "exec":
		return "run"
	case "ssl_request", "ssl_response":
		// A model call reads as one, never as its kind's name (ssl_request).
		verb := map[string]string{"ssl_request": "model request", "ssl_response": "model answer"}[e.Kind]
		if modelServer(e) == "" {
			return verb
		}
		return verb + map[string]string{"ssl_request": " to", "ssl_response": " from"}[e.Kind]
	}
	return e.Op
}

// modelServer is the server a model request or answer line names: its host, else its models[] endpoint's name; ""
// when the line names neither.
func modelServer(e ledgerview.Event) string {
	var p rowPayload
	if json.Unmarshal([]byte(e.Raw), &p) != nil {
		return ""
	}
	if p.Host != "" {
		return p.Host
	}
	return p.Endpoint
}

// gapWords is a recording gap as a sentence: what the record lacks, and why, in words. The live controls' enforce
// lines (record minors 24 and 26) are no gap in what is enforced, so they read as what happened to the run, never "Not
// enforced: run paused".
func gapWords(what, why string) string {
	switch why {
	case "no-models":
		return "Model traffic not recorded (no model capture for this agent)"
	case "no-price-table":
		return "Cost not counted (no price table for this model)"
	case "argv-truncated":
		return "A command line too long to record whole"
	case "path-truncated":
		return "A path too long to record whole"
	case "ringbuf-full":
		return "Some kernel events were dropped (the buffer was full)"
	case "live-block-unreadable":
		return "A live block could not be read"
	case "live-block-lost":
		return "A live block was lost"
	case "run-paused":
		return "Run paused: the agent is frozen"
	case "run-resumed":
		return "Run resumed"
	case "pause-failed":
		return "Pause failed: the agent kept running"
	case "resume-failed":
		return "Resume failed: the run stays paused"
	// ADR 0125's live whys (record minor 26) are what happened to the run's live rules, never "Not enforced".
	case "live-block-expired":
		return "Live block ended: its time ran out"
	case "live-unblock-expired":
		return "Live block back: its time off ran out"
	case "live-rule-lifted":
		return "Rule in the fence allowed"
	case "live-rule-restored":
		return "Rule in the fence refuses again"
	case "live-lift-expired":
		return "Allowed rule ended: its time ran out"
	case "live-lift-refused":
		return "Request to allow a rule refused: nothing was loosened"
	// No action was lost (gaps.Restored): the line names the file whose owner's rights tego gave back.
	case record.GapOwnStateModeRestored:
		return "Tego gave its owner back the rights on one of its own files, which something had taken"
	}
	if why == "" && what == "" {
		return "A gap in the record"
	}
	words := strings.ReplaceAll(why, "-", " ")
	switch what {
	case "capture":
		return "Not captured: " + words
	case "enforce":
		return "Not enforced: " + words
	case "limits":
		return "Limits not checked: " + words
	}
	return "A gap in the record: " + strings.TrimSpace(what+" "+words)
}

// endWords is a run_end line as a sentence: "Run ended, exit 0", "Run stopped by alice", "Run ended by SIGHUP".
func endWords(raw string) string {
	var p struct {
		Reason   string `json:"reason"`
		ExitCode int    `json:"exit_code"`
		Signal   int    `json:"signal"`
		By       string `json:"stopped_by"`
	}
	_ = json.Unmarshal([]byte(raw), &p) // a run_end that does not decode still ended the run
	switch p.Reason {
	case "exit":
		return "Run ended, exit " + strconv.Itoa(p.ExitCode)
	case "stopped":
		if w := who(p.By); w != "" {
			return "Run stopped by " + w
		}
		return "Run stopped"
	case "signal":
		if p.Signal != 0 {
			return "Run ended by " + signalName(p.Signal)
		}
		return "Run ended by a signal"
	case "":
		return "Run ended"
	}
	return "Run ended: " + strings.ToLower(endWord(&ledgerview.Run{EndReason: p.Reason}))
}

// reasonWords is a refusal's reason as a short phrase for a Logs row, under its text ("not on the allowed hosts");
// the code goes in its title. "" where reasonOf says nothing (a live block's refusal, a run_end). A code with no
// phrase here reads as its reasonText label with a lower-case first letter, so a label that opens with an acronym
// needs a phrase (TestEveryReasonCodeHasDashboardWords).
func reasonWords(e ledgerview.Event) string {
	if reasonOf(e) == "" {
		return ""
	}
	switch e.Reason {
	case "net-not-allowed":
		return "not on the allowed hosts"
	case "exec-not-allowed":
		return "not an allowed program"
	case "read-denied":
		return "a read the rules refuse"
	case "write-outside-contract":
		return "outside the folders it may write"
	case "delete-outside-contract", "rename-outside-contract", "mkdir-outside-contract":
		return "a change outside the folders it may write"
	case "path-unresolved":
		return "a path Tego could not resolve"
	case "net-http":
		return "an HTTP request the rules do not allow"
	case "ask-denied":
		return "a person said no"
	case "ask-timeout":
		return "nobody answered in time"
	case "mcp-tool-denied":
		return "an MCP tool the rules do not allow"
	}
	t := reasonText(e.Reason)
	r, n := utf8.DecodeRuneInString(t)
	if n == 0 {
		return ""
	}
	return string(unicode.ToLower(r)) + t[n:]
}

// pathWords is a row's text cut where it may wrap: after each "/" and ":" and at spaces, never inside a name. The
// template "pw" (logs.tmpl) puts a <wbr> between the pieces, and html/template escapes each one, so no agent-written
// text is ever trusted as markup. A path shows its folder muted (the run's home as "~/") and its file name in bold,
// the full path in its title; anything else (a command, a destination) shows whole, with the text in the title too
// when it is long enough to be clamped, or the whole line (full, masked) when the row shows part of it (shellTail).
func pathWords(s, home string, full ...string) wordsView { return pathWordsIn(s, home, "", full...) }

// pathWordsIn is pathWords with the run's working directory as a second root: a Logs row of a file of the project
// reads ./tmp/agent.out, as its Rule cell ("Writable: ./tmp/") and the contract write it, and stays one line.
func pathWordsIn(s, home, cwd string, full ...string) wordsView {
	first, _, _ := strings.Cut(s, " → ")
	if !strings.HasPrefix(first, "/") || strings.Contains(first, " ") {
		shown := s
		if len(shown) > shownMax {
			// The row clamps at a few lines; the rest of an 8 KiB command would cost the template a piece per
			// folder and colon and never be seen. The title and the line page keep it whole.
			cut := shownMax
			for cut > 0 && !utf8.RuneStart(shown[cut]) {
				cut--
			}
			shown = shown[:cut] + "…"
		}
		v := wordsView{Text: breakPieces(shown)}
		switch {
		case len(full) > 0 && full[0] != "" && full[0] != s:
			v.Title = full[0]
		case len(s) > clampChars:
			v.Title = s
		}
		return v
	}
	var v wordsView
	for _, q := range strings.SplitN(s, " → ", 2) {
		rel := relTo(q, home, cwd)
		dir, base := "", rel
		if k := strings.LastIndexByte(strings.TrimSuffix(rel, "/"), '/'); k >= 0 {
			dir, base = rel[:k+1], rel[k+1:]
		}
		v.Parts = append(v.Parts, wordsPart{Full: q, Dir: breakPieces(dir), Base: breakPieces(base)})
	}
	return v
}

// wordsView is pathWords' result: Parts for a path (two for a rename), else Text, with Title when it is long.
type wordsView struct {
	Parts []wordsPart
	Text  []piece
	Title string
}

// wordsPart is one path: Full for the title, its folder and its file name each in pieces.
type wordsPart struct {
	Full      string
	Dir, Base []piece
}

// piece is a run of text between break points. Br says a <wbr> goes before it (the piece before ended in "/" or
// ":"). Keep is set on a hyphenated word short enough to keep whole: the template puts it in a no-wrap span, so a
// browser does not break it at the hyphen ("supply-chain-" / "demo"); a longer one may break anywhere as a last
// resort, so it never pushes the page wider than the screen.
type piece struct {
	Text     string
	Br, Keep bool
}

// keepMax is the longest piece kept whole.
const keepMax = 40

// clampChars is about what three lines of a Logs row's What column hold at 1440 px; longer text also goes in the
// title. shownMax is what a row renders of a longer text (five lines on a phone, with room to spare).
const (
	clampChars = 200
	shownMax   = 1 << 10
)

// breakPieces is s cut after each "/" and ":" that is not its last character, and around each run of white space;
// nil for "".
func breakPieces(s string) []piece {
	var out []piece
	add := func(t string) {
		p := piece{Text: t, Keep: len(t) <= keepMax && len(t) > 1 && strings.Contains(t[1:], "-") && !strings.ContainsAny(t, " \t\n")}
		if n := len(out); n > 0 {
			last := &out[n-1]
			p.Br = strings.HasSuffix(last.Text, "/") || strings.HasSuffix(last.Text, ":")
			if !p.Br && !p.Keep && !last.Keep {
				last.Text += t // nothing between them for the template to mark: one piece
				return
			}
		}
		out = append(out, p)
	}
	start := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == '\n':
			if i > start {
				add(s[start:i])
			}
			j := i
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n') {
				j++
			}
			add(s[i:j])
			start, i = j, j-1
		case (c == '/' || c == ':') && i+1 < len(s):
			add(s[start : i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		add(s[start:])
	}
	return out
}

// answerPhrase is what an answer line says: "denied by somebody after 1 m 29 s".
func answerPhrase(approved bool, reason, by string, after float64) string {
	if strings.HasPrefix(by, "standing:") {
		// Tego answered it from a person's earlier "for this run" answer, at once.
		if approved {
			return "allowed by an earlier answer for the rest of this run"
		}
		return "denied by an earlier answer for the rest of this run"
	}
	if !approved && by == linewords.WithdrawnBy {
		return strings.ToLower(linewords.Withdrawn[:1]) + linewords.Withdrawn[1:]
	}
	word := "denied"
	switch {
	case approved && strings.HasSuffix(by, " always"):
		word = "allowed for the rest of the run"
	case approved:
		word = "allowed once"
	case reason == "ask-timeout":
		word = "timed out, so refused"
	case strings.HasSuffix(by, " always"):
		word = "denied for the rest of the run"
	}
	out := word
	if w := who(by); w != "" && reason != "ask-timeout" {
		out += " by " + w
	}
	if after > 0 {
		out += " after " + human(time.Duration(after*float64(time.Second)))
	}
	return out
}

// blockLabels is the label of each live-block rule of run: "Blocked live by somebody at 21:50", read from its
// live-block-added gap lines (the newest add of a rule wins).
func blockLabels(run *ledgerview.Run) map[string]string {
	out := map[string]string{}
	if run == nil || run.Kinds["gap"] == 0 {
		return out
	}
	evs := run.AllEvents()
	for i := range evs {
		e := &evs[i]
		if e.Kind != "gap" || !strings.HasSuffix(e.Target, "live-block-added") {
			continue
		}
		var p struct {
			Block *struct {
				Rule string `json:"rule"`
				By   string `json:"by"`
			} `json:"live_block"`
		}
		if json.Unmarshal([]byte(e.Raw), &p) != nil || p.Block == nil || p.Block.Rule == "" {
			continue
		}
		label := "Blocked live at " + e.TS.Local().Format("15:04")
		if w := who(p.Block.By); w != "" {
			label += " by " + w
		}
		out[p.Block.Rule] = label
	}
	return out
}

// relabelLive sets the label of each row a live block refused to its blockLabels label, reading each run once
// through find.
func relabelLive(rows []ledgerview.Row, find func(id string) *ledgerview.Run) {
	labels := map[string]map[string]string{}
	for i := range rows {
		e := &rows[i].Event
		if !strings.HasPrefix(e.Rule, "live.block[") {
			continue
		}
		l, ok := labels[e.Run]
		if !ok {
			l = blockLabels(find(e.Run))
			labels[e.Run] = l
		}
		if s, ok := l[e.Rule]; ok {
			rows[i].Label = s
		}
	}
}
