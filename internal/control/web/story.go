// SPDX-License-Identifier: Apache-2.0

package web

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// The story layer: the words and small read models that let a page say what happened in one sentence (a run's
// verdict, ledgerview.RunVerdict), show a file's name instead of the start of its folder (the path shortener), and
// name people and live blocks in words. Every function here reads what the ledger and the run's contract copy say;
// none decides anything.

func init() {
	funcs["sp"] = shortPath
	funcs["spt"] = shortTarget
	// spIn and sptIn are sp and spt with the run's working directory as a second root: ./confidential/plan.md.
	funcs["spIn"] = func(p, home, cwd string) []pathPart { return shortPathIn(p, home, cwd, maxDir) }
	funcs["sptIn"] = shortTargetIn
	funcs["story"] = storyOfRun
	funcs["readGap"] = readGap
	funcs["blockKV"] = blockKV
	funcs["homeIn"] = homeIn
	funcs["chip"] = chipOf
	funcs["runtab"] = func(runs []*ledgerview.Run, now time.Time, v map[string]ledgerview.Verdict) runTable {
		return runTable{Runs: runs, Now: now, V: v}
	}
	funcs["reasonOf"] = reasonOf
	funcs["codeOf"] = codeOf
	funcs["hl"] = func(run string, v any, observe bool, ref, lead string) map[string]any {
		return map[string]any{"Run": run, "V": v, "Obs": observe, "Ref": ref, "Lead": lead}
	}
	funcs["kindWord"] = kindWord
	funcs["blockLine"] = blockLine
	funcs["whoIn"] = whoIn
	// askRow hands the hl-ask template one approval with its run (to name people as the run recorded them) and the
	// run's home (for the path shortener).
	funcs["askRow"] = func(r *ledgerview.Run, home string, v ledgerview.Approval) map[string]any {
		return map[string]any{"Run": r.ID, "R": r, "Home": home, "V": v}
	}
	funcs["ago"] = func(ts, now time.Time) string { return human(now.Sub(ts)) }
	funcs["modeWord"] = modeWord
	funcs["askWhy"] = askWhy
	funcs["giveUp"] = giveUp
	funcs["when"] = when
	funcs["tlv"] = tlMarkedOf
	funcs["leakMark"] = leakMark
	funcs["renameOf"] = renameOf
	// secs is a count of seconds in the dashboard's one duration form (human): "29 s", "188 ms".
	funcs["secs"] = func(s float64) string { return human(time.Duration(s * float64(time.Second))) }
}

// tlMarked is what the "tlrows" template renders: the timeline's rows (tlRows) with the run's verdict, so the lines
// the banner speaks of read "Secret read" and "Sent out" in red instead of a grey "Observed" among the routine reads
// around them (QA QU-3). Watched is a tego watch run: its timeline head says once that nothing was enforced, so its
// observed rows carry no sub-line saying it again. Home is the run's home, which the targets show as "~/" (QU-12),
// as Highlights and Compare do.
type tlMarked struct {
	tlRows
	V       ledgerview.Verdict
	Watched bool
	Home    string
}

// tlMarkedOf is the "tlv" template func.
func tlMarkedOf(t tlRows, v ledgerview.Verdict, watched bool, home string) tlMarked {
	return tlMarked{tlRows: t, V: v, Watched: watched, Home: home}
}

// renameView is a rename's target on one line, "a.pyc → b.pyc", with its folder (or both, when it moved) muted
// under it and the whole text in the title (QA QU-9: the two folders wrapped a row into six lines).
type renameView struct{ From, To, Where, Full string }

// renameOf is target as a renameView when it is a rename of one path to another ("a → b"), else nil.
func renameOf(target, home string) *renameView {
	a, b, ok := strings.Cut(target, " → ")
	if !ok || !strings.HasPrefix(a, "/") || !strings.HasPrefix(b, "/") {
		return nil
	}
	da, ba := splitPath(a, home, 60)
	db, bb := splitPath(b, home, 60)
	where := "in " + da
	if da != db {
		where = "from " + da + " to " + db
	}
	return &renameView{From: ba, To: bb, Where: where, Full: target}
}

// leakMarkView is a marked timeline row's chip and sub-line; the zero value for a row the verdict does not name.
type leakMarkView struct{ Class, Word, Why string }

// leakMark is how a timeline row reads against its run's verdict (ledgerview.Verdict.Mark).
func leakMark(v ledgerview.Verdict, e ledgerview.Event) leakMarkView {
	switch v.Mark(&e) {
	case ledgerview.MarkSecret:
		why := "A secret file, read with nothing to stop it"
		if v.Kind == ledgerview.VerdictLeak {
			why = "A secret file, read just before a send to " + v.Dest()
		}
		return leakMarkView{"mk-leak mk-secret", "Secret read", why}
	case ledgerview.MarkSent:
		why := "The address the secrets were sent to; nothing stopped this send"
		if !v.Observe {
			why = "The address the secrets were sent to; the contract does not list it"
		}
		return leakMarkView{"mk-leak mk-sent", "Sent out", why}
	}
	return leakMarkView{}
}

// timelineOf is the run page's timeline for its quick filter: "refused" (refusals only), "leak" (the secret reads
// and sends the run's verdict names, ledgerview.MarkedTimeline: a watched run's "Secrets and sends"), or every row.
func (s *Server) timelineOf(all []*ledgerview.Run, run *ledgerview.Run, verdict string) *ledgerview.Timeline {
	if verdict == "leak" {
		return ledgerview.MarkedTimeline(run, ledgerview.RunVerdict(run, s.signalOf(all, run)))
	}
	return timeline(run, verdict)
}

// when is a list's start time: the clock alone for a time from today, "Yesterday 21:43" for yesterday, "Oct 26 21:43"
// earlier this year and "Oct 26 2025 21:43" before that, in the local zone the page names. A run list spans days,
// and a bare 21:43:28 next to 01:46:19 hid which came first.
func when(t, now time.Time) string {
	if t.IsZero() {
		return "—"
	}
	t, now = t.Local(), now.Local()
	day := func(x time.Time) time.Time { y, m, d := x.Date(); return time.Date(y, m, d, 0, 0, 0, 0, time.Local) }
	switch today := day(now); {
	case !day(t).Before(today):
		return t.Format("15:04:05")
	case !day(t).Before(today.AddDate(0, 0, -1)):
		return "Yesterday " + t.Format("15:04")
	case t.Year() == now.Year():
		return t.Format("Jan 2 15:04")
	}
	return t.Format("Jan 2 2006 15:04")
}

// giveUp is the ask card's note on how long the agent waits, named by the run's harness (run_start's harness):
// Codex's own client gives up at about 30 s. Other agents' limits are not known here, and the contract's ask.timeout
// is not on the ask line, so the note stays general for them.
func giveUp(harness string) string {
	if harness == "codex" {
		return "Codex gives up at about 30 s"
	}
	return "some agents give up after about 30 s"
}

// keepOf is the protections of a run's contract that a least-privilege change must keep, in words: every
// deny_read, ask_read, ask and deny_write entry.
func keepOf(l rulesview.Lists) []string {
	var out []string
	for _, g := range []struct {
		label string
		xs    []string
	}{{"Never readable: ", l.DenyRead}, {"Asks before a read: ", l.AskRead}, {"Asks before a change: ", l.Ask}, {"Protected from changes: ", l.DenyWrite}} {
		for _, x := range g.xs {
			out = append(out, g.label+x)
		}
	}
	return out
}

// cutOf is the grants a least-privilege change removes: the entries the run was granted and never used, never a
// protection (a deny or ask entry is kept even when nothing touched it: it did its job by being there).
func cutOf(d *rulesview.Drifted) []string {
	if d == nil {
		return nil
	}
	var out []string
	for _, r := range d.Rows {
		if !r.Unused || r.Guard || slices.ContainsFunc([]string{"fs.deny_read[", "fs.ask_read[", "fs.ask[", "fs.deny_write["},
			func(p string) bool { return strings.HasPrefix(r.Rule, p) }) {
			continue
		}
		out = append(out, r.Rule)
	}
	return out
}

// askWhy is the consequence line under the question: which of your rules asked, "Your rules ask before any read
// under …/.config/telemetry/".
func askWhy(rule string) string {
	in := func(p string) (string, bool) {
		v, ok := strings.CutPrefix(rule, p+"[")
		return strings.TrimSuffix(v, "]"), ok && strings.HasSuffix(rule, "]")
	}
	if v, ok := in("fs.ask_read"); ok {
		return "Your rules ask before any read under " + v
	}
	if v, ok := in("fs.ask"); ok {
		return "Your rules ask before any change under " + v
	}
	if rule == "" {
		return "A rule that asks a person"
	}
	return ruleName(rule)
}

// sensitiveOf is what makes a path a secret for run r: its contract's deny_read and ask_read entries. An fs.ask
// entry is a folder whose changes ask first, not a secret.
func (s *Server) sensitiveOf(l rulesview.Lists, r *ledgerview.Run) ledgerview.Sensitive {
	return ledgerview.Sensitive{Entries: slices.Concat(l.DenyRead, l.AskRead), Cwd: r.Cwd, Rules: s.severityRules()}
}

// verdicts reads the verdict of each run (its signalOf, against all the listed runs).
func (s *Server) verdicts(all, runs []*ledgerview.Run) map[string]ledgerview.Verdict {
	sigs := s.signals(all)
	out := make(map[string]ledgerview.Verdict, len(runs))
	for _, r := range runs {
		out[r.ID] = ledgerview.RunVerdict(r, sigs.of(r))
	}
	return out
}

// signalOf is run r's Signal as every page that judges it reads it (cached per run by ledgerview). A watched run is
// read against the allow list of the newest enforced run of the same program in all (ledgerview.ReferenceRun), so
// the project's own API it reached is not marked like the attacker's address; with no such run it keeps its own
// Signal, and the run page says that no contract was there to check its sends against.
func (s *Server) signalOf(all []*ledgerview.Run, r *ledgerview.Run) *ledgerview.RunSignal {
	return s.signals(all).of(r)
}

// sigMemo is one request's Signals: a page that judges many runs (the Overview, Runs) reads each run's contract
// lists, its own Signal and its signalOf once, however many of its parts ask, and the enforced run every watched run
// is read against once for all of them. It belongs to one request; it is not safe for concurrent use.
type sigMemo struct {
	s     *Server
	all   []*ledgerview.Run
	lists map[string]rulesview.Lists
	own   map[string]*ledgerview.RunSignal
	read  map[string]*ledgerview.RunSignal
}

func (s *Server) signals(all []*ledgerview.Run) *sigMemo {
	return &sigMemo{s: s, all: all, lists: map[string]rulesview.Lists{}, own: map[string]*ledgerview.RunSignal{},
		read: map[string]*ledgerview.RunSignal{}}
}

func (m *sigMemo) listsOf(id string) rulesview.Lists {
	l, ok := m.lists[id]
	if !ok {
		l = rulesview.RunLists(m.s.cfg.Ledger, id)
		m.lists[id] = l
	}
	return l
}

// sensitive is what makes a path a secret for r: its own contract's entries, as every page reads its Signal.
func (m *sigMemo) sensitive(r *ledgerview.Run) ledgerview.Sensitive {
	return m.s.sensitiveOf(m.listsOf(r.ID), r)
}

// ownOf is r's Signal by its own contract, not read against another run (ledgerview.Signal).
func (m *sigMemo) ownOf(r *ledgerview.Run) *ledgerview.RunSignal {
	sig, ok := m.own[r.ID]
	if !ok {
		sig = ledgerview.Signal(r, m.sensitive(r))
		m.own[r.ID] = sig
	}
	return sig
}

// of is signalOf(all, r). The result is shared by the request's callers: they read it and do not change it.
func (m *sigMemo) of(r *ledgerview.Run) *ledgerview.RunSignal {
	if sig, ok := m.read[r.ID]; ok {
		return sig
	}
	sig := m.ownOf(r)
	if ref := ledgerview.ReferenceRun(m.all, r); ref != nil {
		sig = sig.Against(ledgerview.NewReference(ref.ID, m.listsOf(ref.ID).Net, m.ownOf(ref)))
	}
	m.read[r.ID] = sig
	return sig
}

// homesOf is each listed row's run home (ledgerview.RunHome), for the path shortener.
func homesOf(rows []ledgerview.Row, snap *ledgerview.Snapshot) map[string]string {
	out := map[string]string{}
	for _, row := range rows {
		if _, ok := out[row.Run]; !ok {
			out[row.Run] = ledgerview.RunHome(snap.Find(row.Run))
		}
	}
	return out
}

// watchedLabel is the rule cell of a line of a watched run (tier observe): no rule decided it, tego watch only
// recorded it, whatever the contract copy beside it says.
const watchedLabel = "Watched only, not enforced"

// watchedRule is the rule of watched lines (ledgerview.WatchedLine) where a page names it in words: no rule decided
// them, so it reads "Watched only · " and label, the words of the rule they name (the contract entry they would have
// matched; "" takes ruleName's), and "Watched only" alone for unmatched, whose words ("Not in contract") would read as
// the default deny that refuses such a line on an enforced run.
func watchedRule(rule, label string) string {
	if rule == "" || rule == "unmatched" {
		return "Watched only"
	}
	if label == "" {
		label = ruleName(rule)
	}
	return "Watched only · " + label
}

// watchLabels relabels the rows of watched runs (tier observe) with watchedLabel.
func watchLabels(rows []ledgerview.Row, snap *ledgerview.Snapshot) {
	for i := range rows {
		watchLabel(&rows[i], snap.Find(rows[i].Run))
	}
}

// watchLabel relabels one row of run r when r is a watched run and the line was only observed.
func watchLabel(row *ledgerview.Row, r *ledgerview.Run) {
	if ledgerview.WatchedLine(r, &row.Event) {
		row.Label = watchedLabel
	}
}

// whoIn is who (askwords.go) for a principal of run r: a uid the run recorded as its launcher reads as the name the
// run recorded (launcher_user), which is the person who was there even when this computer names that uid otherwise.
func whoIn(by string, r *ledgerview.Run) string {
	w := who(by)
	if r == nil || r.User == "" {
		return w
	}
	for _, f := range strings.Fields(by) {
		uid, ok := strings.CutPrefix(f, "uid:")
		if !ok || uid != strconv.Itoa(r.UID) {
			continue
		}
		name := userName(uid)
		if name == "" {
			name = "user " + uid
		}
		if rest, ok := strings.CutPrefix(w, name); ok {
			return r.User + rest
		}
	}
	return w
}

// kindWord is a live block kind in words: Program, Destination, File or folder.
func kindWord(k liveblock.Kind) string {
	switch k {
	case liveblock.KindExec:
		return "Program"
	case liveblock.KindNet:
		return "Destination"
	case liveblock.KindPath:
		return "File or folder"
	case liveblock.KindRead:
		return "Reads of"
	case liveblock.KindWrite:
		return "Changes to"
	}
	return string(k)
}

// blockText is an active live block in words, in parts: Kind ("Reads of"), Value as the rest of the run page writes
// paths (relTo: "~/" for the run's home, "./" for its working directory), Full the value as the block holds it (the
// value's title) and Rest the who and when (": blocked by alice, from the dashboard at 23:40:12"). Written whole, the
// demo's block read /home/…/stage/with/home/.config/telemetry beside Highlights' ~/.config/telemetry/token.
type blockText struct{ Kind, Value, Full, Rest string }

// blockLine is an active live block of run r, whose home (ledgerview.RunHome) is home, in words: "Reads of
// ~/.config/telemetry: blocked by alice, from the dashboard at 23:40:12".
func blockLine(b liveblock.Entry, r *ledgerview.Run, home string) blockText {
	cwd := ""
	if r != nil {
		cwd = r.Cwd
	}
	return blockText{Kind: kindWord(b.Kind), Value: relTo(b.Value, home, cwd), Full: b.Value,
		Rest: ": blocked by " + whoIn(b.By, r) + " at " + b.At.Local().Format("15:04:05")}
}

// reasonOf is the sentence for a line's reason code, "" where it would mislead or repeat: a live block's refusal
// (the contract allows what a block refuses, ledger reason exec-not-allowed or net-not-allowed notwithstanding), and
// a run_end, whose reason is its own word.
func reasonOf(e ledgerview.Event) string {
	if e.Reason == "" || e.Kind == "run_end" || strings.HasPrefix(e.Rule, "live.block[") {
		return ""
	}
	return reasonText(e.Reason)
}

// codeOf is the reason code shown beside reasonOf's sentence: "" when there is no sentence or the sentence is the
// code itself (an unknown code).
func codeOf(e ledgerview.Event) string {
	if s := reasonOf(e); s == "" || s == e.Reason {
		return ""
	}
	return e.Reason
}

// modeWord is how a run's protection reads in a column head: watched, or enforced by Tego.
func modeWord(tier string) string {
	if tier == "observe" {
		return "watched"
	}
	return "enforced by Tego"
}

// maxDir is how many characters of a path's folder the shortener keeps before it elides the middle, in a narrow
// cell; a wider one (shortTarget's n) keeps more.
const maxDir = 34

// splitPath is a path's folder (with its trailing slash, "~/" for the run's home, elided past width characters) and its
// base name.
func splitPath(p, home string, width int) (dir, base string) {
	return splitPathIn(p, home, "", width)
}

// splitPathIn is splitPath with the run's working directory (cwd) as a second root, written "./" as the contract
// writes it (./confidential/plan.md, as the Deny notice and the Act panel say it); of the two the deeper one wins.
func splitPathIn(p, home, cwd string, width int) (dir, base string) {
	rel := relTo(p, home, cwd)
	i := strings.LastIndexByte(strings.TrimSuffix(rel, "/"), '/')
	if i < 0 {
		return "", rel
	}
	return elideDir(rel[:i+1], width), rel[i+1:]
}

// relTo is p from the run's working directory ("./src/a.py") or home ("~/.ssh/id_rsa"), the deeper of the two that
// holds it, else p.
func relTo(p, home, cwd string) string {
	underHome := home != "" && strings.HasPrefix(p, home+"/")
	switch {
	case cwd != "" && cwd != "/" && strings.HasPrefix(p, cwd+"/") && !(underHome && len(home) > len(cwd)):
		return "./" + p[len(cwd)+1:]
	case underHome:
		return "~/" + p[len(home)+1:]
	}
	return p
}

// elideDir keeps a folder's first segment and as many of its last segments as fit in width characters: the end of a
// path is where it says what it is.
func elideDir(dir string, width int) string {
	if utf8.RuneCountInString(dir) <= width {
		return dir
	}
	segs := strings.Split(strings.TrimSuffix(dir, "/"), "/")
	head, from := segs[0]+"/", 1
	if segs[0] == "" && len(segs) > 1 { // an absolute path keeps its first folder: /home/
		head, from = "/"+segs[1]+"/", 2
	}
	tail := ""
	for i := len(segs) - 1; i >= from; i-- {
		next := segs[i] + "/" + tail
		if tail != "" && utf8.RuneCountInString(head)+2+utf8.RuneCountInString(next) > width {
			break
		}
		tail = next
	}
	if head+tail == dir {
		return dir
	}
	return head + "…/" + tail
}

// pathPart is one path as the shortener shows it: Full in the title, Dir muted, Base in bold. The template "spv"
// (layout.tmpl) renders it, so every piece of agent-written text goes through html/template's escaping.
type pathPart struct{ Full, Dir, Base string }

// shortPath is a path for a narrow cell: the folder elided in the middle, the base name never cut first, "~/" for the
// run's home; a rename ("a → b") is two parts.
func shortPath(p, home string) []pathPart { return shortPathN(p, home, maxDir) }

// shortPathN is shortPath keeping up to width characters of the folder.
func shortPathN(p, home string, width int) []pathPart { return shortPathIn(p, home, "", width) }

// shortPathIn is shortPathN with the run's working directory as a second root (splitPathIn).
func shortPathIn(p, home, cwd string, width int) []pathPart {
	var out []pathPart
	for _, q := range strings.SplitN(p, " → ", 2) {
		dir, base := splitPathIn(q, home, cwd, width)
		out = append(out, pathPart{q, dir, base})
	}
	return out
}

// targetView is a row's target for the template "sptv": Parts for a path, otherwise Text (cut in the middle) with
// Full in the title.
type targetView struct {
	Parts      []pathPart
	Full, Text string
}

// shortTarget is a row's target: a path through shortPath, anything else (a destination, a command line) cut in the
// middle at n characters.
func shortTarget(target, home string, n int) targetView { return shortTargetIn(target, home, "", n) }

// shortTargetIn is shortTarget with the run's working directory as a second root: an ask for a file of the project
// reads ./confidential/plan.md.
func shortTargetIn(target, home, cwd string, n int) targetView {
	first, _, _ := strings.Cut(target, " → ")
	if strings.HasPrefix(first, "/") && !strings.Contains(first, " ") {
		return targetView{Parts: shortPathIn(target, home, cwd, max(maxDir, n*2/3))}
	}
	return targetView{Full: target, Text: cutMiddle(target, n)}
}

// storyText is a verdict as the run page's banner says it.
type storyText struct {
	// Tone is leak, ok or neutral; Icon the sprite id.
	Tone, Icon, Title, Sub string
}

// plural4 is "1 secret read" / "2 secret reads".
func plural4(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// destWords is "127.0.0.1:45805", or "127.0.0.1:45805 and 1 more".
func destWords(ds []string) string {
	if len(ds) <= 1 {
		return strings.Join(ds, "")
	}
	return ds[0] + " and " + strconv.Itoa(len(ds)-1) + " more"
}

// baseNames is "id_rsa, token" for paths.
func baseNames(ps []string) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = path.Base(p)
	}
	return strings.Join(out, ", ")
}

// storyOf is the run page's verdict banner: red when secrets left, green when Tego stopped an attempt, neutral
// otherwise. The title is the fact; the second line is labels, joined with " · ".
func storyOf(v ledgerview.Verdict, live bool) storyText {
	if v.Partial {
		v.Partial = false
		st := storyOf(v, live)
		st.Title = "In this event window: " + st.Title
		st.Sub = "This verdict does not cover every recorded event; inspect the ledger for the full record."
		return st
	}
	switch v.Kind {
	case ledgerview.VerdictLeak:
		st := storyText{Tone: "leak", Icon: "i-triangle-alert",
			Title: "Secrets left: " + baseNames(v.Exposed) + " sent to " + v.Dest()}
		st.Sub = "Not in contract"
		if v.Observe {
			st.Sub = "Watched only · nothing refused"
		}
		return st
	case ledgerview.VerdictProtected:
		// Each count names its own destination (RefusedWords), and the total is Stopped: the number the Runs chip
		// and Compare's sentence print.
		st := storyText{Tone: "ok", Icon: "i-shield", Title: "Protected: " + v.RefusedWords() + " refused"}
		var sub []string
		if v.Asked > 0 {
			sub = append(sub, plural4(v.Asked, "request", "requests")+" asked")
		}
		st.Sub = strings.Join(append(sub, lookupsWords(v)...), " · ")
		return st
	case ledgerview.VerdictWatched:
		st := storyText{Tone: "neutral", Icon: "i-eye",
			Title: "Watched only: " + plural4(len(v.Read), "secret", "secrets") + " read, " + noNewDest(len(v.Read)),
			Sub:   "Nothing refused"}
		if v.Reached > 0 {
			st.Sub += " · " + plural4(v.Reached, "destination", "destinations") + " reached"
		}
		return st
	}
	st := storyText{Tone: "neutral", Icon: "i-check", Title: "No attack seen"}
	if live {
		st.Title = "No attack seen yet"
	}
	var sub []string
	if v.Observe {
		sub = append(sub, "Watched only")
	}
	st.Sub = strings.Join(append(sub, lookupsWords(v)...), " · ")
	return st
}

// storyOfRun is the run page's banner (storyOf) for run r. On a run that kept no file read, "nothing seen" is only
// what was recorded: a refused read of a secret may have left no line (readGap), so the banner says reads went
// unrecorded instead of standing as an all-clear.
func storyOfRun(v ledgerview.Verdict, r *ledgerview.Run) storyText {
	st := storyOf(v, r != nil && r.State() == "running")
	if readGap(r) == "" || v.Kind == ledgerview.VerdictLeak || v.Kind == ledgerview.VerdictProtected {
		return st
	}
	if v.Kind != ledgerview.VerdictWatched {
		st.Title = strings.Replace(st.Title, "No attack seen", "No attack seen in the record", 1) // "… record yet" while live
	}
	sub := "File reads not recorded"
	if st.Sub != "" {
		sub += " · " + st.Sub
	}
	st.Sub = sub
	return st
}

// readGap is what the secret lists of a run that kept no file read cannot show (Run.ReadsUnrecorded), in the words
// the run page, its receipt, Compare and the Overview share; "" for a run that kept its reads, or whose run_start
// does not say. The "readfix" template names the contract setting that keeps them.
func readGap(r *ledgerview.Run) string {
	switch {
	case r == nil || !r.ReadsUnrecorded:
		return ""
	case r.RefusedReadsUnseen:
		return "File reads were not recorded, refused ones included, so a secret the agent tried to read is not listed."
	case r.RefusedReadsUnknown: // tego receipt's words for the same record (receipt.readsNote)
		return "Allowed file reads were not recorded, so a secret the agent read is not listed; a refused read may be missing too."
	}
	return "Allowed file reads were not recorded, so a secret the agent read is not listed."
}

// noNewDest is what a watched verdict can say about sends after n secret reads: no destination was first contacted
// next to them. It cannot say that nothing was sent. A send seconds later, or to a host the run already talked to, is
// not next to anything by the verdict's window, and reading every contact as near would call each of an agent's calls to
// its model a leak.
func noNewDest(n int) string {
	if n == 1 {
		return "no new destination next to it"
	}
	return "no new destination next to them"
}

// lookupsWords is the banner's label for the routine lookups Tego also blocked (nscd, DNS: what the C library does
// around any connect), which the verdict never counts; none for none. It goes in the second line only, so the
// title's count stays the chip's.
func lookupsWords(v ledgerview.Verdict) []string {
	if v.Lookups == 0 {
		return nil
	}
	return []string{plural4(v.Lookups, "routine lookup", "routine lookups")}
}

// chipText is a verdict as a Runs or Overview row's Secrets cell says it.
type chipText struct {
	Class, Icon, Text, Title string
}

// chipOf is the Secrets cell: "2 exposed" in red, "2 protected" in green, "1 read" on a watched run, else none.
// Both sides count distinct secrets (len(Exposed), Verdict.Protected); the refusals behind a protected count are in
// its title: "2 secrets kept; 2 secret reads and 2 sends to 127.0.0.1:9821 refused".
func chipOf(v ledgerview.Verdict) chipText {
	if v.Partial {
		v.Partial = false
		c := chipOf(v)
		if c.Text == "" {
			c = chipText{"b-observed", "i-eye", "partial", "This verdict does not cover every recorded event"}
		} else {
			c.Title += "; some events are not covered"
		}
		return c
	}
	switch v.Kind {
	case ledgerview.VerdictLeak:
		return chipText{"b-bad", "i-triangle-alert", strconv.Itoa(len(v.Exposed)) + " exposed",
			baseNames(v.Exposed) + " read just before a send to " + destWords(v.Dests)}
	case ledgerview.VerdictProtected:
		if n := v.Protected(); n > 0 {
			return chipText{"b-good", "i-shield", strconv.Itoa(n) + " protected",
				plural4(n, "secret", "secrets") + " kept (" + baseNames(v.Kept) + "); " + v.RefusedWords() + " refused"}
		}
		// Stopped with no secret path to name (a refused send whose secret line is not kept): count the attempts.
		return chipText{"b-good", "i-shield", strconv.Itoa(v.Stopped()) + " stopped", v.RefusedWords() + " refused"}
	case ledgerview.VerdictWatched:
		return chipText{"b-observed", "i-eye", strconv.Itoa(len(v.Read)) + " read", baseNames(v.Read) + " read; " + noNewDest(len(v.Read))}
	}
	return chipText{}
}

// overviewStory fills the Overview's verdicts: each run's (the Secrets column), how many runs leaked and how many were
// watched reading secrets (the headline), the refused lines split as the run pages split them (the Stopped tile), the
// listed refusals' run homes, and the link that compares the newest watched run with the newest enforced one.
func (s *Server) overviewStory(snap *ledgerview.Snapshot, sigs *sigMemo, d *overviewData) {
	d.V = make(map[string]ledgerview.Verdict, len(snap.Runs))
	for _, r := range snap.Runs {
		sig := sigs.of(r)
		v := ledgerview.RunVerdict(r, sig)
		d.V[r.ID] = v
		switch v.Kind {
		case ledgerview.VerdictLeak:
			d.Leaked++
		case ledgerview.VerdictWatched:
			d.Watched++
		}
		d.Matter += sig.RealLines
		d.BgTotal += sig.BackgroundLines
	}
	d.Homes = homesOf(slices.Concat(d.Refusals, d.Background), snap)
	if p := cmpPick(snap.Runs); p.A != "" && p.B != "" {
		d.CmpURL = "/compare?a=" + p.A + "&b=" + p.B
	}
}

// blockKind is a live block's value split into its kind and what it names: "read:/srv/x" is Kind "read" and Path
// "/srv/x", so the run page shows the folder the way its other paths read (~/.config/telemetry), never the raw
// "read:/home/..." key; "exec:ls" and "net:host:443" keep their value in Value.
type blockKind struct{ Kind, Path, Value string }

// blockKV splits a live block's value (liveblock's <kind>:<value>, as ledgerview.BlockHit carries it).
func blockKV(v string) blockKind {
	kind, val, ok := strings.Cut(v, ":")
	if !ok || val == "" {
		return blockKind{Value: v}
	}
	if kind == "read" || kind == "write" {
		return blockKind{Kind: kind, Path: val}
	}
	return blockKind{Kind: kind, Value: val}
}

// homeIn writes each path in a rule's words that starts with the run's home as ~/…, the way the row's own path
// reads ("Never read: ~/.ssh/id_rsa"). Only a path that starts the text or follows a space is
// shortened, so a folder that merely ends in the same names is left whole; the rule key stays in the title.
func homeIn(s, home string) string {
	if home == "" || home == "/" {
		return s
	}
	pre := home + "/"
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], pre) && (i == 0 || s[i-1] == ' ') {
			b.WriteString("~/")
			i += len(pre)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
