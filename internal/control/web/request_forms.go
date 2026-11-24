// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// A person is never offered Allow once beside a request they cannot read in full there (ADR 0123, "Request sentence
// forms"). A waiting request's sentence (who, what, the target) has two forms. FULL shows every character, wrapped
// and never clamped. LONG is used where the sentence passes a width's bound: the server shortens the target in the
// middle, keeping the parts a decision turns on, and the place that shows it offers one action, Review request, in
// place of Allow once and Deny. The request's own card on Approvals always shows the FULL form with its answers.
//
// The bounds count characters. They were measured in headless Chrome by filling the real banners with host, path and
// command sentences of every length from 60 to 320 characters, two agent names, and counting line boxes: at 320 px
// the phone banner's 16 px sentence held at most four lines up to 112 to 126 characters (the least, 112, is a path
// named by a 20-character agent), and at 1280 px the wide sentence held two lines up to 166 characters on the shared
// banner and 154 on Overview's. TestFix5FullRequestInChrome holds the FULL form at these bounds to four and two
// lines. The markup carries both answers and the style sheets pick by width with phone-only and desktop-only
// (600 px); between 601 and 1279 px the FULL form may take more lines, never hiding any. The safe answer does not
// depend on a style sheet: the phone's cut sentence is hidden by its own attribute in the markup, the style sheet only
// reveals it at 600 px and under, and the quick form is in the markup only where the wide sentence is FULL.
const (
	phoneRequestBound = 112
	wideRequestBound  = 150
	// An agent's name is cut only when it alone passes its own bound.
	phoneAgentBound = 40
	wideAgentBound  = 60
	// requestTargetLeast is the least of a LONG target kept, whatever the name and verb take.
	requestTargetLeast = 32
)

// requestForm is a request's sentence as one width shows it: the name and target whole, or LONG and cut.
type requestForm struct {
	Long   bool
	Agent  string
	Target string
}

// requestView is one waiting request with the sentence's two forms.
type requestView struct {
	ledgerview.Ask
	// Full is the complete sentence: the accessible name carries it in both forms.
	Full        string
	Phone, Wide requestForm
}

// Quick reports whether the quick answers may be in the markup at all: never when the wide form is LONG (the phone
// form is then LONG too).
func (v requestView) Quick() bool { return !v.Wide.Long }

// QuickClass hides the quick answers on a phone when only the phone form is LONG; Review request takes their place.
func (v requestView) QuickClass() string {
	if v.Phone.Long {
		return " desktop-only"
	}
	return ""
}

// requestNamed is a LONG wide sentence with or without the agent's name in front (Overview's single request names
// the agent in its heading).
type requestNamed struct {
	requestView
	Named bool
}

// Named hands the LONG wide sentence its name, or not.
func (v requestView) Named(named bool) requestNamed { return requestNamed{v, named} }

// requestOf is a waiting request's sentence in both forms. The phone form writes the target exactly; the wide form
// reads a file's names against the run's home and working directory (~/…, ./…), as the wide banner has always shown
// them: run is the request's askMeta (or nothing). A sentence's length counts the name, " wants to ", the longer of
// the two verbs a request is shown with (askVerb, bandVerb) and the target as that form writes it.
func requestOf(a ledgerview.Ask, run any) requestView {
	// The ledger's text is valid UTF-8; anything else becomes the replacement character before a cut can split it.
	agent, target := strings.ToValidUTF8(a.Agent, "\uFFFD"), strings.ToValidUTF8(a.Target, "\uFFFD")
	if agent == "" {
		agent = "An agent"
	}
	whole := "(no target named)"
	if target != "" {
		whole = visibleText(target)
	}
	verb := askVerb(a.Op, a.Rule, a.Hold)
	// The accessible name is built from the same visible text the eye reads (control and bidi characters as
	// ⟦U+XXXX⟧), so a screen reader hears what is shown.
	v := requestView{Ask: a, Full: visibleText(agent) + " wants to " + verb + " " + whole}
	fixed := utf8.RuneCountInString(" wants to  ") + max(utf8.RuneCountInString(verb), utf8.RuneCountInString(bandVerb(a.Op, a.Rule, a.Hold)))
	m := metaOf(run)
	agent = visibleText(agent)
	v.Phone = requestFormOf(a.Op, a.Hold, agent, visibleText(target), fixed, phoneRequestBound, phoneAgentBound)
	// The wide bounds are the larger and a wide target is never longer, so a LONG wide form always has a LONG phone
	// form (TestRequestFormsOrdered).
	v.Wide = requestFormOf(a.Op, a.Hold, agent, visibleText(requestShown(target, m.Home, m.Cwd)), fixed, wideRequestBound, wideAgentBound)
	return v
}

// requestShown is a target as the banners write it: each name of a file read against the run's home and working
// directory (requestTarget's rule), anything else as it is.
func requestShown(target, home, cwd string) string {
	first, _, _ := strings.Cut(target, " → ")
	if !strings.HasPrefix(first, "/") || strings.Contains(first, " ") {
		return target
	}
	names := strings.SplitN(target, " → ", 2)
	for i, name := range names {
		names[i] = relTo(name, home, cwd)
	}
	return strings.Join(names, " → ")
}

func requestFormOf(op, hold, agent, target string, fixed, bound, agentBound int) requestForm {
	n := utf8.RuneCountInString
	whole := n(target)
	if target == "" {
		whole = n("(no target named)")
	}
	if n(agent)+fixed+whole <= bound {
		return requestForm{Agent: agent, Target: target}
	}
	if n(agent) > agentBound {
		agent = cutMiddle(agent, agentBound)
	}
	room := max(bound-fixed-n(agent), requestTargetLeast)
	return requestForm{Long: true, Agent: agent, Target: cutTarget(op, hold, target, room)}
}

// cutTarget is target in at most n characters, cut once in the middle with one ellipsis, keeping what a decision
// turns on: of a network target the first label and the end of the host with the port, of a file the leading folders
// and the end with the file name, of a command the program and first arguments and its last characters.
func cutTarget(op, hold, target string, n int) string {
	if utf8.RuneCountInString(target) <= n {
		return target
	}
	switch {
	case op == "connect" || op == "send" || op == "first_write" || op == "request" || (op == "" && hold == "net"):
		return cutHost(target, n)
	case op == "exec" || op == "mcp_tool":
		return cutCommand(target, n)
	case strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~/") || strings.HasPrefix(target, "./"):
		return cutPath(target, n)
	}
	return cutMiddle(target, n)
}

func cutHost(t string, n int) string {
	host, port := t, ""
	// A port is at most five digits; a longer run of digits is part of the host's text and is cut with it.
	if i := strings.LastIndexByte(t, ':'); i > 0 && i+1 < len(t) && len(t)-i-1 <= 5 && strings.Trim(t[i+1:], "0123456789") == "" &&
		(!strings.Contains(t[:i], ":") || strings.HasSuffix(t[:i], "]")) {
		host, port = t[:i], t[i:]
	}
	head := host
	if i := strings.IndexByte(host, '.'); i >= 0 {
		head = host[:i+1]
	}
	if utf8.RuneCountInString(head) > n/3 {
		head = firstRunes(head, n/3)
	}
	rest, room := host[len(head):], n-utf8.RuneCountInString(head)-1-utf8.RuneCountInString(port)
	for i := 0; i < len(rest); i++ {
		if (i == 0 || rest[i-1] == '.') && utf8.RuneCountInString(rest[i:]) <= room {
			return head + "…" + rest[i:] + port
		}
	}
	return head + "…" + lastRunes(rest, room) + port
}

func cutPath(t string, n int) string {
	if a, b, ok := strings.Cut(t, " → "); ok {
		m := (n - 3) / 2
		return cutPath(a, m) + " → " + cutPath(b, n-3-m)
	}
	if utf8.RuneCountInString(t) <= n {
		return t
	}
	i := strings.LastIndexByte(t, '/')
	if i < 0 {
		// A half of a rename may be any text the agent chose: with no slash the whole text is the name.
		return cutMiddle(t, n)
	}
	name := t[i:]
	// The leading folders get the room the file name leaves; a file name too long for that keeps its end.
	room := n - 1 - utf8.RuneCountInString(name)
	if room < n/3 {
		room = n / 3
	}
	head := firstRunes(t, room)
	if i := strings.LastIndexByte(head, '/'); i > 0 {
		head = head[:i+1]
	}
	tail := lastRunes(t[len(head):], n-1-utf8.RuneCountInString(head))
	if j := strings.IndexByte(tail, '/'); j > 0 && len(tail)-j >= len(name) {
		tail = tail[j:]
	}
	return head + "…" + tail
}

func cutCommand(t string, n int) string {
	headRoom := n * 3 / 5
	head := firstRunes(t, headRoom)
	if i := strings.LastIndexByte(head, ' '); i >= 0 && utf8.RuneCountInString(head[:i+1]) >= headRoom/2 {
		head = head[:i+1]
	}
	return head + "…" + lastRunes(t[len(head):], n-1-utf8.RuneCountInString(head))
}

func firstRunes(s string, n int) string {
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}

func lastRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return trimMarks(string(r[len(r)-n:]))
}

// trimMarks drops the combining marks a kept tail starts with: cut from their base letter they would attach to the
// ellipsis. A cut head may end on a base letter whose marks were cut away; that reads whole.
func trimMarks(s string) string {
	return strings.TrimLeftFunc(s, func(r rune) bool { return unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) })
}
