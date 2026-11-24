// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
	"text/template/parse"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// requestCase is one waiting request of the V1 matrix: the sentence just under and just over each bound, the review's
// 200-character host, a deep path and a 4,000-character command. The Chrome test renders the same cases.
type requestCase struct {
	Name, Agent, Op, Hold, Target string
	// Head and Tail are what a LONG form must keep at its two ends.
	Head, Tail string
}

const longAgent = "agent-planning-planning-planning-planning-planning-planning-planning-planning-planning-planning-operator"

// sentenceOf is a request whose sentence is exactly n characters: a network target of whole labels and a last
// shorter one before the kept end, or a path of whole folders and a last shorter one before the file name.
func sentenceOf(name, agent, op, hold string, n int, unit, end, head string) requestCase {
	pad := n - (utf8.RuneCountInString(agent) + utf8.RuneCountInString(" wants to  ") + max(utf8.RuneCountInString(askVerb(op, "", hold)), utf8.RuneCountInString(bandVerb(op, "", hold))))
	body := head
	for len(body)+len(unit)+len(end)+2 <= pad {
		body += unit
	}
	sep := unit[len(unit)-1:]
	body += strings.Repeat("a", pad-len(body)-len(end)-1) + sep + end
	return requestCase{Name: name, Agent: agent, Op: op, Hold: hold, Target: body, Head: head, Tail: end}
}

func requestCases() []requestCase {
	command := "/usr/bin/worker "
	for len(command) < 4000-len("--label='two  spaces' --output=/work/final-report.json") {
		command += "--input=/work/deep/source.data "
	}
	command = command[:4000-len("--label='two  spaces' --output=/work/final-report.json")] + "--label='two  spaces' --output=/work/final-report.json"
	path := func(name string, n int) requestCase {
		return sentenceOf(name, "claude-code-reviewer", "write", "fs", n, "customer-support/", "report.json", "/home/dana/")
	}
	host := func(name string, n int) requestCase {
		return sentenceOf(name, "codex", "connect", "net", n, "longlabel.", "example.com:443", "longlabel.")
	}
	return []requestCase{
		{Name: "short", Agent: "codex", Op: "connect", Hold: "net", Target: "example.com:443"},
		{Name: "medium", Agent: "agent-planning-operator", Op: "write", Hold: "fs", Target: "/work/reports/2026/quarterly-summary.json"},
		path("under-phone", phoneRequestBound),
		path("over-phone", phoneRequestBound+1),
		host("under-wide", wideRequestBound),
		host("over-wide", wideRequestBound+1),
		{Name: "long-host", Agent: longAgent, Op: "connect", Hold: "net", Target: strings.Repeat("longlabel.", 20) + ":443", Head: "longlabel.", Tail: "longlabel.:443"},
		{Name: "deep-path", Agent: longAgent, Op: "write", Hold: "fs", Target: "/work/" + strings.Repeat("deep-folder/", 24) + "report.json", Head: "/work/", Tail: "/report.json"},
		{Name: "long-command", Agent: longAgent, Op: "exec", Hold: "exec", Target: command, Head: "/usr/bin/worker --input=", Tail: "/work/final-report.json"},
	}
}

func sentenceLen(f requestForm, a ledgerview.Ask) int {
	target := f.Target
	if target == "" {
		target = "(no target named)"
	}
	return utf8.RuneCountInString(f.Agent) + utf8.RuneCountInString(" wants to  ") + max(utf8.RuneCountInString(askVerb(a.Op, a.Rule, a.Hold)), utf8.RuneCountInString(bandVerb(a.Op, a.Rule, a.Hold))) + utf8.RuneCountInString(target)
}

func TestRequestFormsOrdered(t *testing.T) {
	if wideRequestBound < phoneRequestBound || wideAgentBound < phoneAgentBound {
		t.Fatal("a LONG wide form must imply a LONG phone form: the wide bounds are the larger")
	}
	longestVerb := 0
	for _, op := range []string{"", "read", "unlink", "mkdir", "rename", "symlink", "link", "write", "open", "connect", "send", "request", "exec", "mcp_tool"} {
		longestVerb = max(longestVerb, utf8.RuneCountInString(askVerb(op, "", "net")), utf8.RuneCountInString(bandVerb(op, "", "net")))
	}
	if phoneAgentBound+utf8.RuneCountInString(" wants to  ")+longestVerb+requestTargetLeast > phoneRequestBound {
		t.Fatal("a LONG phone sentence with a cut name and the longest verb does not fit its bound")
	}
}

func TestRequestFormCuts(t *testing.T) {
	cases := append(requestCases(),
		requestCase{Name: "long-file-name", Agent: "codex", Op: "read", Hold: "fs", Target: "/home/dana/customer-support/" + strings.Repeat("folder/", 12) + strings.Repeat("final", 36) + ".json", Head: "/home/dana/", Tail: "final.json"},
		requestCase{Name: "rename", Agent: "codex", Op: "rename", Hold: "fs", Target: "/work/" + strings.Repeat("a-folder/", 8) + "old.txt → /work/" + strings.Repeat("b-folder/", 8) + "new.txt", Head: "/work/", Tail: "/new.txt"},
		requestCase{Name: "long-agent", Agent: strings.Repeat("Mira", 15) + strings.Repeat("x", 60), Op: "connect", Hold: "net", Target: "example.com:443", Head: "example.com:443", Tail: "example.com:443"},
		requestCase{Name: "ipv6", Agent: longAgent, Op: "connect", Hold: "net", Target: "[2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff]:8443", Head: "[", Tail: "]:8443"},
	)
	for _, tc := range cases {
		a := ledgerview.Ask{Agent: tc.Agent, Op: tc.Op, Hold: tc.Hold, Target: tc.Target, Run: "r", AskID: "a"}
		v := requestOf(a, nil)
		full := sentenceLen(requestForm{Agent: tc.Agent, Target: tc.Target}, a)
		for _, w := range []struct {
			name         string
			f            requestForm
			bound, agent int
		}{{"phone", v.Phone, phoneRequestBound, phoneAgentBound}, {"wide", v.Wide, wideRequestBound, wideAgentBound}} {
			if w.f.Long != (full > w.bound) {
				t.Errorf("%s/%s: sentence of %d characters, bound %d, LONG %v", tc.Name, w.name, full, w.bound, w.f.Long)
			}
			if !w.f.Long {
				if w.f.Agent != tc.Agent || w.f.Target != tc.Target {
					t.Errorf("%s/%s: FULL form changed the name or target", tc.Name, w.name)
				}
				continue
			}
			if n := sentenceLen(w.f, a); n > w.bound {
				t.Errorf("%s/%s: LONG sentence of %d characters passes its bound %d: %q", tc.Name, w.name, n, w.bound, w.f.Target)
			}
			if (utf8.RuneCountInString(tc.Agent) > w.agent) != (w.f.Agent != tc.Agent) {
				t.Errorf("%s/%s: the name is cut only when it alone passes its bound: %q", tc.Name, w.name, w.f.Agent)
			}
			// One ellipsis marks each cut: a cut name, and each name of a target (a rename names two).
			for _, part := range []struct{ shown, whole string }{{w.f.Agent, tc.Agent}, {w.f.Target, tc.Target}} {
				for _, name := range strings.Split(part.shown, " → ") {
					if part.shown != part.whole && !strings.Contains(part.whole, name) && strings.Count(name, "…") != 1 {
						t.Errorf("%s/%s: a cut keeps one ellipsis: %q", tc.Name, w.name, name)
					}
				}
			}
			if w.f.Agent != tc.Agent && (!strings.HasPrefix(w.f.Agent, firstRunes(tc.Agent, 8)) || !strings.HasSuffix(w.f.Agent, lastRunes(tc.Agent, 8))) {
				t.Errorf("%s/%s: a cut name keeps both ends: %q", tc.Name, w.name, w.f.Agent)
			}
			if !strings.HasPrefix(w.f.Target, tc.Head) || !strings.HasSuffix(w.f.Target, tc.Tail) {
				t.Errorf("%s/%s: LONG target %q lost a kept end (%q … %q)", tc.Name, w.name, w.f.Target, tc.Head, tc.Tail)
			}
			t.Logf("%s/%s: %d → %d characters: %s wants to %s %s", tc.Name, w.name, full, sentenceLen(w.f, a), w.f.Agent, askVerb(a.Op, "", a.Hold), w.f.Target)
		}
		if v.Full != tc.Agent+" wants to "+askVerb(tc.Op, "", tc.Hold)+" "+tc.Target {
			t.Errorf("%s: the accessible sentence is not whole", tc.Name)
		}
	}
}

// answerAction is where every answer to a request is posted, whatever the button says or how its tag is written.
const answerAction = "/approvals/answer"

// formClass is a quick form's class attribute, in any quoting: the class the form carries and the view it asks.
var formClass = regexp.MustCompile(`(?is)\bclass\s*=\s*["']?ab-act\{\{\$(\w+)\.QuickClass\}\}`)

// TestNoQuickActionsBesideLongRequest proves that no delivered template can render the quick answers (Allow once,
// Deny) beside a LONG request sentence. Source: every form of every template whose action is /approvals/answer (found
// by the action, in any quoting and attribute order, not by the buttons' words), in every branch, is either in
// askform, which only the request's own cards invoke beside the exact target box, or inside the branch of
// {{if $r.Quick}} of a form whose class carries {{$r.QuickClass}} for the same requestView, built by request; and no
// script builds such a form. Rendering: each of the three banners, for a FULL, a phone-LONG and a LONG request,
// carries the answers only where the same width's sentence is FULL, and with no style sheet at all the cut sentence
// is hidden by its own attribute wherever a quick form is in the markup.
func TestNoQuickActionsBesideLongRequest(t *testing.T) {
	files, err := fs.Glob(assets, "templates/*.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	type found struct{ file, define, cond, class, bound string }
	var buttons []found
	callers := map[string][]string{}
	quick := regexp.MustCompile(`^not \$(\w+)\.Wide\.Long$|^\$(\w+)\.Quick$`)
	for _, file := range files {
		b, err := fs.ReadFile(assets, file)
		if err != nil {
			t.Fatal(err)
		}
		trees := map[string]*parse.Tree{}
		tree := parse.New(file)
		tree.Mode = parse.SkipFuncCheck | parse.ParseComments
		if _, err := tree.Parse(string(b), "{{", "}}", trees); err != nil {
			t.Fatal(err)
		}
		for name, tr := range trees {
			if tr.Root == nil {
				continue
			}
			bound := map[string]string{}
			// last is the markup the list has written before a node, actions as {{pipeline}}, so a button's form tag is
			// found however many actions lie between them.
			var visit func(n parse.Node, cond string, last string)
			visit = func(n parse.Node, cond, last string) {
				switch n := n.(type) {
				case *parse.ListNode:
					if n == nil {
						return
					}
					acc := last
					for _, c := range n.Nodes {
						visit(c, cond, acc)
						switch c := c.(type) {
						case *parse.TextNode:
							acc += string(c.Text)
						case *parse.ActionNode:
							acc += "{{" + c.Pipe.String() + "}}"
						default:
							acc += "{{…}}"
						}
					}
				case *parse.ActionNode:
					if len(n.Pipe.Decl) == 1 && len(n.Pipe.Cmds) == 1 {
						bound[n.Pipe.Decl[0].String()] = n.Pipe.Cmds[0].String()
					}
				case *parse.TextNode:
					text := string(n.Text)
					for from := 0; ; {
						i := strings.Index(text[from:], answerAction)
						if i < 0 {
							break
						}
						at := from + i
						from = at + len(answerAction)
						before := last + text[:at]
						start := strings.LastIndex(before, "<form")
						if start < 0 || strings.Contains(before[start:], ">") {
							buttons = append(buttons, found{file, name, cond, "(not inside a form tag)", ""})
							continue
						}
						tag := before[start:] + text[at:]
						if end := strings.IndexByte(tag[len(before)-start:], '>'); end >= 0 {
							tag = tag[:len(before)-start+end]
						}
						buttons = append(buttons, found{file, name, cond, tag, ""})
					}
				case *parse.IfNode:
					visit(n.List, n.Pipe.String(), "")
					visit(n.ElseList, "else "+n.Pipe.String(), "")
				case *parse.WithNode:
					visit(n.List, cond, last)
					visit(n.ElseList, cond, last)
				case *parse.RangeNode:
					visit(n.List, cond, last)
					visit(n.ElseList, cond, last)
				case *parse.TemplateNode:
					callers[n.Name] = append(callers[n.Name], name)
				}
			}
			visit(tr.Root, "", "")
			for i := range buttons {
				if buttons[i].file == file && buttons[i].define == name {
					if m := quick.FindStringSubmatch(buttons[i].cond); m != nil {
						buttons[i].bound = bound["$"+m[1]+m[2]]
					}
				}
			}
		}
	}
	if len(buttons) == 0 {
		t.Fatal("found no answer form: the walker is blind")
	}
	guarded := 0
	for _, b := range buttons {
		switch {
		case b.define == "askform":
		case quick.MatchString(b.cond):
			m := quick.FindStringSubmatch(b.cond)
			v := "$" + m[1] + m[2]
			if m := formClass.FindStringSubmatch(b.class); m == nil || "$"+m[1] != v {
				t.Errorf("%s %s: quick answers in {{if %s}} without %s.QuickClass on their form: %q", b.file, b.define, b.cond, v, b.class)
			}
			if !strings.HasPrefix(b.bound, "request ") {
				t.Errorf("%s %s: %s is not a requestView built by request: %q", b.file, b.define, v, b.bound)
			}
			guarded++
		default:
			t.Errorf("%s %s: an answer form outside askform and outside a {{if $r.Quick}} branch (in %q): %q", b.file, b.define, b.cond, b.class)
		}
	}
	scripts, err := fs.Glob(assets, "static/*.js")
	if err != nil || len(scripts) == 0 {
		t.Fatalf("no scripts found: %v", err)
	}
	for _, script := range scripts {
		b, err := fs.ReadFile(assets, script)
		if err != nil {
			t.Fatal(err)
		}
		// live.js only recognises the form's path when a person submits it; nothing builds a form or a request to it.
		if n := strings.Count(string(b), answerAction); n > 0 && (script != "static/live.js" || n != 1 || !strings.Contains(string(b), "path === '/approvals/answer' ? 'answer'")) {
			t.Errorf("%s names %s %d times: a script may only recognise the path, never build an answer", script, answerAction, n)
		}
	}
	if guarded != 3 {
		t.Errorf("guarded quick answers in %d places, want the three banners (shared, Overview, Approvals)", guarded)
	}
	for _, caller := range callers["askform"] {
		if caller != "ap-card" && caller != "askcard" {
			t.Errorf("askform is invoked by %s, not by a request card that shows the exact target whole", caller)
		}
	}
	for _, card := range []string{"ap-card", "askcard"} {
		if !slices.Contains(callers["askform"], card) {
			t.Errorf("%s no longer invokes askform: re-examine this proof", card)
		}
	}

	// Rendering, for the shared banner (/runs), Overview's and the Approvals compact banner.
	short := ledgerview.Ask{Agent: "codex", Op: "connect", Hold: "net", Target: "example.com:443"}
	phoneOnly := sentenceOf("", "codex", "connect", "net", phoneRequestBound+10, "longlabel.", "example.com:443", "longlabel.")
	both := sentenceOf("", "codex", "connect", "net", wideRequestBound+10, "longlabel.", "example.com:443", "longlabel.")
	for _, tc := range []struct {
		name               string
		target             string
		phoneLong, wideLog bool
	}{{"full", short.Target, false, false}, {"phone-long", phoneOnly.Target, true, false}, {"long", both.Target, true, true}} {
		root := fixture(t)
		appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "answer", `"ask_id":"ask-7","approved":false`))
		appendLine(t, root, harmRun, line(harmRun, "codex", 8, time.Now(), "ask", fmt.Sprintf(`"ask_id":"forms","hold":"net","op":"connect","target":%q`, tc.target)))
		s := newServer(t, root)
		c := login(t, s)
		v := requestOf(ledgerview.Ask{Agent: "codex", Op: "connect", Hold: "net", Target: tc.target}, nil)
		if v.Phone.Long != tc.phoneLong || v.Wide.Long != tc.wideLog {
			t.Fatalf("%s: case does not have the forms it names", tc.name)
		}
		for _, path := range []string{"/runs", "/", "/approvals"} {
			w := doRaw(s, "GET", path, "127.0.0.1:8484", c)
			if w.Code != 200 {
				t.Fatalf("%s %s: %d", tc.name, path, w.Code)
			}
			page := w.Body.String()
			start := strings.Index(page, `id="ask-banner"`)
			if start < 0 {
				t.Fatalf("%s %s: no banner", tc.name, path)
			}
			banner := page[strings.LastIndex(page[:start], "<section"):]
			banner = banner[:strings.Index(banner, "</section>")]
			approve := strings.Count(banner, `value="approve"`)
			forms := regexp.MustCompile(`<form class="ab-act([^"]*)"`).FindAllStringSubmatch(banner, -1)
			reviews := regexp.MustCompile(`<p class="ab-review([^"]*)"`).FindAllStringSubmatch(banner, -1)
			phoneShort := strings.Contains(banner[strings.Index(banner, `class="ab-summary"`):], "…")
			// With no style sheet at all, only attributes hide anything: wherever a quick form is in the markup, the
			// cut sentence is hidden by its own attribute, and no wide LONG sentence is there.
			summary := regexp.MustCompile(`<p class="ab-summary"([^>]*)>`).FindStringSubmatch(banner)
			if summary == nil {
				t.Fatalf("%s %s: no phone sentence", tc.name, path)
			}
			if hidden := strings.Contains(summary[1], " hidden"); hidden != tc.phoneLong {
				t.Errorf("%s %s: the phone sentence's hidden attribute is %v for a LONG form %v", tc.name, path, hidden, tc.phoneLong)
			}
			if approve > 0 && (strings.Contains(banner, `data-number-exclude="layout.request-long"`) || (phoneShort && !strings.Contains(summary[1], " hidden"))) {
				t.Errorf("%s %s: with no style sheet the answers sit beside a cut sentence", tc.name, path)
			}
			switch {
			case tc.wideLog:
				if strings.Contains(banner, "Allow once lets") {
					t.Errorf("%s %s: the banner explains Allow once where it offers none", tc.name, path)
				}
				if approve != 0 || len(forms) != 0 || len(reviews) != 1 || reviews[0][1] != "" {
					t.Errorf("%s %s: LONG everywhere must render Review request alone: %d answers, forms %v, review %v", tc.name, path, approve, forms, reviews)
				}
			case tc.phoneLong:
				if len(forms) != 1 || forms[0][1] != " desktop-only" || len(reviews) != 1 || reviews[0][1] != " phone-only" || !phoneShort {
					t.Errorf("%s %s: phone-LONG must hide the answers on a phone and show Review request there: forms %v, review %v", tc.name, path, forms, reviews)
				}
			default:
				if len(forms) != 1 || forms[0][1] != "" || len(reviews) != 0 || phoneShort {
					t.Errorf("%s %s: FULL keeps the quick answers and no review: forms %v, review %v", tc.name, path, forms, reviews)
				}
			}
			if !strings.Contains(banner, `aria-label="`+v.Full+`"`) {
				t.Errorf("%s %s: the phone sentence's accessible name is not the whole sentence", tc.name, path)
			}
		}
	}
}

// TestRequestFormRenameWithoutSlash is the review's finding F1: a rename whose second half has no slash (an agent
// chooses it; the banner runs on every page, so a panic here breaks every page).
func TestRequestFormRenameWithoutSlash(t *testing.T) {
	// The review's exact repro.
	if got := cutTarget("rename", "fs", "/a/b → "+strings.Repeat("n", 200), 60); utf8.RuneCountInString(got) > 60 || !strings.Contains(got, "…") || !strings.HasPrefix(got, "/a/b") || !strings.HasSuffix(got, "n") {
		t.Errorf("rename with a slashless second name: %q", got)
	}
	for _, target := range []string{strings.Repeat("n", 200), "x → " + strings.Repeat("n", 200), strings.Repeat("n", 200) + " → /a/b"} {
		for _, op := range []string{"rename", "write", "read", "link", "symlink", "unlink"} {
			if got := cutTarget(op, "fs", target, 60); utf8.RuneCountInString(got) > 60 {
				t.Errorf("%s %.12q: %d characters", op, target, utf8.RuneCountInString(got))
			}
		}
	}
	// The whole path through the banner's view.
	v := requestOf(ledgerview.Ask{Agent: "codex", Op: "rename", Hold: "fs", Target: "/a/b → " + strings.Repeat("n", 200)}, nil)
	if !v.Phone.Long || utf8.RuneCountInString(v.Phone.Target) > phoneRequestBound {
		t.Errorf("rename: %+v", v.Phone)
	}
}

// TestRequestFormPortIsAtMostFiveDigits is finding F3: a longer run of digits is the host's text and is cut with it.
func TestRequestFormPortIsAtMostFiveDigits(t *testing.T) {
	for _, target := range []string{"a.b:" + strings.Repeat("9", 200), "a.b:123456", "[::1]:" + strings.Repeat("8", 200)} {
		for _, n := range []int{32, 60, 100} {
			if got := cutTarget("connect", "net", target, n); utf8.RuneCountInString(got) > n {
				t.Errorf("%.20q in %d: %d characters %q", target, n, utf8.RuneCountInString(got), got)
			}
		}
	}
	if got := cutTarget("connect", "net", strings.Repeat("host.", 30)+"example.com:65535", 40); !strings.HasSuffix(got, "example.com:65535") {
		t.Errorf("a real port stays with the host's end: %q", got)
	}
}

// TestRequestFormCutsKeepMarksWithLetters is finding F4: a cut never starts the kept tail with a combining mark, which
// would attach to the ellipsis.
func TestRequestFormCutsKeepMarksWithLetters(t *testing.T) {
	mark := "́"
	for _, target := range []string{"/work/" + strings.Repeat("e"+mark, 100), "cmd " + strings.Repeat("a"+mark+mark, 90), strings.Repeat("o"+mark, 100)} {
		for _, op := range []string{"read", "exec", "connect", "write"} {
			for n := 32; n < 70; n++ {
				got := cutTarget(op, "fs", target, n)
				if i := strings.Index(got, "…"); i >= 0 {
					if r, _ := utf8.DecodeRuneInString(got[i+len("…"):]); unicode.Is(unicode.Mn, r) {
						t.Fatalf("%s n=%d: the tail starts with a mark: %q", op, n, got)
					}
				}
			}
		}
	}
	if got := cutMiddle(strings.Repeat("ab"+mark, 60), 30); strings.Contains(got, "…"+mark) {
		t.Errorf("cutMiddle left a mark on the ellipsis: %q", got)
	}
}

// TestRequestFormAccessibleNameIsVisibleText is finding F5: control and bidi characters as the literals the eye reads.
func TestRequestFormAccessibleNameIsVisibleText(t *testing.T) {
	a := ledgerview.Ask{Agent: "co\u202edex", Op: "write", Hold: "fs", Target: "/work/a\u200bb\u202e.txt"}
	if got, want := requestOf(a, nil).Full, "co⟦U+202E⟧dex wants to "+askVerb("write", "", "fs")+" /work/a⟦U+200B⟧b⟦U+202E⟧.txt"; got != want {
		t.Errorf("accessible name %q, want %q", got, want)
	}
}

// requestOps and requestHolds are every operation and hold kind a request can name.
var (
	requestOps   = []string{"", "read", "unlink", "mkdir", "rename", "symlink", "link", "write", "open", "connect", "send", "request", "exec", "mcp_tool", "first_write", "unknown-op"}
	requestHolds = []string{"", "fs", "net", "exec", "mcp", "other"}
)

// FuzzRequestForms throws arbitrary agent and target text at every operation and hold kind: the banner runs on every
// page, so nothing an agent writes may panic, break UTF-8, grow a sentence past its bound or cut away the ends a
// decision turns on.
func FuzzRequestForms(f *testing.F) {
	for _, seed := range []struct {
		agent, target string
		op, hold, n   uint8
	}{
		{"codex", "/a/b → " + strings.Repeat("n", 200), 4, 1, 0},
		{"codex", "a.b:" + strings.Repeat("9", 200), 9, 2, 1},
		{"co\u202edex", "/work/" + strings.Repeat("deep/", 60) + "x\u200b.json", 7, 1, 2},
		{strings.Repeat("Mira", 30), "example.com:443", 9, 2, 3},
		{"codex", "/usr/bin/worker " + strings.Repeat("--input=/work/x ", 100), 12, 3, 4},
		{"codex", strings.Repeat("é", 120), 2, 0, 5},
		{"", "", 0, 0, 6},
		{"codex", "[2001:db8::1]:" + strings.Repeat("8", 40), 9, 2, 7},
		{"codex", "\xff\xfe/bad\xc3 → \xc3", 3, 1, 8},
		{"codex", "~/" + strings.Repeat("dir/", 50) + " → ./" + strings.Repeat("nme", 80), 4, 1, 9},
	} {
		f.Add(seed.agent, seed.target, seed.op, seed.hold, seed.n)
	}
	f.Fuzz(func(t *testing.T, agent, target string, opi, holdi, ni uint8) {
		op, hold := requestOps[int(opi)%len(requestOps)], requestHolds[int(holdi)%len(requestHolds)]
		a := ledgerview.Ask{Agent: agent, Op: op, Hold: hold, Target: target, Run: "r", AskID: "a"}
		var run any
		if ni%2 == 1 {
			run = askMeta{Home: "/home/u", Cwd: "/home/u/p"}
		}
		v := requestOf(a, run)
		for _, s := range []string{v.Full, v.Phone.Agent, v.Phone.Target, v.Wide.Agent, v.Wide.Target} {
			if !utf8.ValidString(s) {
				t.Fatalf("not UTF-8: %q", s)
			}
		}
		cleanAgent, cleanTarget := strings.ToValidUTF8(agent, "�"), strings.ToValidUTF8(target, "�")
		if cleanAgent == "" {
			cleanAgent = "An agent"
		}
		m := metaOf(run)
		shown := map[string]string{"phone": visibleText(cleanTarget), "wide": visibleText(requestShown(cleanTarget, m.Home, m.Cwd))}
		for _, w := range []struct {
			name         string
			f            requestForm
			bound, agent int
		}{{"phone", v.Phone, phoneRequestBound, phoneAgentBound}, {"wide", v.Wide, wideRequestBound, wideAgentBound}} {
			full := requestForm{Agent: visibleText(cleanAgent), Target: shown[w.name]}
			if !w.f.Long {
				if w.f != full {
					t.Fatalf("%s: FULL is not the visible input: %+v, want %+v", w.name, w.f, full)
				}
				if sentenceLen(w.f, a) > w.bound {
					t.Fatalf("%s: FULL form passes its bound", w.name)
				}
				continue
			}
			if sentenceLen(full, a) <= w.bound {
				t.Fatalf("%s: LONG for a sentence within its bound", w.name)
			}
			if n := sentenceLen(w.f, a); n > w.bound {
				t.Fatalf("%s: LONG sentence of %d characters passes its bound %d: %+v", w.name, n, w.bound, w.f)
			}
			if utf8.RuneCountInString(full.Agent) > w.agent != (w.f.Agent != full.Agent) {
				t.Fatalf("%s: the name is cut only when it alone passes its bound: %q", w.name, w.f.Agent)
			}
			if w.f.Agent != full.Agent && !strings.Contains(w.f.Agent, "…") {
				t.Fatalf("%s: a cut name has no ellipsis: %q", w.name, w.f.Agent)
			}
			if w.f.Target == full.Target {
				continue
			}
			// The kept ends (ruling V1(a)): the first characters and the last ones of the target, whatever its kind,
			// as far as a combining mark left alone at the cut allows; a network target also keeps its port.
			in, out := []rune(full.Target), []rune(w.f.Target)
			if len(in) > 0 && (len(out) == 0 || out[0] != in[0]) {
				t.Fatalf("%s: the cut lost the first character: %q from %q", w.name, w.f.Target, full.Target)
			}
			if !strings.Contains(w.f.Target, "…") {
				t.Fatalf("%s: a cut target has no ellipsis: %q", w.name, w.f.Target)
			}
			if last := out[len(out)-1]; last != in[len(in)-1] && last != '…' {
				t.Fatalf("%s: the cut lost the last character: %q from %q", w.name, w.f.Target, full.Target)
			}
			if net := op == "connect" || op == "send" || op == "first_write" || op == "request" || (op == "" && hold == "net"); net {
				if i := strings.LastIndexByte(full.Target, ':'); i > 0 && len(full.Target)-i-1 > 0 && len(full.Target)-i-1 <= 5 && strings.Trim(full.Target[i+1:], "0123456789") == "" &&
					(!strings.Contains(full.Target[:i], ":") || strings.HasSuffix(full.Target[:i], "]")) && !strings.HasSuffix(w.f.Target, full.Target[i:]) {
					t.Fatalf("%s: the cut lost the port: %q from %q", w.name, w.f.Target, full.Target)
				}
			}
		}
		// cutTarget at any width a caller could pass.
		n := requestTargetLeast + int(ni)%150
		if got := cutTarget(op, hold, visibleText(cleanTarget), n); utf8.RuneCountInString(got) > n || !utf8.ValidString(got) {
			t.Fatalf("cutTarget(%q, %d) = %q", target, n, got)
		}
	})
}
