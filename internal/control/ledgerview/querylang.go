// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The Logs query language: space-separated tokens, all of which a line must match.
//
//	kind:exec verdict:refused pid:123 prog:curl rule:fs.deny_read* path:~/.ssh host:chatgpt.com run:<id> agent:x
//	source:kernel since:15m until:2026-10-27T01:00 after:<cursor> -word "quoted phrase" key:"quoted value"
//
// A word is a literal substring, like the plain search (Filter.Text). A leading - leaves out what the token names
// (kind, verdict, prog, rule, host, run, agent and words). The same key twice means either value (kind:exec
// kind:net); pid, path, source, since, until and after take one value, the last given. prog is the program the line's
// process was running (program.go). A key the language does not know stays a word,
// so text such as unix:/run/x or http://host is searched as written. since and until take a duration back from now
// (30s, 15m, 2h, 7d) or a local time (2026-10-27, 2026-10-27T01:00, 01:00 today, or RFC 3339).

// Token is one term of a query: Key is "" for a word.
type Token struct {
	Key   string
	Value string
	Neg   bool
}

// The query keys, and the ones a leading - can negate.
var (
	queryKeys   = []string{"kind", "verdict", "pid", "prog", "rule", "path", "host", "run", "agent", "source", "since", "until", "after"}
	negatedKeys = []string{"kind", "verdict", "prog", "rule", "host", "run", "agent"}
)

// verdictWords maps what a person may type for a verdict to the verdict Logs counts (verdictOf).
var verdictWords = map[string]string{
	"refused": "refused", "refusal": "refused", "denied": "refused", "blocked": "refused",
	"allow": "allow", "allowed": "allow",
	"ask": "ask", "asked": "ask",
	"observed": "observed", "observe": "observed",
	"none": "none",
}

// String is the token as a query writes it.
func (t Token) String() string {
	var b strings.Builder
	if t.Neg {
		b.WriteByte('-')
	}
	if t.Key != "" {
		b.WriteString(t.Key)
		b.WriteByte(':')
	}
	if needsQuote(t.Value, t.Key == "") {
		b.WriteString(quote(t.Value))
	} else {
		b.WriteString(t.Value)
	}
	return b.String()
}

// FormatQuery writes tokens back as a query that ParseQuery reads as the same tokens.
func FormatQuery(toks []Token) string {
	parts := make([]string, len(toks))
	for i, t := range toks {
		parts[i] = t.String()
	}
	return strings.Join(parts, " ")
}

func needsQuote(v string, word bool) bool {
	if v == "" || strings.ContainsAny(v, "\"\\") || strings.IndexFunc(v, unicode.IsSpace) >= 0 {
		return true
	}
	if !word {
		return strings.HasPrefix(v, "\"")
	}
	if strings.HasPrefix(v, "-") {
		return true
	}
	if k, _, ok := strings.Cut(v, ":"); ok && slices.Contains(queryKeys, strings.ToLower(k)) {
		return true
	}
	return false
}

func quote(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`
}

// scanQuery splits s into raw terms: neg, the key text before a quoted value (with its colon), and the value.
type rawTerm struct {
	neg    bool
	quoted bool
	text   string // a bare term, or a quoted term's content
	key    string // for key:"value", the key
}

var errOpenQuote = errors.New(`a quote is not closed: end the phrase with "`)

func scanQuery(s string) ([]rawTerm, error) {
	var out []rawTerm
	rs := []rune(s)
	i := 0
	readQuoted := func() (string, bool) { // at rs[i] == '"'
		var b strings.Builder
		for i++; i < len(rs); i++ {
			switch rs[i] {
			case '\\':
				if i+1 < len(rs) {
					i++
					b.WriteRune(rs[i])
				}
			case '"':
				i++
				return b.String(), true
			default:
				b.WriteRune(rs[i])
			}
		}
		return b.String(), false
	}
	for i < len(rs) {
		if unicode.IsSpace(rs[i]) {
			i++
			continue
		}
		var t rawTerm
		if rs[i] == '-' && i+1 < len(rs) && !unicode.IsSpace(rs[i+1]) {
			t.neg = true
			i++
		}
		if rs[i] == '"' {
			v, ok := readQuoted()
			if !ok {
				return out, errOpenQuote
			}
			t.quoted, t.text = true, v
			out = append(out, t)
			continue
		}
		start := i
		for i < len(rs) && !unicode.IsSpace(rs[i]) {
			if rs[i] == ':' && i+1 < len(rs) && rs[i+1] == '"' && slices.Contains(queryKeys, strings.ToLower(string(rs[start:i]))) {
				t.key = string(rs[start:i])
				i++
				v, ok := readQuoted()
				if !ok {
					return out, errOpenQuote
				}
				t.quoted, t.text = true, v
				break
			}
			i++
		}
		if t.key == "" {
			t.text = string(rs[start:i])
		}
		out = append(out, t)
	}
	return out, nil
}

// ParseQuery reads a query (see the package's query language above) into a Filter and its tokens, with relative
// times counted back from now in the local time zone.
func ParseQuery(s string) (Filter, []Token, error) { return ParseQueryAt(s, time.Now(), time.Local) }

// ParseQueryAt is ParseQuery at now, reading local times in loc. A token it cannot read (a pid that is no number,
// a time it does not know, a key negated that cannot be) is left out of both the filter and the tokens and named in
// the error; the rest still apply.
func ParseQueryAt(s string, now time.Time, loc *time.Location) (Filter, []Token, error) {
	var f Filter
	var toks []Token
	terms, err := scanQuery(s)
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, rt := range terms {
		t := Token{Neg: rt.neg, Value: rt.text}
		switch {
		case rt.key != "":
			t.Key = strings.ToLower(rt.key)
		case !rt.quoted:
			if k, v, ok := strings.Cut(rt.text, ":"); ok && slices.Contains(queryKeys, strings.ToLower(k)) {
				if v == "" {
					errs = append(errs, fmt.Errorf("%s: needs a value, as in %s", k, example(strings.ToLower(k))))
					continue
				}
				t.Key, t.Value = strings.ToLower(k), v
			}
		}
		if t.Value == "" {
			if t.Key != "" {
				errs = append(errs, fmt.Errorf("%s: needs a value, as in %s", t.Key, example(t.Key)))
			}
			continue
		}
		if err := apply(&f, t, now, loc); err != nil {
			errs = append(errs, err)
			continue
		}
		toks = append(toks, t)
	}
	return f, toks, errors.Join(errs...)
}

func example(key string) string {
	switch key {
	case "kind":
		return "kind:exec"
	case "verdict":
		return "verdict:refused"
	case "pid":
		return "pid:123"
	case "prog":
		return "prog:curl"
	case "rule":
		return "rule:fs.deny_read*"
	case "path":
		return "path:~/.ssh"
	case "host":
		return "host:chatgpt.com"
	case "since":
		return "since:15m"
	case "until":
		return "until:2026-10-27T01:00"
	}
	return key + ":value"
}

// apply adds token t to f.
func apply(f *Filter, t Token, now time.Time, loc *time.Location) error {
	if t.Neg && t.Key != "" && !slices.Contains(negatedKeys, t.Key) {
		return fmt.Errorf("-%s: cannot be left out; only kind, verdict, prog, rule, host, run, agent and words can", t.Key)
	}
	add := func(pos, neg *[]string, v string) {
		if t.Neg {
			*neg = append(*neg, v)
		} else {
			*pos = append(*pos, v)
		}
	}
	switch t.Key {
	case "":
		add(&f.Words, &f.Not.Words, t.Value)
	case "kind":
		add(&f.Kinds, &f.Not.Kinds, logsKind(strings.ToLower(t.Value)))
	case "verdict":
		v, ok := verdictWords[strings.ToLower(t.Value)]
		if !ok {
			return fmt.Errorf("verdict:%s: not a verdict; use refused, allow, ask, observed or none", t.Value)
		}
		add(&f.Verdicts, &f.Not.Verdicts, v)
	case "rule":
		add(&f.Rules, &f.Not.Rules, t.Value)
	case "host":
		add(&f.Hosts, &f.Not.Hosts, strings.ToLower(t.Value))
	case "prog":
		add(&f.Programs, &f.Not.Programs, strings.ToLower(t.Value))
	case "run":
		add(&f.Runs, &f.Not.Runs, t.Value)
	case "agent":
		add(&f.Agents, &f.Not.Agents, t.Value)
	case "pid":
		n, err := strconv.Atoi(t.Value)
		if err != nil || n <= 0 {
			return fmt.Errorf("pid:%s: not a process number", t.Value)
		}
		f.PID = n
	case "path":
		f.PathPrefix = t.Value
	case "source":
		f.Source = strings.ToLower(t.Value)
	case "since", "until":
		at, err := queryTime(t.Value, now, loc)
		if err != nil {
			return fmt.Errorf("%s:%s: %w", t.Key, t.Value, err)
		}
		if t.Key == "since" {
			f.Since = at
		} else {
			f.Until = at
		}
	case "after":
		if _, ok := parseCursor(t.Value); !ok {
			return fmt.Errorf("after:%s: not a line cursor", t.Value)
		}
		f.After = t.Value
	}
	return nil
}

// queryTime reads a since or until value: a duration back from now, or a local time.
func queryTime(v string, now time.Time, loc *time.Location) (time.Time, error) {
	if n, ok := strings.CutSuffix(v, "d"); ok {
		if days, err := strconv.ParseFloat(n, 64); err == nil && days >= 0 {
			return now.Add(-time.Duration(days * float64(24*time.Hour))), nil
		}
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, loc); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(layout, v, loc); err == nil {
			y, m, d := now.In(loc).Date()
			return time.Date(y, m, d, t.Hour(), t.Minute(), t.Second(), 0, loc), nil
		}
	}
	return time.Time{}, errors.New("not a time; use 15m, 2h, 7d, 2026-10-27, 2026-10-27T01:00 or 01:00")
}

// And is a filter that matches the lines both f and g match: the Logs form's fields joined with a query's. The page
// size and cursor are f's.
func (f Filter) And(g Filter) Filter {
	out := f
	same := func(a, b string) string {
		switch {
		case a == "":
			return b
		case b != "" && a != b:
			out.none = true
		}
		return a
	}
	out.Run, out.Agent, out.Kind = same(f.Run, g.Run), same(f.Agent, g.Agent), same(f.Kind, g.Kind)
	out.Source, out.After = same(f.Source, g.Source), same(f.After, g.After)
	if g.PID != 0 {
		if f.PID != 0 && f.PID != g.PID {
			out.none = true
		}
		out.PID = g.PID
	}
	switch {
	case f.PathPrefix == "" || strings.HasPrefix(g.PathPrefix, f.PathPrefix):
		out.PathPrefix = g.PathPrefix
		if g.PathPrefix == "" {
			out.PathPrefix = f.PathPrefix
		}
	case !strings.HasPrefix(f.PathPrefix, g.PathPrefix):
		out.none = true
	}
	if g.Since.After(f.Since) {
		out.Since = g.Since
	}
	if !g.Until.IsZero() && (f.Until.IsZero() || g.Until.Before(f.Until)) {
		out.Until = g.Until
	}
	if f.Text == "" {
		out.Text = g.Text
	} else if g.Text != "" {
		out.Words = append(slices.Clone(out.Words), g.Text)
	}
	out.Words = append(slices.Clone(out.Words), g.Words...)
	inter := func(a, b []string) []string {
		if len(a) == 0 {
			return b
		}
		if len(b) == 0 {
			return a
		}
		var r []string
		for _, x := range a {
			if slices.Contains(b, x) {
				r = append(r, x)
			}
		}
		if len(r) == 0 {
			out.none = true
		}
		return r
	}
	out.Verdicts, out.Kinds = inter(f.Verdicts, g.Verdicts), inter(f.Kinds, g.Kinds)
	out.Runs, out.Agents, out.Hosts = inter(f.Runs, g.Runs), inter(f.Agents, g.Agents), inter(f.Hosts, g.Hosts)
	out.Programs = inter(f.Programs, g.Programs)
	out.Rules = interRules(f.Rules, g.Rules, &out.none)
	cat := func(a, b []string) []string { return append(slices.Clone(a), b...) }
	n := &out.Not
	n.Kinds, n.Verdicts, n.Rules = cat(f.Not.Kinds, g.Not.Kinds), cat(f.Not.Verdicts, g.Not.Verdicts), cat(f.Not.Rules, g.Not.Rules)
	n.Hosts, n.Runs, n.Agents = cat(f.Not.Hosts, g.Not.Hosts), cat(f.Not.Runs, g.Not.Runs), cat(f.Not.Agents, g.Not.Agents)
	n.Words, n.Programs = cat(f.Not.Words, g.Not.Words), cat(f.Not.Programs, g.Not.Programs)
	out.HideSys, out.OnlyRefus, out.Facets = f.HideSys || g.HideSys, f.OnlyRefus || g.OnlyRefus, f.Facets || g.Facets
	out.HideNoise = f.HideNoise || g.HideNoise
	out.none = out.none || f.none || g.none
	return out
}

// interRules is the rule entries both lists match: an exact key one list holds and the other matches, and of two
// prefixes the longer when one starts with the other.
func interRules(a, b []string, none *bool) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	var out []string
	for _, x := range a {
		if !strings.HasSuffix(x, "*") && ruleMatches(b, x) {
			out = append(out, x)
		}
	}
	for _, y := range b {
		if !strings.HasSuffix(y, "*") && ruleMatches(a, y) && !slices.Contains(out, y) {
			out = append(out, y)
		}
	}
	for _, x := range a {
		px, ok := strings.CutSuffix(x, "*")
		if !ok {
			continue
		}
		for _, y := range b {
			py, ok := strings.CutSuffix(y, "*")
			if !ok {
				continue
			}
			switch {
			case strings.HasPrefix(px, py):
				out = append(out, x)
			case strings.HasPrefix(py, px):
				out = append(out, y)
			}
		}
	}
	if len(out) == 0 {
		*none = true
	}
	return out
}
