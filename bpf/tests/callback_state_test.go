// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The bpf_loop callback state lint (enforce-plane R21's second half). A verifier before 6.8's "verify callbacks as
// if they are called unknown number of times" (AL2023's 6.1, and any kernel without the backport) verifies a
// bpf_loop callback once, from the state its first call gives it, and hard-wires every branch that state rules out.
// A field the callback branches on and changes across iterations then behaves as its first value forever: the
// plane's walk once lost its BOUND check that way (steps a known 0), and its unix name check (the state byte a known
// 0), each found only in a guest. A value read from memory is one no verifier assumes, so every such field must be
// seeded from map or argument memory before the loop, never from a constant or the zero-initialised stack.

// cFunc is one C function definition: its name, its parameter list and its body, braces included.
type cFunc struct {
	name, params, body string
}

var (
	cIdentRe     = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	cCondHeadRe  = regexp.MustCompile(`\b(if|while|switch|for)\s*\(`)
	cBPFLoopRe   = regexp.MustCompile(`\bbpf_loop\s*\(`)
	cNumberRe    = regexp.MustCompile(`^(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*$`)
	cCastRe      = regexp.MustCompile(`\(\s*(const\s+)?(struct\s+[A-Za-z_]\w*|__[us](8|16|32|64)|u?int[0-9]*_t|char|int|long|unsigned(\s+(int|long|char))?|void)\s*\**\s*\)`)
	cKeywordRe   = regexp.MustCompile(`^(sizeof|struct|const|volatile|unsigned|signed|int|long|char|void|return)$`)
	cStructVarRe = `\bstruct\s+(\w+)\s+%s\s*(=\s*(\{[^;]*\}))?\s*;`
)

// stripPreprocessor blanks every preprocessor line and its continuations, so that a macro's body is never taken for
// code: the functions a macro emits are analysed where they are written out (TEGO_PLANE_HOOK's body follows the
// invocation), and a #if's branches are both kept, as both are code some build compiles.
func stripPreprocessor(src string) string {
	lines := strings.Split(src, "\n")
	cont := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if cont || strings.HasPrefix(t, "#") {
			cont = strings.HasSuffix(strings.TrimRight(l, " \t"), "\\")
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// matchClose returns the index of the bracket closing the one at open, -1 when it is unbalanced.
func matchClose(s string, open int) int {
	o := s[open]
	c := map[byte]byte{'(': ')', '{': '}', '[': ']'}[o]
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// matchOpen returns the index of the '(' that the ')' at close closes, -1 when there is none.
func matchOpen(s string, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		switch s[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// cFuncs lists the function definitions of a comment-stripped source: at brace depth 0, a '{' that follows a ')'
// whose '(' follows a name. Struct, union and enum bodies and initialisers are not preceded by one.
func cFuncs(src string) []cFunc {
	src = stripPreprocessor(src)
	var out []cFunc
	for i := 0; i < len(src); i++ {
		if src[i] != '{' {
			continue
		}
		end := matchClose(src, i)
		if end < 0 {
			return out
		}
		j := i - 1
		for j >= 0 && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n') {
			j--
		}
		if j >= 0 && src[j] == ')' {
			if open := matchOpen(src, j); open > 0 {
				k := open - 1
				for k >= 0 && (src[k] == ' ' || src[k] == '\t') {
					k--
				}
				e := k + 1
				for k >= 0 && (src[k] == '_' || src[k] >= 'a' && src[k] <= 'z' || src[k] >= 'A' && src[k] <= 'Z' || src[k] >= '0' && src[k] <= '9') {
					k--
				}
				if name := src[k+1 : e]; name != "" && !cKeywordRe.MatchString(name) && name != "if" && name != "while" && name != "for" && name != "switch" {
					out = append(out, cFunc{name: name, params: src[open+1 : j], body: src[i : end+1]})
				}
			}
		}
		i = end
	}
	return out
}

// splitTop splits s at the top-level commas (outside any bracket).
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// paramNames are a parameter list's names, in order ("" for an unnamed one or void).
func paramNames(params string) []string {
	var out []string
	for _, p := range splitTop(params) {
		ids := cIdentRe.FindAllString(p, -1)
		if len(ids) < 2 {
			out = append(out, "")
			continue
		}
		out = append(out, ids[len(ids)-1])
	}
	return out
}

// statements splits a body into its simple statements at ';', '{' and '}', each with its leading condition heads
// (if, while, switch, for and else) removed; conds are those heads' conditions.
func statements(body string) (stmts, conds []string) {
	b := body
	// The conditions first, with their text blanked so that the statements that follow them stand alone.
	for {
		m := cCondHeadRe.FindStringSubmatchIndex(b)
		if m == nil {
			break
		}
		open := m[1] - 1
		close := matchClose(b, open)
		if close < 0 {
			break
		}
		inner := b[open+1 : close]
		if b[m[2]:m[3]] == "for" {
			if parts := strings.Split(inner, ";"); len(parts) == 3 {
				conds = append(conds, parts[1])
				stmts = append(stmts, parts[0], parts[2])
			}
		} else {
			conds = append(conds, inner)
		}
		b = b[:m[0]] + strings.Repeat(" ", close+1-m[0]) + b[close+1:]
	}
	b = regexp.MustCompile(`\belse\b`).ReplaceAllString(b, " ")
	for _, s := range strings.FieldsFunc(b, func(r rune) bool { return r == ';' || r == '{' || r == '}' }) {
		if s = strings.TrimSpace(s); s != "" {
			stmts = append(stmts, s)
		}
	}
	// A short-circuit or a ternary outside a condition head is a branch too: an assignment's value up to its '?', or
	// the whole of it.
	for _, s := range stmts {
		if !strings.Contains(s, "&&") && !strings.Contains(s, "||") && !strings.Contains(s, "?") {
			continue
		}
		if _, r, ok := assignment(s); ok {
			s = r
		}
		if q := strings.IndexByte(s, '?'); q >= 0 && !strings.Contains(s, "&&") && !strings.Contains(s, "||") {
			s = s[:q]
		}
		conds = append(conds, s)
	}
	return stmts, conds
}

// assignment splits a statement into the variable it assigns (a plain local name, or s.f / p->f as written) and
// the expression; ok is false for a statement that assigns nothing. A declaration's type is dropped.
func assignment(stmt string) (lhs, rhs string, ok bool) {
	for i := 0; i < len(stmt); i++ {
		if stmt[i] != '=' {
			continue
		}
		if i+1 < len(stmt) && stmt[i+1] == '=' {
			i++
			continue
		}
		if i > 0 && strings.ContainsRune("=!<>", rune(stmt[i-1])) {
			continue
		}
		l := strings.TrimSpace(stmt[:i])
		l = strings.TrimRight(l, "+-*/|&^%<> \t")
		if f := strings.Fields(strings.ReplaceAll(l, "*", " ")); len(f) > 0 {
			l = f[len(f)-1]
		}
		return l, strings.TrimSpace(stmt[i+1:]), true
	}
	return "", "", false
}

// fieldRefs are the fields of state pointer sp an expression names (sp->f), and whether it passes sp itself.
func fieldRefs(expr, sp string) (fields []string, bare bool) {
	re := regexp.MustCompile(`(^|[^\w.>])` + regexp.QuoteMeta(sp) + `\s*->\s*(\w+)`)
	for _, m := range re.FindAllStringSubmatch(expr, -1) {
		fields = append(fields, m[2])
	}
	bareRe := regexp.MustCompile(`(^|[^\w.>])` + regexp.QuoteMeta(sp) + `\b\s*($|[^\w\s-]|-[^>])`)
	return fields, bareRe.MatchString(expr)
}

// calleeFields are the fields a function reads through its parameters when an expression passes state pointer sp to
// it bare: every pname->f in the callee's body, for each callee named in expr with sp at pname's position.
func calleeFields(expr, sp string, funcs map[string][]cFunc) []string {
	var out []string
	for _, loc := range regexp.MustCompile(`\b(\w+)\s*\(`).FindAllStringSubmatchIndex(expr, -1) {
		name := expr[loc[2]:loc[3]]
		close := matchClose(expr, loc[1]-1)
		if close < 0 {
			continue
		}
		args := splitTop(expr[loc[1]:close])
		for _, f := range funcs[name] {
			names := paramNames(f.params)
			for i, a := range args {
				if a != sp || i >= len(names) || names[i] == "" {
					continue
				}
				got, _ := fieldRefs(f.body, names[i])
				out = append(out, got...)
			}
		}
	}
	return out
}

// branchedFields are the fields of a callback's state that it branches on: named in a condition directly, through a
// local assigned from them (to a fixed point), or read by a function the condition passes the state to.
func branchedFields(cb cFunc, funcs map[string][]cFunc) []string {
	names := paramNames(cb.params)
	if len(names) < 2 || names[1] == "" {
		return nil
	}
	ptrs := []string{names[1]}
	stmts, conds := statements(cb.body)
	// A state reached through a void * argument is aliased to its type once: struct T *s = arg.
	for _, s := range stmts {
		if l, r, ok := assignment(s); ok && strings.TrimSpace(r) == names[1] {
			ptrs = append(ptrs, l)
		}
	}
	refs := func(expr string) []string {
		var out []string
		for _, sp := range ptrs {
			f, bare := fieldRefs(expr, sp)
			out = append(out, f...)
			if bare {
				out = append(out, calleeFields(expr, sp, funcs)...)
			}
		}
		return out
	}
	taint := map[string][]string{}
	for changed := true; changed; {
		changed = false
		for _, s := range stmts {
			l, r, ok := assignment(s)
			if !ok || strings.Contains(l, "->") || strings.Contains(l, ".") || slices.Contains(ptrs, l) {
				continue
			}
			got := refs(r)
			for _, id := range cIdentRe.FindAllString(r, -1) {
				got = append(got, taint[id]...)
			}
			for _, f := range got {
				if !slices.Contains(taint[l], f) {
					taint[l] = append(taint[l], f)
					changed = true
				}
			}
		}
	}
	var out []string
	for _, c := range conds {
		got := refs(c)
		for _, id := range cIdentRe.FindAllString(c, -1) {
			got = append(got, taint[id]...)
		}
		for _, f := range got {
			if !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	slices.Sort(out)
	return out
}

// constantExpr reports whether an expression is a constant: after its casts, nothing but numbers, upper-case macro
// constants, sizeof and operators, or locals of fn every one of whose assignments is such an expression.
func constantExpr(expr string, fn cFunc, depth int) bool {
	e := cCastRe.ReplaceAllString(expr, " ")
	if strings.Contains(e, "->") || strings.Contains(e, "[") {
		return false
	}
	for _, tok := range regexp.MustCompile(`[A-Za-z_0-9]+`).FindAllString(e, -1) {
		switch {
		case cNumberRe.MatchString(tok), tok == "sizeof":
		case strings.ToUpper(tok) == tok && tok[0] != '_':
		default:
			// A local of the caller holding a constant is one; a parameter, a call or any other name is not.
			if depth > 4 || slices.Contains(paramNames(fn.params), tok) {
				return false
			}
			stmts, _ := statements(fn.body)
			seen := false
			for _, s := range stmts {
				l, r, ok := assignment(s)
				if !ok || l != tok {
					continue
				}
				seen = true
				if !constantExpr(r, fn, depth+1) {
					return false
				}
			}
			if !seen {
				return false
			}
		}
	}
	return true
}

// loopSite is one bpf_loop call: the function it is in, the callback's name, the state expression and where the
// call starts in the body.
type loopSite struct {
	fn       cFunc
	callback string
	state    string
	at       int
}

// loopSites finds every bpf_loop call in funcs.
func loopSites(funcs []cFunc) []loopSite {
	var out []loopSite
	for _, f := range funcs {
		for _, m := range cBPFLoopRe.FindAllStringIndex(f.body, -1) {
			close := matchClose(f.body, m[1]-1)
			if close < 0 {
				continue
			}
			args := splitTop(f.body[m[1]:close])
			if len(args) != 4 {
				continue
			}
			out = append(out, loopSite{fn: f, callback: args[1], state: args[2], at: m[0]})
		}
	}
	return out
}

// seed is one expression a state field is assigned before the loop, and the function it is written in (the loop's,
// or a setup helper the state is handed to), whose locals and parameters decide whether it is a constant.
type seed struct {
	expr string
	fn   cFunc
}

// helperSeeds are the seeds of field that setup helpers write before the site: a call fn(STATE, ...) before the loop,
// with STATE the loop's state expression (with or without its &), fn defined in funcs, and fn's first parameter a
// pointer it assigns through (`param->field = expr;`).
func helperSeeds(site loopSite, field string, funcs map[string][]cFunc) []seed {
	before := site.fn.body[:site.at]
	state := strings.TrimSpace(site.state)
	forms := []string{regexp.QuoteMeta(state)}
	if strings.HasPrefix(state, "&") {
		forms = append(forms, regexp.QuoteMeta(strings.TrimSpace(state[1:])))
	} else {
		forms = append(forms, "&\\s*"+regexp.QuoteMeta(state))
	}
	var out []seed
	for _, form := range forms {
		callRe := regexp.MustCompile(`\b(\w+)\s*\(\s*` + form + `\s*[,)]`)
		for _, m := range callRe.FindAllStringSubmatch(before, -1) {
			for _, fn := range funcs[m[1]] {
				params := splitTop(fn.params)
				if len(params) == 0 {
					continue
				}
				ids := cIdentRe.FindAllString(params[0], -1)
				if len(ids) == 0 || !strings.Contains(params[0], "*") {
					continue
				}
				param := ids[len(ids)-1]
				assignRe := regexp.MustCompile(`(?:^|[^\w.>])` + regexp.QuoteMeta(param) + `\s*->\s*` + field + `\s*=([^=][^;]*);`)
				for _, a := range assignRe.FindAllStringSubmatch(fn.body, -1) {
					out = append(out, seed{strings.TrimSpace(a[1]), fn})
				}
			}
		}
	}
	return out
}

// seeds are the expressions a site's state field is seeded with before the loop, and why a field has none: the
// designated initialiser's and every assignment's up to the call. local is false for a state reached through a
// pointer, whose unassigned fields are the memory it points to.
func seeds(site loopSite, field string) (exprs []string, local, zeroInit bool) {
	before := site.fn.body[:site.at]
	name := strings.TrimSpace(site.state)
	var assignRe *regexp.Regexp
	if strings.HasPrefix(name, "&") {
		name = strings.TrimSpace(name[1:])
		local = true
		decl := regexp.MustCompile(fmt.Sprintf(cStructVarRe, regexp.QuoteMeta(name))).FindStringSubmatch(before)
		if decl != nil && decl[3] != "" {
			init := strings.TrimSpace(decl[3][1 : len(decl[3])-1])
			zeroInit = true
			for _, part := range splitTop(init) {
				if k, v, ok := strings.Cut(part, "="); ok && strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(k), ".")) == field {
					exprs = append(exprs, strings.TrimSpace(v))
				}
			}
		}
		assignRe = regexp.MustCompile(`(?:^|[^\w.>])` + regexp.QuoteMeta(name) + `\s*\.\s*` + field + `\s*=([^=][^;]*);`)
	} else {
		assignRe = regexp.MustCompile(`(?:^|[^\w.>])` + regexp.QuoteMeta(name) + `\s*->\s*` + field + `\s*=([^=][^;]*);`)
	}
	for _, m := range assignRe.FindAllStringSubmatch(before, -1) {
		exprs = append(exprs, strings.TrimSpace(m[1]))
	}
	return exprs, local, zeroInit
}

// lintCallbackSeeds is the lint over one set of comment-stripped sources: for every bpf_loop call, every field its
// callback branches on must be seeded before the call, from map or argument memory. It returns one finding per
// field seeded wrongly, and the number of loop sites it checked.
func lintCallbackSeeds(src string) (findings []string, sites int) {
	all := cFuncs(src)
	funcs := map[string][]cFunc{}
	for _, f := range all {
		funcs[f.name] = append(funcs[f.name], f)
	}
	for _, site := range loopSites(all) {
		cbs := funcs[site.callback]
		if len(cbs) == 0 {
			findings = append(findings, fmt.Sprintf("%s: bpf_loop's callback %s is not defined in the sources", site.fn.name, site.callback))
			continue
		}
		sites++
		var fields []string
		for _, cb := range cbs {
			for _, f := range branchedFields(cb, funcs) {
				if !slices.Contains(fields, f) {
					fields = append(fields, f)
				}
			}
		}
		slices.Sort(fields)
		for _, field := range fields {
			if _, ok := callbackSeedExempt[site.callback+"."+field]; ok {
				continue
			}
			exprs, local, _ := seeds(site, field)
			all := make([]seed, 0, len(exprs))
			for _, e := range exprs {
				all = append(all, seed{e, site.fn})
			}
			all = append(all, helperSeeds(site, field, funcs)...)
			where := fmt.Sprintf("%s's bpf_loop(%s): field %s, which %s branches on,", site.fn.name, site.callback, field, site.callback)
			if local && len(all) == 0 {
				findings = append(findings, where+" is never seeded: it is the zero-initialised stack")
				continue
			}
			for _, e := range all {
				if constantExpr(e.expr, e.fn, 0) {
					findings = append(findings, fmt.Sprintf("%s is seeded from the constant %q", where, e.expr))
				}
			}
		}
	}
	return findings, sites
}

// callbackSeedExempt names the callback fields the lint passes, each with why no first-call state can hard-wire a
// branch on it. Keep it short: a field belongs here only when every branch on it compares it with a value the verifier
// cannot know.
var callbackSeedExempt = map[string]string{
	// trace_proc's directory walk: pass 0 writes seq[level] from the dentry's d_seq read that iteration, and pass 1
	// compares it with a fresh d_seq read; the other side of every branch on seq is memory, never a constant.
	"tego_dir_step.seq": "compared only with a d_seq read from memory in the same iteration",
}

// productionSources is every C source and header a tego object is built from, comment-stripped and joined: a
// callback and its caller may sit in different files (plane_name.h's name passes).
func productionSources(t *testing.T) string {
	t.Helper()
	var files []string
	for _, g := range []string{"*.bpf.c", "*.h", filepath.Join("include", "*.h")} {
		got, err := filepath.Glob(filepath.Join(sourceDir, g))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, got...)
	}
	slices.Sort(files)
	var b strings.Builder
	for _, f := range files {
		if filepath.Base(f) == "vmlinux.h" {
			continue
		}
		b.WriteString(read(t, f))
		b.WriteByte('\n')
	}
	return b.String()
}

// TestBPFLoopCallbackStateIsSeededFromMemory is the lint over every object's sources: each field a bpf_loop callback
// branches on is seeded from map or argument memory before the loop, never from a constant or the zero-initialised
// stack. It must see the plane's walk, its exec sample's path copy, its unix name check and the name passes.
func TestBPFLoopCallbackStateIsSeededFromMemory(t *testing.T) {
	t.Parallel()
	findings, sites := lintCallbackSeeds(productionSources(t))
	for _, f := range findings {
		t.Error(f)
	}
	if sites < 6 {
		t.Errorf("the lint checked %d bpf_loop calls; the sources have at least 6 (the walk, the path copies, the unix "+
			"check, the name hash and compare): it no longer finds them", sites)
	}
}

// TestCallbackSeedLintCatchesAPlantedFixture holds the lint to a fixture that seeds a branched field from a
// constant, one from a local holding a constant, and leaves one as the zero-initialised stack: each is a finding,
// and a field seeded from a parameter or from memory is not.
func TestCallbackSeedLintCatchesAPlantedFixture(t *testing.T) {
	t.Parallel()
	findings, sites := lintCallbackSeeds(read(t, filepath.Join("testdata", "callback_const_seed.c")))
	if sites != 3 {
		t.Fatalf("the lint saw %d bpf_loop calls in the fixture, want 3", sites)
	}
	want := []string{
		`fixture_const_seed's bpf_loop(fixture_step): field steps, which fixture_step branches on, is seeded from the constant "0"`,
		`fixture_const_seed's bpf_loop(fixture_step): field crossed, which fixture_step branches on, is seeded from the constant "none"`,
		`fixture_zero_seed's bpf_loop(fixture_step): field crossed, which fixture_step branches on, is never seeded: it is the zero-initialised stack`,
		`fixture_helper_seed's bpf_loop(fixture_step): field crossed, which fixture_step branches on, is seeded from the constant "1"`,
	}
	slices.Sort(findings)
	slices.Sort(want)
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}
}

// TestCallbackBranchedFields holds branchedFields to the walk's shape: a field named in a condition, one reached
// through a local, one read by a function the condition passes the state to, and one only written.
func TestCallbackBranchedFields(t *testing.T) {
	t.Parallel()
	src := `
static __u64 word(const struct st *p, __u32 i) { return p->addr + p->len; }
static long cb(__u32 i, void *arg)
{
    struct st *s = arg;
    __u64 d = s->d;
    __u64 up = parent(d);

    if (!up || s->steps > 64)
        return 1;
    if (word(s, i) != 0)
        s->result = 1;
    s->out = s->steps ? 1 : 0;
    return 0;
}`
	funcs := map[string][]cFunc{}
	for _, f := range cFuncs(src) {
		funcs[f.name] = append(funcs[f.name], f)
	}
	got := branchedFields(funcs["cb"][0], funcs)
	if want := []string{"addr", "d", "len", "steps"}; !slices.Equal(got, want) {
		t.Errorf("branched fields %v, want %v", got, want)
	}
}
