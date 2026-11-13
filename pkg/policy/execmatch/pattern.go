// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// List is the contract list a pattern came from.
type List uint8

// Lists.
const (
	// ListAllow is exec.allow: words after the command constrain its argv.
	ListAllow List = iota + 1
	// ListDeny is exec.deny: never runs, at any specificity.
	ListDeny
	// ListAsk is exec.ask, reserved: refused at every tier until ADR 0044 gives a list floor a completion.
	ListAsk
)

// String is the list's contract key.
func (l List) String() string {
	switch l {
	case ListAllow:
		return "allow"
	case ListDeny:
		return "deny"
	case ListAsk:
		return "ask"
	}
	return "unknown"
}

// Bounds on one command pattern (ADR 0048 (1)); the 512-pattern bound over a contract is the compiler's.
const (
	MaxWords     = 32
	MaxWordBytes = 256
	MaxEntry     = 1024
	MaxPatterns  = 512
)

// PatOpt is one option word of a pattern.
type PatOpt struct {
	// Opt is the row's option; nil for an option the row does not list, and for the generic fallback.
	Opt *Opt
	// Raw is the word as written, without a value: "--force", "-r".
	Raw string
	// Long is a raw long option's name without dashes; Short a raw short option's letter.
	Long  string
	Short byte
	// Value is a glob over the option's value when HasValue.
	Value    string
	HasValue bool
	// Neg is git parse-options' --no-<name>.
	Neg bool
	// Depth is the subcommand depth the word stands at: 0 before the first subcommand word.
	Depth int
}

// Pattern is one compiled command pattern: a command word and the words after it (ADR 0048 (1)).
type Pattern struct {
	// Entry is the entry as written.
	Entry string
	// List is the list it came from.
	List List
	// Command is the command word as written: a bare name, or a path in exec.allow.
	Command string
	// Tool is the name rules are keyed by: the row's tool, or the command word's basename.
	Tool string
	// Row is the tool's row; nil for the generic fallback.
	Row *Row
	// Bare is an entry with no words after the command word.
	Bare bool
	// Path, Opts and Operands are a row pattern's subcommand words, option words and operand words.
	Path     []string
	Opts     []PatOpt
	Operands []string
	// Rest is a trailing lone `*`: any further tokens.
	Rest bool
	// Words are the generic fallback's words after the command word (the separator and Rest's `*` excluded).
	Words []string
	// Warnings are lint findings, including literal shell characters and unusual option dashes.
	Warnings []string
	// Runtime names the grant of a pattern the runtime made on its own authority (ExactPattern), "" for a contract's
	// entry. Such a pattern matches exactly: Argv0 is the argv[0] it admits, and Words every element after it.
	Runtime, Argv0 string

	// fallback is this entry parsed against the interpreter compatibility row.
	fallback *Pattern

	// legacyDashes keeps the released whole-pattern reading for deny/ask entries
	// with extra name dashes. It must retain value and subcommand binding too.
	compat                    *Pattern
	legacyDashes, extraDashes bool
	released                  *Pattern

	genWords, genOpts []string // the generic fallback's non-option and option words
	genOperands       []string // operands after a generic pattern separator
	genSeparator      int      // its offset in Words, -1 when absent

	// separated holds the other meanings of an unestablished command-position separator.
	// pathExact prevents a separator that leaves dispatch at this level from naming its children.
	separated []*Pattern
	pathExact bool
	separator bool
}

// Rule is the pattern's rule name in the ledger: exec.deny[git push], or exec.<kind>[<argv[0]>] for a runtime grant
// (ExactPattern).
func (p *Pattern) Rule() string {
	if p.Runtime != "" {
		return "exec." + p.Runtime + "[" + p.Entry + "]"
	}
	return "exec." + p.List.String() + "[" + p.Entry + "]"
}

// HasWords reports whether the pattern names anything after its command word.
func (p *Pattern) HasWords() bool { return !p.Bare }

// NamesArgs reports whether the pattern names options or operands, which a constrained allow entry requires and
// an unknown option can rebind.
func (p *Pattern) NamesArgs() bool {
	if p.Row == nil {
		return len(p.Words) > 0
	}
	if len(p.Opts) > 0 || len(p.Operands) > 0 {
		return true
	}
	for _, q := range p.separated {
		if len(q.Opts) > 0 || len(q.Operands) > 0 {
			return true
		}
	}
	return false
}

// SyntaxError is a pattern the contract cannot hold; Fix says what to write instead.
type SyntaxError struct {
	Entry, Msg, Fix string
	// Warnings remain actionable even when another part of the entry is invalid.
	Warnings []string
}

func (e *SyntaxError) Error() string {
	if e.Fix == "" {
		return fmt.Sprintf("%q: %s", e.Entry, e.Msg)
	}
	return fmt.Sprintf("%q: %s; %s", e.Entry, e.Msg, e.Fix)
}

// SplitWords splits an entry on unquoted ASCII spaces and tabs; "..." and '...' quote a word that holds a space, and
// no other escape exists. quoted reports whether any quote was used.
func SplitWords(entry string) (words []string, quoted bool, err error) {
	var cur strings.Builder
	in := byte(0)
	started := false
	for i := 0; i < len(entry); i++ {
		c := entry[i]
		switch {
		case in != 0:
			if c == in {
				in = 0
				continue
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			in, started, quoted = c, true, true
		case c == ' ' || c == '\t':
			if started {
				words = append(words, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if in != 0 {
		return nil, quoted, fmt.Errorf("unterminated %c quote", in)
	}
	if started {
		words = append(words, cur.String())
	}
	return words, quoted, nil
}

// IsPattern reports whether an exec.allow entry is a command pattern (it has an unquoted space or tab) rather than
// one word (a bare name or a path). It is a pure function of the text (ADR 0048 (1)). An entry with no space or tab
// is one word exactly as written, quote characters included, as every entry was before ADR 0048: a path such as
// /home/me/O'Brien/bin/tool or /opt/a'b'c/tool names that file.
func IsPattern(entry string) bool {
	if literalWord(entry) {
		return false
	}
	words, _, err := SplitWords(entry)
	return err != nil || len(words) != 1
}

// Word is a one-word exec.allow entry's word: an entry with no space or tab as written, and one whose quotes make a
// single word of text with spaces without them ('/opt/My Tools/run' is /opt/My Tools/run). An entry that is not one
// word is returned as written.
func Word(entry string) string {
	if literalWord(entry) {
		return entry
	}
	words, _, err := SplitWords(entry)
	if err != nil || len(words) != 1 {
		return entry
	}
	return words[0]
}

// literalWord reports whether an entry holds no space or tab, so no quote in it is needed: in exec.allow it is one
// word, exactly as written.
func literalWord(entry string) bool {
	return entry != "" && !strings.ContainsAny(entry, " \t")
}

// shellWords are whole words that are shell syntax: nothing in an entry is run by a shell, so each is an error.
var shellWords = map[string]bool{"&&": true, "||": true, "|": true, ";": true, "<": true, ">": true, ">>": true, "&": true}

// Parse compiles one entry of list with the rows. A one-word entry (a bare name or, in exec.allow, a path) is a
// Bare pattern. Errors are *SyntaxError and name the word and the fix.
func Parse(entry string, list List, rows *Rows) (*Pattern, error) {
	bad := func(msg, fix string) (*Pattern, error) { return nil, &SyntaxError{Entry: entry, Msg: msg, Fix: fix} }
	if len(entry) > MaxEntry {
		return bad(fmt.Sprintf("an entry holds at most %d bytes", MaxEntry), "split it into shorter entries")
	}
	if !utf8.ValidString(entry) || strings.ContainsRune(entry, 0) {
		return bad("an entry must be valid UTF-8 with no NUL", "")
	}
	words, _, err := SplitWords(entry)
	if list == ListAllow && literalWord(entry) {
		// An exec.allow entry with no space or tab is a path or a name as written (IsPattern).
		words, err = []string{entry}, nil
	}
	if err != nil {
		return bad(err.Error(), "close the quote, or quote the whole word with the other quote character; no other escape exists")
	}
	if len(words) == 0 || words[0] == "" {
		return bad("an entry needs a command word", "")
	}
	if len(words) > MaxWords+1 {
		return bad(fmt.Sprintf("an entry holds at most %d words after its command", MaxWords), "")
	}
	p := &Pattern{Entry: entry, List: list, Command: words[0], genSeparator: -1}
	for i, w := range words {
		if len(w) > MaxWordBytes {
			return bad(fmt.Sprintf("word %d holds more than %d bytes", i+1, MaxWordBytes), "")
		}
		if shellWords[w] {
			return bad(fmt.Sprintf("%q is shell syntax, and nothing in an entry runs through a shell", w), "write each command as its own entry")
		}
		if strings.Contains(w, "$") || strings.Contains(w, "`") {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%q holds $ or a backtick, which is matched literally: nothing is expanded", w))
		}
	}
	cmd := words[0]
	if strings.Contains(cmd, "(") || strings.HasSuffix(words[len(words)-1], ":*") {
		return bad("Claude Code's Bash(...:*) rule syntax is not an exec entry", "write the command and its words: "+strconv.Quote(claudeFix(words)))
	}
	if strings.ContainsAny(cmd, "*?[") {
		return bad(fmt.Sprintf("the command word %q holds a glob", cmd), "name the command; globs are allowed in later words")
	}
	if strings.Contains(cmd, "/") && list != ListAllow {
		fix := path.Base(cmd)
		if len(words) > 1 {
			fix += " " + strings.Join(words[1:], " ")
		}
		article := "a"
		if list == ListAsk {
			article = "an"
		}
		return bad(fmt.Sprintf("%s %s entry matches every file of a name, so a path in its command word would broaden it", article, list), "write "+strconv.Quote(fix))
	}
	p.Tool = path.Base(cmd)
	p.Row = rows.Lookup(p.Tool)
	if p.Row != nil {
		p.Tool = p.Row.Tool
	}
	rest := words[1:]
	if len(rest) == 0 {
		p.Bare = true
		return p, nil
	}
	for i, w := range rest {
		if w == "*" && i != len(rest)-1 {
			return bad("a lone * is allowed only as the last word", "remove it, or move it last to mean any further tokens")
		}
	}
	if rest[len(rest)-1] == "*" {
		p.Rest = true
		rest = rest[:len(rest)-1]
	}
	if p.Row == nil {
		if err := p.keepReleasePattern(rest); err != nil {
			return nil, err
		}
		for _, w := range rest {
			if w == "--" && p.genSeparator < 0 {
				p.separator = true
				p.genSeparator = len(p.Words)
				continue
			}
			p.Words = append(p.Words, w)
			switch {
			case p.genSeparator >= 0:
				p.genOperands = append(p.genOperands, w)
			case isOptionWord(w):
				p.warnOptionSpelling(w, nil)
				p.genOpts = append(p.genOpts, w)
			default:
				p.genWords = append(p.genWords, w)
			}
		}
		return p, nil
	}
	if err := p.parseRow(rest); err != nil {
		if se, ok := err.(*SyntaxError); ok {
			se.Warnings = p.Warnings
		}
		return nil, err
	}
	if p.extraDashes && list != ListAllow {
		q := &Pattern{Entry: entry, List: list, Command: p.Command, Tool: p.Tool, Row: p.Row, Rest: p.Rest, legacyDashes: true}
		if err := q.parseRow(rest); err != nil {
			return nil, err
		}
		p.compat = q
	}
	if err := p.keepReleasePattern(rest); err != nil {
		return nil, err
	}
	if spec := p.Row.Interp; spec != nil && spec.Fallback != nil {
		fallback, err := Parse(entry, list, NewRows(spec.Fallback))
		if err == nil {
			p.fallback = fallback
			if p.released != nil {
				p.released.fallback = fallback.released
			}
		}
		// An inventory-only allow option may be unknown to the compatibility
		// row. Match fails closed there rather than falling back to token matching.
	}
	return p, nil
}

// claudeFix turns Bash(git push:*) into the entry it meant.
func claudeFix(words []string) string {
	s := strings.Join(words, " ")
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, ")"), ":*")
	return strings.TrimSpace(s)
}

// parseRow reads a row pattern's words with the row, as an invocation is read: subcommand words while the level has
// subcommands, option words wherever they stand, operands after.
func (p *Pattern) parseRow(words []string) error {
	lv := p.Row.Root
	depth := 0
	opsOnly := false
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case opsOnly || w == "-" || len(w) < 2 || w[0] != '-' && !(w[0] == '+' && lv.Syntax.PlusOptions):
			if !opsOnly && lv.Subs != nil {
				if lv.skip(w) {
					if p.List == ListAllow {
						return &SyntaxError{Entry: p.Entry, Msg: fmt.Sprintf("row %s discards selector %q and cannot enforce it in an allow entry", p.Row.Tool, w), Fix: "remove the selector to admit the operation across variants"}
					}
					continue
				}
				if path, child, ok := lv.sub(w); ok {
					p.Path = append(p.Path, path...)
					if child == nil {
						child = &Level{parent: lv, Syntax: lv.Syntax}
					}
					lv, depth = child, depth+len(path)
					continue
				}
				if lv.Wild != nil {
					p.Path = append(p.Path, w)
					lv, depth = lv.Wild, depth+1
					continue
				}
				// An unknown subcommand word (a plugin, an external command): matched as written, and the level below it
				// reads only the options persistent above it.
				p.Path = append(p.Path, w)
				lv, depth = &Level{parent: lv, Syntax: lv.Syntax}, depth+1
				continue
			}
			p.Operands = append(p.Operands, w)
			if !lv.Syntax.Permute {
				opsOnly = true
			}
		case lv.Syntax.AllDashTerminator && len(w) > 2 && strings.Trim(w, "-") == "":
			return &SyntaxError{Entry: p.Entry, Msg: "an all-dash terminator has no stable pattern meaning", Fix: "write -- before operands"}
		case w == "--":
			return p.parseSeparatedRow(words)
		default:
			if lv.Subs != nil && lv.Default != "" {
				p.Path = append(p.Path, lv.Default)
				lv, depth = lv.Subs[lv.Default], depth+1
			}
			n, err := p.optionWord(lv, depth, words, i)
			if err != nil {
				return err
			}
			if n == 1 && words[i+1] == "--" && len(p.Opts) > 0 {
				o := p.Opts[len(p.Opts)-1].Opt
				if o != nil && o.Arg == ArgRequired {
					mode := lv.Syntax.NextOption
					if o.NextOption != NextOptionDefault {
						mode = o.NextOption
					}
					if mode != NextOptionValue {
						// The value reader may leave this word as the separator.
						// Reuse its typed readings instead of making the entry inert.
						return p.parseSeparatedRow(words)
					}
				}
			}
			i += n
			if k := len(p.Opts); k > 0 && p.Opts[k-1].Opt != nil && p.Opts[k-1].Opt.ends(p.Opts[k-1].HasValue, p.Opts[k-1].Value) {
				opsOnly = true // the option ends the options, as `--` does (Opt.Ends, Opt.EndsAttached)
			}
		}
	}
	return nil
}

// parseSeparatedRow uses the invocation parser for a pattern with a separator. In
// particular, a default command is selected before operands, and only a child's
// established option vocabulary restarts after command dispatch. Rejected-marker
// readings are not separator meanings and cannot become empty broad predicates.
func (p *Pattern) parseSeparatedRow(words []string) error {
	// Pattern command words remain literal. Autocorrection is an invocation
	// reading, so do not supply its candidate set while compiling an entry.
	nz := &Normalizer{row: p.Row.ready()}
	var meanings []*Pattern
readings:
	for _, r := range nz.Normalize(words) {
		if r.Unlocatable {
			return &SyntaxError{Entry: p.Entry, Msg: "separator pattern has too many or unlocatable meanings", Fix: "name the subcommand and its operands without the separator"}
		}
		for _, word := range r.Path {
			if strings.ContainsAny(word, "*?[") {
				// A literal unknown token looks like a leaf to Normalize, but a
				// glob can also name a group with different separator/default rules.
				return &SyntaxError{Entry: p.Entry,
					Msg: fmt.Sprintf("subcommand glob %q cannot establish separator dispatch", word),
					Fix: "name each subcommand explicitly when using --"}
			}
		}
		q := &Pattern{Row: p.Row, List: p.List, Path: r.Path, Operands: r.Operands, Rest: p.Rest, pathExact: !r.Located}
		for _, h := range r.Hits {
			if h.Opt == nil && h.Raw == "--" {
				continue readings
			}
			if h.Opt == nil && p.List == ListAllow {
				return p.unknownOptErr(h.Raw)
			}
			if h.Opt == nil {
				spelled, err := p.separatorUnknownOptions(&r, h)
				if err != nil {
					return err
				}
				q.Opts = append(q.Opts, spelled...)
				continue
			}
			// Name spelling remains the pattern parser's policy even when
			// invocation normalization already knows the option identity.
			lv := p.separatorLevel(&r, h.Depth)
			if lv == nil {
				return &SyntaxError{Entry: p.Entry, Msg: "separator option has an invalid command depth", Fix: "name the command before --"}
			}
			names := &Pattern{Entry: p.Entry, List: p.List, Row: p.Row, legacyDashes: p.legacyDashes}
			if _, err := names.optionWord(lv, h.Depth, []string{h.Raw}, 0); err != nil {
				p.Warnings = append(p.Warnings, names.Warnings...)
				return err
			}
			p.Warnings = append(p.Warnings, names.Warnings...)
			p.extraDashes = p.extraDashes || names.extraDashes
			for _, po := range names.Opts {
				po.Value, po.HasValue, po.Neg, po.Depth = h.Value, h.HasValue, h.Neg, h.Depth
				q.Opts = append(q.Opts, po)
			}
		}
		if p.List == ListAllow && r.UnknownBefore {
			return &SyntaxError{Entry: p.Entry, Msg: "separator pattern cannot locate its command", Fix: "name the subcommand before the separator"}
		}
		if !slices.ContainsFunc(meanings, func(other *Pattern) bool { return sameSeparatorMeaning(other, q) }) {
			meanings = append(meanings, q)
		}
	}
	if len(meanings) == 0 {
		return &SyntaxError{Entry: p.Entry, Msg: "the row does not accept -- as a separator here", Fix: "name the subcommand before the separator"}
	}
	if p.List == ListAllow && len(meanings) > 1 {
		// An invocation grant requires every parser reading. Choosing one of
		// several pattern meanings could instead grant a different operation
		// or discard a required argument predicate (ADR 0048 (2)).
		return &SyntaxError{Entry: p.Entry, Msg: "separator allow pattern has more than one command or argument meaning", Fix: "name the command before -- and spell required option values explicitly"}
	}
	first := meanings[0]
	p.Path, p.Opts, p.Operands, p.pathExact = first.Path, first.Opts, first.Operands, first.pathExact
	p.separated = meanings[1:]
	p.separator = true
	return nil
}

// separatorUnknownOptions recovers spelling through the existing pattern name
// parser, with only the original level's syntax. No ancestor vocabulary may turn
// an ended parser's unknown spelling into a known or negated option. Values and
// arities remain those of the normalized reading, not the spelling parser.
func (p *Pattern) separatorUnknownOptions(r *Reading, h Hit) ([]PatOpt, error) {
	bad := func() ([]PatOpt, error) {
		return nil, &SyntaxError{Entry: p.Entry, Msg: fmt.Sprintf("separator option %q has no stable pattern spelling", h.Raw), Fix: "name the command before the separator"}
	}
	if h.Depth < 0 || h.Depth > len(r.Path) {
		return bad()
	}
	lv := p.separatorLevel(r, h.Depth)
	if lv == nil {
		return bad()
	}
	names := &Pattern{Entry: p.Entry, List: p.List, Row: p.Row, legacyDashes: p.legacyDashes}
	if _, err := names.optionWord(&Level{Syntax: lv.Syntax}, h.Depth, []string{h.Raw}, 0); err != nil {
		return nil, err
	}
	p.Warnings = append(p.Warnings, names.Warnings...)
	p.extraDashes = p.extraDashes || names.extraDashes
	if len(names.Opts) == 0 {
		return bad()
	}
	for i := range names.Opts {
		o := &names.Opts[i]
		if o.Long == "" && o.Short == 0 {
			return bad()
		}
		o.Value, o.HasValue, o.Neg, o.Depth = h.Value, h.HasValue, h.Neg, h.Depth
	}
	return names.Opts, nil
}

func (p *Pattern) separatorLevel(r *Reading, depth int) *Level {
	if r == nil || p.Row == nil || p.Row.Root == nil || depth < 0 || depth > len(r.Path) {
		return nil
	}
	lv := p.Row.Root
	for _, name := range r.Path[:depth] {
		if lv == nil {
			return &Level{}
		}
		child, known := lv.Subs[name]
		if !known {
			child = lv.Wild
		}
		if child == nil {
			child = &Level{parent: lv, Syntax: lv.Syntax}
		}
		lv = child
	}
	return lv
}

// sameSeparatorMeaning compares matching predicates, ignoring spelling, option
// order and duplicate requirements. Parser forks with the same predicates do not
// make an otherwise established allow entry ambiguous.
func sameSeparatorMeaning(a, b *Pattern) bool {
	if a.pathExact != b.pathExact || a.Rest != b.Rest || !slices.Equal(a.Path, b.Path) || !slices.Equal(a.Operands, b.Operands) {
		return false
	}
	contains := func(haystack []PatOpt, needle PatOpt) bool {
		return slices.ContainsFunc(haystack, func(o PatOpt) bool {
			if o.Neg != needle.Neg || o.HasValue != needle.HasValue || o.HasValue && o.Value != needle.Value {
				return false
			}
			if o.Opt == nil || needle.Opt == nil {
				return o.Opt == needle.Opt && o.Long == needle.Long && o.Short == needle.Short
			}
			if o.Opt.Name != needle.Opt.Name {
				return false
			}
			return a.List != ListAllow || o.Opt.Persistent == needle.Opt.Persistent && (o.Opt.Persistent || o.Depth == needle.Depth)
		})
	}
	for _, o := range a.Opts {
		if !contains(b.Opts, o) {
			return false
		}
	}
	for _, o := range b.Opts {
		if !contains(a.Opts, o) {
			return false
		}
	}
	return true
}

// optionWord reads the option word at words[i] (and its value word, when the option takes one) and returns how many
// further words it consumed.
func (p *Pattern) optionWord(lv *Level, depth int, words []string, i int) (int, error) {
	w := words[i]
	if !p.legacyDashes {
		p.warnOptionSpelling(w, lv)
	}
	long := strings.HasPrefix(w, "--") || lv.Syntax.SingleDashLong
	if long {
		body := w
		switch {
		case p.legacyDashes:
			body = strings.TrimLeft(w, "-")
		case strings.HasPrefix(w, "--"):
			body = w[2:]
		case strings.HasPrefix(w, "-"):
			body = w[1:]
		}
		name, value, hasEq := strings.Cut(body, "=")
		if lv.Syntax.Underscores {
			name = strings.ReplaceAll(name, "_", "-") // as the normalizer reads the tool's argv (Syntax.Underscores)
		}
		o := lv.long(name)
		neg := false
		if o == nil && lv.Syntax.Negatable && strings.HasPrefix(name, "no-") {
			if o = lv.long(name[3:]); o != nil {
				neg = true
			}
		}
		if o == nil && lv.Syntax.LongPrefix && name != "" {
			if c, ok := lv.longPrefix(name); ok {
				o = c
			} else if !p.legacyDashes && lv.Syntax.Negatable && strings.HasPrefix(name, "no-") {
				if c, ok := lv.longPrefix(name[3:]); ok {
					o, neg = c, true
				}
			}
		}
		raw := w
		if hasEq {
			raw = w[:len(w)-len(value)-1]
		}
		po := PatOpt{Opt: o, Raw: raw, Long: name, Value: value, HasValue: hasEq, Neg: neg, Depth: depth}
		if neg {
			po.Long = name[3:]
		}
		used := 0
		// An ArgNextWord option takes a word after its --no- form too, as the normalizer reads it; an attached value
		// in a pattern stays the glob it was written as.
		if o != nil && (!neg || o.Arg == ArgNextWord) && !hasEq && takesNext(o, words, i) {
			po.Value, po.HasValue, used = words[i+1], true, 1
		}
		if o == nil && p.List == ListAllow {
			return 0, p.unknownOptErr(w)
		}
		p.Opts = append(p.Opts, po)
		return used, nil
	}
	if lv.Syntax.ShortWords && len(w) > 2 && w[0] == '-' {
		if o := lv.long(w[1:]); o != nil {
			po := PatOpt{Opt: o, Raw: w, Long: w[1:], Depth: depth}
			used := 0
			if takesNext(o, words, i) {
				po.Value, po.HasValue, used = words[i+1], true, 1
			}
			p.Opts = append(p.Opts, po)
			return used, nil
		}
	}
	// -n=v is the pattern spelling of a short option with a value, whatever the tool accepts.
	if len(w) > 2 && w[2] == '=' {
		o := lv.shortOpt(w[1])
		if o == nil && p.List == ListAllow {
			return 0, p.unknownOptErr(w)
		}
		p.Opts = append(p.Opts, PatOpt{Opt: o, Raw: w[:2], Short: w[1], Value: w[3:], HasValue: true, Depth: depth})
		return 0, nil
	}
	for j := 1; j < len(w); j++ {
		c := w[j]
		o := lv.shortOpt(c)
		if o == nil {
			if p.List == ListAllow {
				return 0, p.unknownOptErr(w)
			}
			p.Opts = append(p.Opts, PatOpt{Raw: string([]byte{w[0], c}), Short: c, Depth: depth})
			if !lv.Syntax.Clusters {
				return 0, nil
			}
			continue
		}
		if o.Arg == ArgNone || o.Arg == ArgNextWord && j < len(w)-1 {
			p.Opts = append(p.Opts, PatOpt{Opt: o, Raw: string([]byte{w[0], c}), Short: c, Depth: depth})
			continue
		}
		po := PatOpt{Opt: o, Raw: string([]byte{w[0], c}), Short: c, Depth: depth}
		if rest := w[j+1:]; rest != "" {
			po.Value, po.HasValue = rest, true
			p.Opts = append(p.Opts, po)
			return 0, nil
		}
		used := 0
		if takesNext(o, words, i) {
			po.Value, po.HasValue, used = words[i+1], true, 1
		}
		p.Opts = append(p.Opts, po)
		return used, nil
	}
	return 0, nil
}

// warnOptionSpelling names likely contract typos before they become errors in a
// later minor release. Invocation parsing remains independent of this lint.
func (p *Pattern) warnOptionSpelling(w string, lv *Level) {
	name, _, _ := strings.Cut(w, "=")
	ordinary := strings.TrimLeft(name, "-")
	extra := strings.HasPrefix(name, "---") && ordinary != ""
	single := false
	if len(name) > 2 && name[0] == '-' && name[1] != '-' && lv != nil {
		long := name[1:]
		// These rows explicitly accept the tool's single-dash spelling.
		if lv.Syntax.SingleDashLong || lv.Syntax.ShortWords && lv.long(w[1:]) != nil {
			return
		}
		single = lv.long(long) != nil
		if !single && lv.Syntax.Negatable && strings.HasPrefix(long, "no-") {
			long = long[3:]
			single = lv.long(long) != nil
		}
		if !single && long != "" && lv.Syntax.LongPrefix {
			_, single = lv.longPrefix(long)
		}
	}
	if !extra && !single {
		return
	}
	p.extraDashes = p.extraDashes || extra
	p.Warnings = append(p.Warnings, fmt.Sprintf("option %q has unusual leading dashes; the ordinary spelling is probably %q; correct the entry before a later minor release makes this an error", name, "--"+ordinary))
}

// takesNext reports whether a pattern's option word takes the next word as its value: a value-taking option does, an
// ArgMaybe option when the next word is one of its values, and an ArgNextWord option when it is a word, not an
// option. A trailing * is never a value.
func takesNext(o *Opt, words []string, i int) bool {
	if i+1 >= len(words) || words[i+1] == "*" {
		return false
	}
	switch o.Arg {
	case ArgRequired:
		return true
	case ArgMaybe:
		for _, v := range o.Values {
			if words[i+1] == v {
				return true
			}
		}
	case ArgNextWord:
		return words[i+1] != "" && words[i+1][0] != '-'
	case ArgNone, ArgOptional:
	}
	return false
}

// unknownOptErr is an allow entry naming an option its row does not list: the entry requires it, and an option the
// row does not read can never be shown to be present.
func (p *Pattern) unknownOptErr(w string) error {
	return &SyntaxError{Entry: p.Entry,
		Msg: fmt.Sprintf("row %s does not list the option %q where it stands, and an allow entry can require only options its row reads", p.Row.Tool, w),
		Fix: "drop the option, or name it in a deny entry instead"}
}
