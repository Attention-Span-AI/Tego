// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"fmt"
	"path"
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
	// Words are the generic fallback's words after the command word (Rest's `*` excluded).
	Words []string
	// Warnings are lint findings that do not refuse the entry ($ or a backtick in a word, matched literally).
	Warnings []string
	// Runtime names the grant of a pattern the runtime made on its own authority (ExactPattern), "" for a contract's
	// entry. Such a pattern matches exactly: Argv0 is the argv[0] it admits, and Words every element after it.
	Runtime, Argv0 string

	genWords, genOpts []string // the generic fallback's non-option and option words
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
	return len(p.Opts) > 0 || len(p.Operands) > 0
}

// SyntaxError is a pattern the contract cannot hold; Fix says what to write instead.
type SyntaxError struct {
	Entry, Msg, Fix string
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
	p := &Pattern{Entry: entry, List: list, Command: words[0]}
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
		p.Words = append([]string(nil), rest...)
		for _, w := range rest {
			if isOptionWord(w) {
				p.genOpts = append(p.genOpts, w)
			} else {
				p.genWords = append(p.genWords, w)
			}
		}
		return p, nil
	}
	if err := p.parseRow(rest); err != nil {
		return nil, err
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
		case w == "--":
			opsOnly = true
		default:
			if lv.Subs != nil && lv.Default != "" {
				p.Path = append(p.Path, lv.Default)
				lv, depth = lv.Subs[lv.Default], depth+1
			}
			n, err := p.optionWord(lv, depth, words, i)
			if err != nil {
				return err
			}
			i += n
			if k := len(p.Opts); k > 0 && p.Opts[k-1].Opt != nil && p.Opts[k-1].Opt.ends(p.Opts[k-1].HasValue, p.Opts[k-1].Value) {
				opsOnly = true // the option ends the options, as `--` does (Opt.Ends, Opt.EndsAttached)
			}
		}
	}
	return nil
}

// optionWord reads the option word at words[i] (and its value word, when the option takes one) and returns how many
// further words it consumed.
func (p *Pattern) optionWord(lv *Level, depth int, words []string, i int) (int, error) {
	w := words[i]
	long := strings.HasPrefix(w, "--") || lv.Syntax.SingleDashLong
	if long {
		body := strings.TrimLeft(w, "-")
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
		if o == nil && lv.Syntax.LongPrefix {
			if c, ok := lv.longPrefix(name); ok {
				o = c
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
