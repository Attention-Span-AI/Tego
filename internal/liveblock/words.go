// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// A command-word block is an exec block whose value is a command (ADR 0171): a program name and words, "git push" or
// "npm install --global *". It refuses what a contract holding the same text as an exec.deny entry would refuse, decided
// by the contract's own matcher (execmatch, ADR 0048), so the block, `exec.deny` and `exec.allow` words read an argv one
// way. Its value is the entry's text in the entry's own grammar: words split on spaces, a word holding a space quoted
// with "..." or '...', no other escape, and the program named by its bare name (a deny entry matches every file of a
// name, so a path in the command word would broaden it, and execmatch.Parse refuses one). A value with no "/" in front
// and a space in it is such a command; an absolute value is a program path, with spaces if its file has them, exactly as
// before. An overlay that holds one is VersionWords, written only to a run whose launcher made the WordsName mark.

// IsWords reports whether the exec value v (normalized) names a command with words rather than a program: it does not
// start with "/" and it holds a space.
func IsWords(v string) bool { return !strings.HasPrefix(v, "/") && strings.Contains(v, " ") }

// IsWords reports whether e is a command-word block.
func (e Entry) IsWords() bool { return e.Kind == KindExec && IsWords(e.Value) }

// NormalizeWords is the normal form of a command-word value, or why it is not one: trimmed, the entry grammar's
// words, the program a bare name followed by at least one word, and accepted by the command matcher as an exec.deny
// entry (execmatch.Parse with ListDeny, the contract's own rows). Words are joined by one space; an entry that quotes a
// word is kept as written, since another spelling of its quotes could mean something else. Every spelling of one
// command normalizes to one value, so adding it twice adds it once and removing it by another spelling removes it.
func NormalizeWords(value string) (string, error) {
	v := strings.TrimSpace(value)
	if err := plain(v); err != nil {
		return "", err
	}
	words, quoted, err := execmatch.SplitWords(v)
	if err != nil {
		return "", fmt.Errorf("%w: command %q: %v", ErrInvalid, v, err)
	}
	if len(words) < 2 {
		return "", fmt.Errorf("%w: command %q names no words after its program; block the program itself instead", ErrInvalid, v)
	}
	prog := words[0]
	if strings.HasPrefix(prog, "/") || strings.Contains(prog, "/") || prog == "." || prog == ".." || len(prog) > 255 {
		return "", fmt.Errorf("%w: command %q: a command block names its program by its bare name (%q), never a path, which would broaden it", ErrInvalid, v, baseName(prog))
	}
	if _, err := execmatch.Parse(v, execmatch.ListDeny, rows.Builtin()); err != nil {
		return "", fmt.Errorf("%w: command %q: %v", ErrInvalid, v, err)
	}
	if !quoted {
		v = strings.Join(words, " ")
	}
	return v, nil
}

// baseName is the last element of p, for the hint that names the program without its path.
func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}

// NormalizeKey is the normal form of value as a lookup key finds a held block: Normalize, or, for an exec value that is
// not a program, NormalizeWords. The overlay's finders and removers use it, so one spelling asks for either sort of block.
func NormalizeKey(kind Kind, value string) (string, error) {
	v, err := Normalize(kind, value)
	if err == nil || kind != KindExec {
		return v, err
	}
	if t := strings.TrimSpace(value); !strings.HasPrefix(t, "/") && strings.ContainsAny(t, " \t") {
		return NormalizeWords(t)
	}
	return v, err
}
