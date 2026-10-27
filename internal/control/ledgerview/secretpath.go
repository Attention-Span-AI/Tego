// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/secretpath"
)

// IsSecretPath reports whether p names a file or directory that holds secrets, by its name only (secretpath.Is, the
// one classifier the receipt's "Sensitive files read" uses too, so the page and the terminal flag the same files). A
// path the run's own rules guard (fs.deny_read, fs.ask_read) is a secret to that run whatever its name (secretRule).
func IsSecretPath(p string) bool { return secretpath.Is(p) }

// secretRule reports whether the rule that decided a file line guards a secret (secretpath.GuardRule).
func secretRule(rule string) bool { return secretpath.GuardRule(rule) }

// A path's name is classified once per line, when the Store takes the line (markSecret), and kept on the Event:
// 56-64% of a live update's CPU went to IsSecretPath for every path of every line on each Signal and Compare (the r7
// perf lane, PF-F1). A per-path memo was tried first and dropped: a long run names more distinct paths than a bounded
// memo holds (86k in the perf ledger), and the thrashing memo cost more than the classifier it saved.

// secKnown is the bit of Event.sec that says the line was marked: bits 0 and 1 then hold IsSecretPath of its paths.
const secKnown uint8 = 1 << 7

// markSecret marks e with IsSecretPath of what Signal and Compare read as its paths: a file line's path, or both of a
// rename's (paths); a refused line's target; an ask line's target. A file line naming more than two paths (a path
// holding " → ") is left unmarked and read by name each time.
func markSecret(e *Event) {
	set := func(i int, p string) {
		if IsSecretPath(p) {
			e.sec |= 1 << i
		}
	}
	switch e.Kind {
	case "fs":
		a, b, two := strings.Cut(e.Target, " → ")
		if two && strings.Contains(b, " → ") {
			return
		}
		set(0, a)
		if two {
			set(1, b)
		}
	case "refused":
		set(0, e.Target)
	case "ask":
		set(0, e.askTarget)
	default:
		return
	}
	e.sec |= secKnown
}

// secretPart is IsSecretPath(p) for p the i-th of e's paths as markSecret reads them (i is 0 or 1), from the line's
// mark, or by name when the line was not taken by a Store (a test's literal) or holds more than two paths.
func (e *Event) secretPart(i int, p string) bool {
	if e.sec&secKnown != 0 && i < 2 {
		return e.sec&(1<<i) != 0
	}
	return IsSecretPath(p)
}

// sensitiveMatch is a Sensitive with its entries resolved once (the run's working folder joined, cleaned) and its key
// (the entries and the folder: Signal's fold is for one Sensitive only).
type sensitiveMatch struct {
	key     string
	entries []sensEntry
	rules   []SevRule // the person's severity rules, which finish reads
}

type sensEntry struct {
	entry, full, dir string // dir is full + "/"
	glob             bool
}

func sensKey(s Sensitive) string {
	var k strings.Builder
	k.WriteString(strings.Join(s.Entries, "\x00"))
	k.WriteString("\x01")
	k.WriteString(s.Cwd)
	for _, r := range s.Rules {
		for _, part := range [...]string{"\x01", r.Channel, "\x00", r.Match, "\x00", r.Severity.String()} {
			k.WriteString(part)
		}
	}
	return k.String()
}

// compileSensitive resolves s's entries as Sensitive.under reads them: an entry under ~ is skipped (the run's home is
// not recorded; a refusal still names the entry in its rule), a relative one joins the run's working folder (skipped
// without one), and a pattern with * ? or [ matches by filepath.Match.
func compileSensitive(s Sensitive) sensitiveMatch {
	m := sensitiveMatch{key: sensKey(s), rules: s.Rules}
	for _, e := range s.Entries {
		full := e
		if strings.HasPrefix(full, "~") {
			continue
		}
		if !filepath.IsAbs(full) {
			if s.Cwd == "" {
				continue
			}
			full = filepath.Join(s.Cwd, full)
		}
		full = filepath.Clean(full)
		m.entries = append(m.entries, sensEntry{entry: e, full: full, dir: full + "/", glob: strings.ContainsAny(full, "*?[")})
	}
	return m
}

// under is the first entry p is under, as written.
func (m *sensitiveMatch) under(p string) (string, bool) {
	for _, e := range m.entries {
		if e.glob {
			if ok, _ := filepath.Match(e.full, p); ok {
				return e.entry, true
			}
			continue
		}
		if p == e.full || strings.HasPrefix(p, e.dir) {
			return e.entry, true
		}
	}
	return "", false
}
