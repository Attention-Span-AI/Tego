// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Direction is which way a change moves what the next run may do. A page confirms a narrowing in one step and asks
// for an explicit acknowledgement of anything else: Mixed is confirmed like Widens.
type Direction string

// The three directions.
const (
	// Narrows: the next run may do less, or the same; nothing it may do becomes looser.
	Narrows Direction = "narrows"
	// Widens: the next run may do more somewhere, and less nowhere.
	Widens Direction = "widens"
	// Mixed: more somewhere and less elsewhere, or a change whose direction the core cannot tell for sure.
	Mixed Direction = "mixed"
)

// join is the direction of two changes made together.
func (d Direction) join(o Direction) Direction {
	switch {
	case d == "":
		return o
	case o == "" || d == o:
		return d
	}
	return Mixed
}

// actionDirection is the direction of "make this a rule" from an event: a block only refuses, an allow only lets
// through, and an ask narrows an action the run was allowed and widens one it was refused (a person may now say yes).
func actionDirection(a Action, refused bool) Direction {
	switch a {
	case Block:
		return Narrows
	case Allow:
		return Widens
	case Ask:
	}
	if refused {
		return Widens
	}
	return Narrows
}

// resolver reads fs entries as compile does: relative ones from dir (the run's working directory, or the
// contract's), ~/ ones from home.
type resolver struct{ dir, home string }

// resolve is where an fs entry points, cleaned; "" for a ~/ entry when no home is known.
func (r resolver) resolve(entry string) string {
	switch {
	case entry == "~" || strings.HasPrefix(entry, "~/"):
		if r.home == "" {
			return ""
		}
		return path.Join(r.home, strings.TrimPrefix(entry, "~"))
	case path.IsAbs(entry):
		return path.Clean(entry)
	}
	return path.Join(r.dir, entry)
}

// within reports whether p is root or lies beneath it (both clean and absolute).
func within(p, root string) bool {
	return root != "" && p != "" && (p == root || root == "/" || strings.HasPrefix(p, root+"/"))
}

// access is what a contract does with one action at one place, as the next run would decide it.
type access int

// The accesses, least permissive first.
const (
	// refusedNone: no entry grants it (a write outside every write entry, a program off the allow list).
	refusedNone access = iota
	// refusedDeny: an entry refuses it (deny_read, deny_write, a built-in protection).
	refusedDeny
	// asked: a person is asked first.
	asked
	// allowed: it goes ahead.
	allowed
)

// rank orders accesses by how much they let through: both refusals are one rank.
func (a access) rank() int {
	switch a {
	case asked:
		return 1
	case allowed:
		return 2
	case refusedNone, refusedDeny:
	}
	return 0
}

// compare is the direction of moving from a to b; "" when both let the same through.
func compare(a, b access) Direction {
	switch {
	case b.rank() < a.rank():
		return Narrows
	case b.rank() > a.rank():
		return Widens
	}
	return ""
}

// model is the lexical reading of one contract's top-level file the edit core decides directions and sentences by:
// the entries this file spells, resolved, and the built-in deny_read list. It is not the compiler: a profile's
// entries, globs and tego's own state are not in it, which is why every edit is compiled too (EditRequest.Check).
type model struct {
	r                                           resolver
	write, denyRead, askRead, ask, denyWrite    []string
	execAllow, execDeny, netAllow, netAsk       []string
	builtin                                     []string
	hasExecAllow, hasNet, builtinOff, homeKnown bool
}

// newModel reads top. A ~/ entry with no home known is left out (it resolves to nothing).
func newModel(top *yaml.Node, r resolver) model {
	m := model{r: r, homeKnown: r.home != ""}
	res := func(key string) []string {
		var out []string
		for _, e := range list(top, key) {
			if strings.ContainsAny(e, "*?[") {
				continue // a glob is the compiler's to expand
			}
			if p := r.resolve(e); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	m.write, m.denyRead, m.askRead = res("fs.write"), res("fs.deny_read"), res("fs.ask_read")
	m.ask, m.denyWrite = res("fs.ask"), res("fs.deny_write")
	m.execAllow, m.execDeny = list(top, "exec.allow"), list(top, "exec.deny")
	m.netAllow, m.netAsk = list(top, "net.allow"), list(top, "net.ask")
	m.hasExecAllow, m.hasNet = present(top, "exec.allow"), present(top, "net")
	fs, _ := lookup(top, "fs")
	dr, _ := lookup(fs, "deny_read")
	m.builtinOff = dr != nil && dr.Kind == yaml.SequenceNode && len(dr.Content) == 0
	if m.homeKnown && !m.builtinOff {
		for _, rel := range agent.BuiltInDenyRead() {
			m.builtin = append(m.builtin, path.Join(r.home, rel))
		}
	}
	return m
}

// present reports whether the dotted key is there and not null: `net:` with nothing after it is no section.
func present(top *yaml.Node, key string) bool {
	sec, field, _ := strings.Cut(key, ".")
	n, _ := lookup(top, sec)
	if field != "" {
		n, _ = lookup(n, field)
	}
	return n != nil && n.ShortTag() != "!!null"
}

// nearest is the longest entry of es at or above p, "" when none.
func nearest(es []string, p string) string {
	best := ""
	for _, e := range es {
		if within(p, e) && len(e) > len(best) {
			best = e
		}
	}
	return best
}

// readAt is how the next run decides a read at p: the nearest read-deciding entry wins (SEMANTICS §2), a write entry
// reopening reads beneath a deny, an ask_read entry at or beneath a built-in protection replacing it (ADR 0057 D4).
func (m model) readAt(p string) access {
	type cand struct {
		at  string
		a   access
		pri int // the tie-break at one place: an explicit deny, then an ask, then a write, then a built-in
	}
	best := cand{pri: -1}
	env := ""
	if !m.builtinOff && agent.IsBuiltInEnvName(path.Base(p)) {
		env = p // the built-in .env scan's file, wherever it lies (conservative: the scan covers the project's)
	}
	for _, c := range []cand{
		{nearest(m.denyRead, p), refusedDeny, 3}, {nearest(m.askRead, p), asked, 2},
		{nearest(m.write, p), allowed, 1}, {nearest(m.builtin, p), refusedDeny, 0}, {env, refusedDeny, 0},
	} {
		if c.at == "" {
			continue
		}
		if best.pri < 0 || len(c.at) > len(best.at) || len(c.at) == len(best.at) && c.pri > best.pri {
			best = c
		}
	}
	if best.pri < 0 {
		return allowed // reads are allowed by default (SEMANTICS §1)
	}
	return best.a
}

// writeAt is how the next run decides a write at p: a deny_write nearer than every write entry refuses, a write entry
// allows (an ordinary grant takes precedence over an ask, ADR 0057 D3), an fs.ask scope asks, and anything else is
// outside the contract.
func (m model) writeAt(p string) access {
	w, d := nearest(m.write, p), nearest(m.denyWrite, p)
	switch {
	case d != "" && len(d) >= len(w):
		return refusedDeny
	case w != "":
		return allowed
	case nearest(m.ask, p) != "":
		return asked
	}
	return refusedNone
}

// execAt is how the next run decides running prog, an exec.allow entry as spelled.
func (m model) execAt(prog string) access {
	match := func(es []string) bool {
		for _, e := range es {
			if e == prog || path.Base(e) == path.Base(prog) && !strings.Contains(e, " ") {
				return true
			}
		}
		return false
	}
	switch {
	case match(m.execDeny):
		return refusedDeny
	case !m.hasExecAllow || match(m.execAllow):
		return allowed
	}
	return refusedNone
}

// netAt is how the next run decides connecting to dest, a net entry as spelled: an allow entry takes precedence over
// an ask entry (SEMANTICS §6), and anything else is refused under a net: section.
func (m model) netAt(dest string) access {
	has := func(es []string) bool {
		for _, e := range es {
			if sameDest(e, dest) {
				return true
			}
		}
		return false
	}
	switch {
	case !m.hasNet || has(m.netAllow):
		return allowed
	case has(m.netAsk):
		return asked
	}
	return refusedNone
}

// sameDest reports whether two net entries name one destination: a bare host:port and its tcp:// spelling are one.
func sameDest(a, b string) bool {
	return strings.TrimPrefix(a, "tcp://") == strings.TrimPrefix(b, "tcp://")
}

// at is the access the key's kind of action has at entry under m.
func (m model) at(key, entry string) access {
	switch key {
	case "fs.write", "fs.ask", "fs.deny_write":
		return m.writeAt(m.r.resolve(entry))
	case "fs.deny_read", "fs.ask_read":
		return m.readAt(m.r.resolve(entry))
	case "exec.allow":
		return m.execAt(entry)
	}
	return m.netAt(entry)
}

// sentence says a in words for the key's kind of action at what: "Asks you before it reads ~/.config/telemetry/".
func sentence(key string, a access, what string) string {
	switch key {
	case "fs.write", "fs.ask", "fs.deny_write":
		return [...]string{"Cannot change ", "Can never change ", "Asks you before it changes ", "May change "}[a] + what
	case "fs.deny_read", "fs.ask_read":
		return [...]string{"Can never read ", "Can never read ", "Asks you before it reads ", "May read "}[a] + what
	case "exec.allow":
		return [...]string{"Cannot run ", "Can never run ", "Cannot run ", "May run "}[a] + what
	}
	return [...]string{"Cannot connect to ", "Cannot connect to ", "Asks you before it connects to ", "May connect to "}[a] + what
}

// staticDirection is the direction of a change when the contract decides the same at its entry before and after
// (a redundant entry): a deny only refuses, a grant only lets through, and an ask entry added or removed where it
// changes nothing loosens nothing.
func staticDirection(c Change) Direction {
	switch c.Key {
	case "fs.deny_read", "fs.deny_write":
		if c.Remove {
			return Widens
		}
		return Narrows
	case "fs.write", "exec.allow", "net.allow":
		if c.Remove {
			return Narrows
		}
		return Widens
	}
	return Narrows
}
