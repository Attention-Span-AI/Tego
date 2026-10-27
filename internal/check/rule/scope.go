// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"path"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// The scopes a rule from one event may name beyond the event's own file, program or destination: an ancestor
// folder of the file (Request.Level), the program's command (Request.Command: the program and its subcommand, as an
// exec command rule spells it, ADR 0048) and the destination's whole host (Request.HostOnly). Each is never broader
// than what the person picked: the entry written names exactly that scope, and a removal lifts no more than it.

// level is the folder level the request names: 0 the file, 1 its folder, n the folder n-1 levels above that.
func (r Request) level() int {
	if r.Level > 0 {
		return r.Level
	}
	if r.Folder {
		return 1
	}
	return 0
}

// Ancestors is the breadcrumb of the scopes a rule from a read or write of file may name: the file, its folder, and
// each parent folder up to the run's working directory (cwd) when file is inside it, else up to home when inside
// that; a file in neither offers its own folder only. Index i is Request.Level i. "/" is never offered.
func Ancestors(file, cwd, home string) []string {
	file = path.Clean(file)
	out := []string{file}
	d := path.Dir(file)
	if d == "/" {
		return out
	}
	out = append(out, d)
	bound := ""
	for _, b := range []string{cwd, home} {
		if b == "" || !path.IsAbs(b) {
			continue
		}
		b = path.Clean(b)
		if b != "/" && strings.HasPrefix(file, b+"/") {
			bound = b
			break
		}
	}
	if bound == "" {
		return out
	}
	for d != bound && strings.HasPrefix(d, bound+"/") {
		d = path.Dir(d)
		out = append(out, d)
	}
	return out
}

// underBound reports whether file lies under the run's working directory (cwd) or home: the bounds Ancestors climbs
// to. A file under neither sits in a system folder, whose folder no Allow may name (apply.go subject, CR-04).
func underBound(file, cwd, home string) bool {
	file = path.Clean(file)
	for _, b := range []string{cwd, home} {
		if b == "" || !path.IsAbs(b) {
			continue
		}
		if b = path.Clean(b); b != "/" && strings.HasPrefix(file, b+"/") {
			return true
		}
	}
	return false
}

// commandWord is a token an exec command entry can carry unquoted.
func commandWord(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if c != '-' && c != '_' && c != '.' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// Command is the exec command rule an exec of argv names (ADR 0048): the program's basename and its subcommand path
// ("git push" for `git -C . push origin`), read with the tool's grammar row; a tool with no row is named by its first
// argument when that is a plain word ("make test"), which the generic matcher reads anywhere in a later argv. It is
// "" when argv names no subcommand (a bare program, an option first, readings that disagree). Grammar says whether a
// row read it.
func Command(prog string, argv []string) (entry string, grammar bool) {
	base := path.Base(prog)
	if len(argv) < 2 || !commandWord(base) {
		return "", false
	}
	if row := rows.Builtin().Lookup(base); row != nil {
		rs := execmatch.NewNormalizer(row, nil).Normalize(argv[1:])
		var sub []string
		for i, r := range rs {
			if r.Unlocatable || r.Corrected || len(r.Path) == 0 {
				return "", true
			}
			if i == 0 {
				sub = r.Path
				continue
			}
			if strings.Join(r.Path, " ") != strings.Join(sub, " ") {
				return "", true
			}
		}
		for _, w := range sub {
			if !commandWord(w) {
				return "", true
			}
		}
		if len(sub) == 0 {
			return "", true
		}
		return base + " " + strings.Join(sub, " "), true
	}
	if !commandWord(argv[1]) {
		return "", false
	}
	return base + " " + argv[1], false
}

// hostOf is the host of a host:port destination, "" for a unix socket or a destination with no port.
func hostOf(dest string) string {
	if strings.HasPrefix(dest, "unix:") {
		return ""
	}
	i := strings.LastIndexByte(dest, ':')
	if i <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(dest[:i], "["), "]")
}

// HostOf is the host a destination names, for a page's "the whole host" scope; "" when it has none.
func HostOf(dest string) string { return hostOf(dest) }

// sameHost reports whether the net.allow entry e names host (any port, any scheme prefix).
func sameHost(e, host string) bool {
	e = strings.TrimPrefix(strings.TrimPrefix(e, "tcp://"), "udp://")
	return hostOf(e) == host
}

// CommandEntry is the command a rule from t may name: the exec's own (Command), or, for a run refused by an
// exec.deny command entry, that entry ("" when neither).
func CommandEntry(t Target) string {
	if c, _ := Command(t.Path, t.Argv); c != "" {
		return c
	}
	if k, e, ok := ruleEntry(t.Rule); ok && k == "exec.deny" && strings.Contains(e, " ") {
		return e
	}
	return ""
}

// EntryLevel is the Request.Level whose folder is the fs ask entry that decided t (fs.ask_read[E] or fs.ask[E]),
// read from cwd (the run's working directory, or the contract's) and home: the scope a page opens "Never allow" on,
// so a block moves E itself instead of adding a rule for one file beneath it. -1 when an ask entry did not decide t
// or E is not on the file's breadcrumb (Ancestors). A file entry is level 0.
func EntryLevel(t Target, cwd, home string) int {
	k, e, ok := ruleEntry(t.Rule)
	if !ok || k != "fs.ask_read" && k != "fs.ask" || t.Kind != KindRead && t.Kind != KindWrite {
		return -1
	}
	r := resolver{path.Clean(cwd), home}.resolve(e)
	for i, a := range Ancestors(t.Path, cwd, home) {
		if r != "" && a == r {
			return i
		}
	}
	return -1
}
