// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Op is what one structured edit does to one list.
type Op string

// The edit operations.
const (
	// OpAdd adds Entry to the list at Key.
	OpAdd Op = "add"
	// OpRemove removes Entry, spelled exactly as the file spells it, from the list at Key.
	OpRemove Op = "remove"
	// OpNever turns the ask entry Key[Entry] into a refusal: fs.ask_read moves to fs.deny_read with the same
	// spelling, fs.ask goes (a write there is outside the contract again; under a write entry it becomes an
	// fs.deny_write), net.ask goes. It is "Never allow" on a line a person was asked about.
	OpNever Op = "never"
)

// Edit is one change a person asks for on the Change rules form: one entry added to or removed from one list.
type Edit struct {
	Op    Op
	Key   string
	Entry string
}

// editKeys are the lists an edit may change . Anything else (limits, the command, env, tier,
// extends) is a terminal edit: those are not entries a form can add one at a time and say plainly what changes.
var editKeys = []string{
	"fs.write", "fs.deny_read", "fs.ask_read", "fs.ask", "fs.deny_write", "exec.allow", "net.allow", "net.ask",
}

// EditKeys is the lists an edit may change, in the order a form offers them.
func EditKeys() []string { return slices.Clone(editKeys) }

// askKeys are the ask lists OpNever takes.
var askKeys = []string{"fs.ask_read", "fs.ask", "net.ask"}

// MaxEntry is the longest entry an edit adds, in bytes: an fs.ask or fs.ask_read scope's limit (SEMANTICS §6), and
// PATH_MAX.
const MaxEntry = 4096

// maxEdits bounds one request: the form makes one edit, and a "never" a few changes.
const maxEdits = 16

// EditRequest is one structured change to a contract file.
type EditRequest struct {
	// Contract is the contract file's text and ContractPath its absolute path.
	Contract     []byte
	ContractPath string
	// Cwd is the directory relative fs entries are read from, as compile reads them (the run's working directory);
	// empty is the contract's directory.
	Cwd string
	// Home is the invoking user's home, for ~/ entries and the built-in deny_read list; without it an fs.ask_read
	// entry added is Mixed, since the core cannot tell whether it relaxes a built-in protection.
	Home  string
	Edits []Edit
	// Date and Via are what an added line's comment says: "# added via dashboard, 2026-10-26". The package reads no
	// clock. Each is at most 64 printable characters.
	Date, Via string
	// Check is the compiler, and is required: a text it refuses is never returned.
	Check func(text []byte) error
	// Relaxes, when set, is the compiler's count of the built-in deny_read entries the text's fs.ask_read entries
	// relax (len of the compiled RuleTable.AskReadRelaxes). The compiler matches on resolved paths, so it sees a
	// relaxation through a symlink the lexical model cannot (an ask_read ./lnk/credentials with ./lnk -> ~/.aws);
	// a count that grows makes the request Widens or Mixed, never Narrows. Nil leaves the lexical model's word.
	Relaxes func(text []byte) (int, error)
}

// Sentence is one change in words, what the next run did before and does after: "Asks you before it reads
// ~/.config/telemetry/" then "Can never read ~/.config/telemetry/".
type Sentence struct {
	Before, After string
	// Direction is this change's own.
	Direction Direction
}

// EditResult is the new contract text and what it changes.
type EditResult struct {
	Text []byte
	// Changes are the list edits made, removals first; one Edit can be several (a "never", a deny_read that drops
	// the ask_read entries beneath it).
	Changes []Change
	// Diff is the line diff of the file, removed lines before added ones.
	Diff string
	// Sentences are the changes in words, in the order of Changes, one per distinct sentence: the two halves of a
	// "never" (the ask entry removed, the deny entry added) say the same and are shown once.
	Sentences []Sentence
	// Direction is the whole request's: Narrows only when no change loosens anything.
	Direction Direction
	// Why says what decided Direction, one clause per change.
	Why string
}

// ApplyEdits makes the edits on the contract text, keeping every comment and every byte it does not change where it
// can (yamledit's splice), compiles the result with req.Check, and says what changed in words with its direction.
// It refuses an entry the file does not spell (a profile's, a built-in), the first entry of an absent net: section or
// exec.allow list (that would refuse everything else), an entry with control characters or over MaxEntry, and a
// result that does not compile; ErrNothing when the contract already says so.
func ApplyEdits(req EditRequest) (*EditResult, error) {
	if !path.IsAbs(req.ContractPath) {
		return nil, fmt.Errorf("the contract path %q is not absolute", req.ContractPath)
	}
	if req.Check == nil {
		return nil, errors.New("no compiler: an edit is never returned uncompiled")
	}
	if len(req.Edits) == 0 || len(req.Edits) > maxEdits {
		return nil, refuse("an edit request holds 1 to %d edits, not %d", maxEdits, len(req.Edits))
	}
	if err := commentWord("date", req.Date, 64); err != nil {
		return nil, err
	}
	if err := commentWord("via", req.Via, 64); err != nil {
		return nil, err
	}
	_, top, err := parse(req.Contract)
	if err != nil {
		return nil, err
	}
	dir := path.Clean(req.Cwd)
	if req.Cwd == "" || !path.IsAbs(req.Cwd) {
		dir = path.Dir(req.ContractPath)
	}
	ep := &editPlanner{top: top, r: resolver{dir, req.Home}, comment: editComment(req.Via, req.Date)}
	for _, e := range req.Edits {
		if err := ep.plan(e); err != nil {
			return nil, err
		}
	}
	ep.order()
	changes := make([]Change, len(ep.changes))
	for i, pc := range ep.changes {
		changes[i] = pc.Change
	}
	text, err := edit(req.Contract, changes)
	if err != nil {
		return nil, refuse("the edit cannot be made on this file: %v", err)
	}
	if bytes.Equal(text, req.Contract) {
		return nil, nothing("the contract already says so")
	}
	_, after, err := parse(text)
	if err != nil {
		return nil, refuse("the edit made a file that does not parse, so nothing was written: %v", err)
	}
	for _, c := range changes {
		if hasString(after, c.Key, c.Entry) == c.Remove {
			return nil, refuse("the edit %s could not be made exactly, so nothing was written", c)
		}
	}
	if err := req.Check(text); err != nil {
		return nil, refuse("the new contract does not compile, so nothing was written: %v", err)
	}
	res := &EditResult{Text: text, Changes: changes, Diff: Diff(path.Base(req.ContractPath), req.Contract, text)}
	before, now := newModel(top, ep.r), newModel(after, ep.r)
	var why []string
	for _, pc := range ep.changes {
		s, w := describe(pc, before, now)
		if !slices.Contains(res.Sentences, s) {
			res.Sentences = append(res.Sentences, s)
		}
		res.Direction = res.Direction.join(s.Direction)
		why = append(why, w)
	}
	if req.Relaxes != nil {
		w, err := relaxesMore(req.Relaxes, req.Contract, text)
		if err != nil {
			return nil, err
		}
		if w != "" {
			res.Direction = res.Direction.join(Widens)
			why = append(why, w)
		}
	}
	res.Why = strings.Join(why, "; ")
	return res, nil
}

// relaxesMore is the why clause when the compiled after text relaxes more built-in deny_read entries than the
// before text (EditRequest.Relaxes); "" when it relaxes no more.
func relaxesMore(relaxes func([]byte) (int, error), before, after []byte) (string, error) {
	b, err := relaxes(before)
	if err != nil {
		b = 0 // a contract that did not compile relaxed nothing yet: every relaxation after counts as new
	}
	a, err := relaxes(after)
	if err != nil {
		return "", refuse("the new contract does not compile, so nothing was written: %v", err)
	}
	if a <= b {
		return "", nil
	}
	return fmt.Sprintf("widens: the compiled contract relaxes %d built-in deny_read entries into a question, %d "+
		"before (an fs.ask_read entry at or beneath a built-in protection, through a link or not)", a, b), nil
}

// editPlanner turns edits into list changes against one parsed file.
type editPlanner struct {
	top     *yaml.Node
	r       resolver
	comment string
	changes []plannedChange
}

// plannedChange is a list change and whether it is half of a move from an ask list into a refusal (OpNever, a
// deny_read that drops the ask_read entries beneath it): such a half narrows whatever the lexical model says of it
// alone (an ask_read entry removed reads as "May read" until its deny_read lands).
type plannedChange struct {
	Change
	moved bool
}

func (ep *editPlanner) push(c Change, moved bool) {
	for _, have := range ep.changes {
		if have.Remove == c.Remove && have.Key == c.Key && have.Entry == c.Entry {
			return
		}
	}
	ep.changes = append(ep.changes, plannedChange{c, moved})
}

// order puts every removal first, so an entry leaves its list before one that would contradict it arrives, and the
// sentences read old before new.
func (ep *editPlanner) order() {
	slices.SortStableFunc(ep.changes, func(a, b plannedChange) int {
		switch {
		case a.Remove == b.Remove:
			return 0
		case a.Remove:
			return -1
		}
		return 1
	})
}

func (ep *editPlanner) plan(e Edit) error {
	if !slices.Contains(editKeys, e.Key) {
		return refuse("%q is not a list the dashboard edits (%s)", e.Key, strings.Join(editKeys, ", "))
	}
	if err := checkEntry(e.Key, e.Entry); err != nil {
		return err
	}
	switch e.Op {
	case OpAdd:
		return ep.add(e.Key, e.Entry)
	case OpRemove:
		return ep.remove(e.Key, e.Entry)
	case OpNever:
		return ep.never(e.Key, e.Entry)
	}
	return fmt.Errorf("unknown edit operation %q", e.Op)
}

func (ep *editPlanner) add(key, entry string) error {
	switch {
	case strings.HasPrefix(key, "net.") && !present(ep.top, "net"):
		return refuse("this contract has no net: section, so the run's network is not restricted; a first %s entry "+
			"would refuse every other destination: write the net: section yourself", key)
	case key == "exec.allow" && !present(ep.top, "exec.allow"):
		return refuse("this contract has no exec.allow list, so every program may run; a first entry would refuse " +
			"every other program: write the exec.allow list yourself")
	}
	for _, have := range list(ep.top, key) {
		if have == entry || strings.HasPrefix(key, "fs.") && ep.r.resolve(have) != "" && ep.r.resolve(have) == ep.r.resolve(entry) {
			return nothing("%s already lists %s", key, have)
		}
	}
	if key == "fs.deny_read" {
		if s := ep.r.resolve(entry); s != "" && !strings.ContainsAny(entry, "*?[") {
			ep.dropUnder("fs.ask_read", s)
		}
	}
	ep.push(Change{Key: key, Entry: entry, Comment: ep.comment}, false)
	return nil
}

// dropUnder removes every entry of the ask list at key this file spells at or beneath s, as half of a move into a
// refusal: an ask entry at or beneath a declared deny_read is a contradiction compile refuses (SEMANTICS §6).
func (ep *editPlanner) dropUnder(key, s string) {
	for _, e := range list(ep.top, key) {
		if within(ep.r.resolve(e), s) {
			ep.push(Change{Remove: true, Key: key, Entry: e}, true)
		}
	}
}

func (ep *editPlanner) remove(key, entry string) error {
	if !slices.Contains(list(ep.top, key), entry) {
		return refuse("this file's %s does not list %q (a profile's entry, a built-in protection or another "+
			"spelling); only an entry the file spells is removed", key, entry)
	}
	if key == "exec.allow" {
		if own := ownCommand(ep.top); own != "" && path.Base(own) == path.Base(entry) {
			return refuse("%s is the run's own command, which runs whatever exec.allow says", entry)
		}
	}
	ep.push(Change{Remove: true, Key: key, Entry: entry}, false)
	return nil
}

func (ep *editPlanner) never(key, entry string) error {
	if !slices.Contains(askKeys, key) {
		return refuse("never takes an ask entry (fs.ask_read, fs.ask or net.ask), not %s", key)
	}
	if !slices.Contains(list(ep.top, key), entry) {
		return refuse("this file's %s does not list %q (a profile's entry or another spelling); tego never changes "+
			"an entry the file does not spell", key, entry)
	}
	switch key {
	case "fs.ask_read":
		s := ep.r.resolve(entry)
		if s == "" {
			return refuse("the entry %q names a path under the home, and no home was given to read it", entry)
		}
		ep.dropUnder("fs.ask_read", s)
		for _, have := range list(ep.top, "fs.deny_read") {
			if ep.r.resolve(have) == s {
				return nil
			}
		}
		ep.push(Change{Key: "fs.deny_read", Entry: entry, Comment: ep.comment}, true)
	case "fs.ask":
		ep.push(Change{Remove: true, Key: key, Entry: entry}, true)
		s := ep.r.resolve(entry)
		if s == "" {
			return refuse("the entry %q names a path under the home, and no home was given to read it", entry)
		}
		if nearest(newModel(ep.top, ep.r).write, s) != "" {
			// Beneath a write entry the scope never asked (ADR 0057 D3): the write grant decides, so never is a
			// deny_write at the scope.
			ep.push(Change{Key: "fs.deny_write", Entry: entry, Comment: ep.comment}, true)
		}
	case "net.ask":
		ep.push(Change{Remove: true, Key: key, Entry: entry}, true)
	}
	return nil
}

// describe is one change in words and its direction, from the lexical model of the file before and after.
func describe(pc plannedChange, before, now model) (Sentence, string) {
	c := pc.Change
	a, b := before.at(c.Key, c.Entry), now.at(c.Key, c.Entry)
	s := Sentence{Before: sentence(c.Key, a, c.Entry), After: sentence(c.Key, b, c.Entry)}
	switch {
	case pc.moved:
		s.Direction = Narrows
	default:
		s.Direction = compare(a, b)
		if s.Direction == "" {
			s.Direction = staticDirection(c)
		}
	}
	why := c.String() + " " + string(s.Direction)
	if c.Key == "fs.ask_read" && !c.Remove && !before.homeKnown && s.Direction == Narrows {
		s.Direction = Mixed
		why = c.String() + " mixed: no home was given, so whether it relaxes a built-in deny_read entry is unknown"
	}
	return s, why
}

// checkEntry refuses an entry no list takes: empty, over MaxEntry, not UTF-8, a control or line-separator
// character (which would break the line it is written on), a space at either end, or a space in a network entry.
func checkEntry(key, e string) error {
	switch {
	case e == "":
		return refuse("the %s entry is empty", key)
	case len(e) > MaxEntry:
		return refuse("the %s entry is %d bytes, over the %d an entry may be", key, len(e), MaxEntry)
	case !utf8.ValidString(e):
		return refuse("the %s entry is not UTF-8 text", key)
	case strings.TrimSpace(e) != e:
		return refuse("the %s entry %q starts or ends with a space", key, e)
	case strings.HasPrefix(key, "net.") && strings.ContainsAny(e, " \t"):
		return refuse("the %s entry %q holds a space; a destination is host:port, tcp://host:port or unix:<path>", key, e)
	}
	for _, r := range e {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 || r == 0xfeff {
			return refuse("the %s entry holds the control character %U", key, r)
		}
	}
	return nil
}

// commentWord refuses a date or via that would not sit on one comment line.
func commentWord(name, s string, maxLen int) error {
	if len(s) > maxLen {
		return refuse("the %s %q is over %d characters", name, s, maxLen)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return refuse("the %s holds the character %U, which a comment line cannot carry", name, r)
		}
	}
	return nil
}

// editComment is the comment an added entry carries: "# added via dashboard, 2026-10-26".
func editComment(via, date string) string {
	switch {
	case via != "" && date != "":
		return "# added via " + via + ", " + date
	case via != "":
		return "# added via " + via
	case date != "":
		return "# added " + date
	}
	return ""
}

// ownCommand is the contract's own program: the first word of command:, "" when it has none.
func ownCommand(top *yaml.Node) string {
	c, _ := lookup(top, "command")
	switch {
	case c == nil:
	case c.Kind == yaml.SequenceNode && len(c.Content) > 0:
		return c.Content[0].Value
	case c.Kind == yaml.ScalarNode:
		if f := strings.Fields(c.Value); len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

// hasString reports whether the list at the dotted key holds entry as a string (a quoted "null" is one, a bare
// null is not).
func hasString(top *yaml.Node, key, entry string) bool {
	sec, field, _ := strings.Cut(key, ".")
	m, _ := lookup(top, sec)
	s, _ := lookup(m, field)
	if s == nil || s.Kind != yaml.SequenceNode {
		return false
	}
	for _, n := range s.Content {
		if n.Kind == yaml.ScalarNode && n.Value == entry && n.ShortTag() == "!!str" {
			return true
		}
	}
	return false
}
