// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Request is one "make this a rule".
type Request struct {
	// Contract is the contract file's text and ContractPath its absolute path.
	Contract     []byte
	ContractPath string
	// Cwd is the run's working directory (run_start.cwd), which relative entries are read from, as compile reads
	// them; a new entry inside it is spelled relative to it ("./notes.txt"). Empty is the contract's directory.
	Cwd string
	// Home is the invoking user's home, for entries spelled ~/...; empty reads none of them as a match.
	Home   string
	Event  *record.Event
	Action Action
	// Folder makes a read or write rule name the event's directory instead of its file.
	Folder bool
	// Level names an ancestor folder of a read or written file instead (scope.go, Ancestors): 1 is its folder (as
	// Folder), n the folder n-1 levels above that, up to the run's working directory or home. 0 is Folder's choice.
	Level int
	// Command makes an exec rule name the program's command (program and subcommand, "git push") instead of the
	// whole program (scope.go, Command).
	Command bool
	// HostOnly makes a net rule name the destination's whole host (every port) instead of its host:port.
	HostOnly bool
	// Date is what the changed line's comment says ("2026-10-25"); the package reads no clock.
	Date string
	// Check is the compiler: nil skips it (a preview of options), otherwise a text it refuses is never returned.
	Check func(text []byte) error
}

// Result is the new contract and what it changes.
type Result struct {
	Text    []byte
	Changes []Change
	Target  Target
	// Summary is one line: "block reads of /p/secret.txt: fs.deny_read += ./secret.txt (run r-1 line #7)".
	Summary string
	// Effect is what the next run does differently, completing "The next run of <contract> will ...".
	Effect string
	Diff   string
	// Sentences are the changes in words, what the next run did before and does after, one per distinct sentence
	// (the two halves of an ask entry turned into a refusal say the same and are shown once), as ApplyEdits says
	// them: the dashboard's preview and saved state lead with these, not the diff .
	Sentences []Sentence
	// Direction is which way the rule moves what the next run may do: a block narrows, an allow widens, and an ask
	// narrows an action the run was allowed and widens one it was refused.
	Direction Direction
}

// ErrNothing is Apply's error when the contract already does what the action asks.
var ErrNothing = errors.New("nothing to change")

// ErrRefused is Apply's error when the action cannot be made without widening past the event's target, touching an
// entry the file does not spell, or writing a contract the compiler refuses.
var ErrRefused = errors.New("refused")

func nothing(f string, a ...any) error {
	return fmt.Errorf("%w: "+f, append([]any{ErrNothing}, a...)...)
}
func refuse(f string, a ...any) error {
	return fmt.Errorf("%w: "+f, append([]any{ErrRefused}, a...)...)
}

// Apply makes the rule: the changes the action needs, made to the text, compiled by req.Check.
func Apply(req Request) (*Result, error) {
	if req.Event == nil {
		return nil, errors.New("no event")
	}
	if !path.IsAbs(req.ContractPath) {
		return nil, fmt.Errorf("the contract path %q is not absolute", req.ContractPath)
	}
	t, err := TargetOf(req.Event)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(Actions(t.Kind), req.Action) {
		if t.Kind == KindExec && req.Action == Ask {
			return nil, refuse("a program cannot be asked about yet: exec.ask is reserved and refuses every match (ADR 0048 (5)); pick block or allow")
		}
		return nil, fmt.Errorf("unknown action %q", req.Action)
	}
	if req.level() > 0 && t.Kind != KindRead && t.Kind != KindWrite {
		return nil, refuse("a folder rule is made from a read or a write only")
	}
	if req.Command && t.Kind != KindExec {
		return nil, refuse("a command rule is made from a program run only")
	}
	if req.HostOnly && t.Kind != KindNet {
		return nil, refuse("a host rule is made from a connection only")
	}
	_, top, err := parse(req.Contract)
	if err != nil {
		return nil, err
	}
	dir := path.Clean(req.Cwd)
	if req.Cwd == "" || !path.IsAbs(req.Cwd) {
		dir = path.Dir(req.ContractPath)
	}
	p := &planner{req: req, t: t, top: top, dir: dir}
	p.comment = fmt.Sprintf("# from run %s line #%d, %s", req.Event.Run, req.Event.Seq, req.Date)
	if err := commentWord("comment", p.comment, 256); err != nil {
		return nil, err // a run id or date that would break the comment's line
	}
	effect, err := p.plan()
	if err != nil {
		return nil, err
	}
	text, err := edit(req.Contract, p.changes)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(text, req.Contract) {
		return nil, nothing("the contract already says so")
	}
	if req.Check != nil {
		if err := req.Check(text); err != nil {
			return nil, refuse("the new contract does not compile, so nothing was written: %v", err)
		}
	}
	parts := make([]string, len(p.changes))
	for i, c := range p.changes {
		parts[i] = c.String()
	}
	return &Result{
		Text: text, Changes: p.changes, Target: t, Effect: effect, Direction: actionDirection(req.Action, t.Refused),
		Summary:   fmt.Sprintf("%s: %s (run %s line #%d)", effect, strings.Join(parts, ", "), req.Event.Run, req.Event.Seq),
		Diff:      Diff(path.Base(req.ContractPath), req.Contract, text),
		Sentences: sentences(top, text, resolver{dir, req.Home}, p.changes),
	}, nil
}

// sentences is the changes in words from the lexical model of the file before (top) and after (text), one per
// distinct sentence; none when the new text does not parse (it does: edit has re-read it). Only the lists the
// lexical model reads (editKeys) are said; a change of another list (exec.deny, a command entry) has no sentence, and
// the caller says Effect instead.
func sentences(top *yaml.Node, text []byte, r resolver, changes []Change) []Sentence {
	_, after, err := parse(text)
	if err != nil {
		return nil
	}
	before, now := newModel(top, r), newModel(after, r)
	var out []Sentence
	for _, c := range changes {
		if !slices.Contains(editKeys, c.Key) {
			continue
		}
		s, _ := describe(plannedChange{Change: c}, before, now)
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

type planner struct {
	req     Request
	t       Target
	top     *yaml.Node
	dir     string
	comment string
	changes []Change
}

// add adds entry to the list at key, unless an entry there already names it (resolved, for an fs list).
func (p *planner) add(key, entry string) {
	for _, e := range list(p.top, key) {
		if e == entry || strings.HasPrefix(key, "fs.") && p.resolve(e) == p.resolve(entry) {
			return
		}
	}
	p.changes = append(p.changes, Change{Key: key, Entry: entry, Comment: p.comment})
}

func (p *planner) remove(key, entry string) {
	p.changes = append(p.changes, Change{Remove: true, Key: key, Entry: entry})
}

// resolve is where an fs entry points, cleaned: from the run's working directory, or the home for ~/.
func (p *planner) resolve(entry string) string { return resolver{p.dir, p.req.Home}.resolve(entry) }

// askedBy is the entry of the ask list at key that decided the event (its rule is key[entry]), whatever the
// person answered: the line was asked about, approved, denied or timed out.
func (p *planner) askedBy(key string) (string, bool) {
	k, e, ok := ruleEntry(p.t.Rule)
	if !ok || k != key {
		return "", false
	}
	return e, true
}

// dropUnder removes every entry of the list at key this file spells at or beneath s, and reports how many.
func (p *planner) dropUnder(key, s string) int {
	n := 0
	for _, e := range list(p.top, key) {
		if within(p.resolve(e), s) {
			p.remove(key, e)
			n++
		}
	}
	return n
}

// denyRead refuses reads at s with the deny_read entry spelled so. Every fs.ask_read entry this file spells at or
// beneath s goes first: an ask entry at or beneath a declared deny_read is a contradiction compile refuses
// (SEMANTICS §6), and one left nearer would keep asking where the person said never.
func (p *planner) denyRead(s, spelling string) {
	p.dropUnder("fs.ask_read", s)
	p.add("fs.deny_read", spelling)
}

// spelledHere refuses an ask entry the event names that this file does not spell (a profile's).
func (p *planner) spelledHere(key, e string) error {
	if !slices.Contains(list(p.top, key), e) {
		return refuse("%s was decided by %s, which this file does not spell (a profile's entry); tego rule never "+
			"changes it", p.t.What(), p.t.Rule)
	}
	return nil
}

// subject is the path the rule names: the event's file, or with Folder its directory, or with Level that ancestor
// (never past the run's working directory or home, never "/").
func (p *planner) subject() (string, error) {
	lv := p.req.level()
	if lv == 0 {
		return path.Clean(p.t.Path), nil
	}
	anc := Ancestors(p.t.Path, p.dir, p.req.Home)
	if p.req.Action == Allow && p.t.Kind == KindWrite && !underBound(p.t.Path, p.dir, p.req.Home) {
		// CR-04: outside the run's working directory and home, the folder of a file is a system folder (/dev/,
		// /etc/x/): granting all of it from one event (fs.write += /dev/ from a write to /dev/null) hands the agent
		// far more than the event showed. Block and Ask keep the folder: they only take away. An Allow of a read
		// grants nothing new: it only lifts an entry this file spells at exactly that folder (narrow), which the
		// person wrote.
		return "", refuse("the folder of %s is a system folder: name the file", p.t.Path)
	}
	if lv >= len(anc) {
		top := path.Dir(path.Clean(p.t.Path))
		if len(anc) > 1 {
			top = anc[len(anc)-1]
		}
		if lv == 1 {
			return "", refuse("the folder of %s is %s: too wide for a rule from one event; name the file", p.t.Path, top)
		}
		return "", refuse("level %d is above %s, the widest folder a rule from this event may name (the run's "+
			"working directory or home)", lv, top)
	}
	d := anc[lv]
	if p.req.Home != "" && d == path.Clean(p.req.Home) && p.req.Action == Allow {
		return "", refuse("the folder of %s is %s: too wide for a rule from one event; name the file", p.t.Path, d)
	}
	return d, nil
}

// spell is how a new entry names s: relative to the run's working directory when inside it, else absolute; a folder
// ends in "/".
func (p *planner) spell(s string) string {
	out := s
	if s == p.dir {
		out = "."
	} else if strings.HasPrefix(s, p.dir+"/") && p.dir != "/" {
		out = "./" + s[len(p.dir)+1:]
	}
	if p.req.level() > 0 {
		out = strings.TrimSuffix(out, "/") + "/"
	}
	return out
}

// spelled is the entry of the list at key that resolves to s, "" when none does.
func (p *planner) spelled(key, s string) string {
	for _, e := range list(p.top, key) {
		if p.resolve(e) == s {
			return e
		}
	}
	return ""
}

// decidedBy is the event's rule when it names an entry of the list at key that this file spells; "" when the rule
// is another list's, and an error when it is that list's but no entry of this file (built in, a profile's).
func (p *planner) decidedBy(keys ...string) (key, entry string, err error) {
	k, e, ok := ruleEntry(p.t.Rule)
	if !ok || !slices.Contains(keys, k) {
		return "", "", nil
	}
	if !slices.Contains(list(p.top, k), e) {
		return k, e, refuse("%s was decided by %s, which this file does not spell (a built-in protection, a profile's "+
			"entry or tego's own); tego rule never changes it", p.t.What(), p.t.Rule)
	}
	return k, e, nil
}

// narrow says whether removing the fs entry e (decided the event) lifts no more than the rule's subject s.
func (p *planner) narrow(e, s string) error {
	if r := p.resolve(e); r != s {
		return refuse("the entry %q covers %s, more than %s; removing it would widen past this event", e, r, s)
	}
	return nil
}

func (p *planner) plan() (string, error) {
	switch p.t.Kind {
	case KindRead:
		return p.planRead()
	case KindWrite:
		return p.planWrite()
	case KindExec:
		return p.planExec()
	}
	return p.planNet()
}

func (p *planner) planRead() (string, error) {
	s, err := p.subject()
	if err != nil {
		return "", err
	}
	what := s
	if p.req.level() > 0 {
		what = "files under " + s + "/"
	}
	askE, asked := p.askedBy("fs.ask_read")
	switch p.req.Action {
	case Block:
		if asked {
			return p.neverRead(s, what, askE)
		}
		if p.t.Refused {
			return "", nothing("the read of %s was already refused (%s)", p.t.Path, p.t.Rule)
		}
		p.denyRead(s, p.spell(s))
		return "refuse reads of " + what, nil
	case Ask:
		if asked {
			return "", nothing("the read of %s is already asked about (%s)", p.t.Path, p.t.Rule)
		}
		if p.t.Refused {
			k, e, err := p.decidedBy("fs.deny_read", "fs.ask_read")
			if err != nil {
				return "", err
			}
			if k == "fs.ask_read" {
				return "", nothing("the read of %s is already asked about (%s)", p.t.Path, p.t.Rule)
			}
			if k == "" {
				return "", refuse("the read of %s was refused by %s, which tego rule cannot turn into a question", p.t.Path, p.t.Rule)
			}
			if err := p.narrow(e, s); err != nil {
				return "", err
			}
			p.remove(k, e)
		}
		p.add("fs.ask_read", p.spell(s))
		return "ask you before it reads " + what + " (tier landlock only)", nil
	case Allow:
	}
	if !p.t.Refused && !asked {
		return "", nothing("the read of %s was already allowed", p.t.Path)
	}
	k, e, err := p.decidedBy("fs.deny_read", "fs.ask_read")
	if err != nil {
		return "", err
	}
	if k == "" {
		return "", refuse("the read of %s was refused by %s, which tego rule does not lift", p.t.Path, p.t.Rule)
	}
	if err := p.narrow(e, s); err != nil {
		return "", err
	}
	p.remove(k, e)
	if err := p.readAllowedAfter(s, k, e); err != nil {
		return "", err
	}
	return "allow reads of " + what, nil
}

// readAllowedAfter refuses an allow whose removal of k[e] would not let the read of s through: an fs.ask_read entry
// at or beneath a built-in protection replaces it (ADR 0057 D4), so removing it brings the refusal back, and a
// wider deny_read, ask_read or built-in entry still decides a read whose own entry goes. The effect says "allow
// reads", so the next run must allow them. The lexical model (direction.go) reads the file as changed; with no home
// it holds no built-in list, and compile is what remains.
func (p *planner) readAllowedAfter(s, k, e string) error {
	text, err := edit(p.req.Contract, p.changes)
	if err != nil {
		return err
	}
	_, after, err := parse(text)
	if err != nil {
		return err
	}
	switch newModel(after, resolver{p.dir, p.req.Home}).readAt(s) {
	case allowed:
		return nil
	case asked:
		return refuse("removing %s[%s] would still ask before reading %s (another fs.ask_read entry covers it), not "+
			"allow it", k, e, s)
	case refusedNone, refusedDeny:
	}
	if k == "fs.ask_read" {
		return refuse("%s[%s] relaxes a refusal (a built-in protection, ADR 0057 D4, or a wider deny_read) into a "+
			"question; removing it would refuse reading %s, not allow it", k, e, s)
	}
	return refuse("removing %s[%s] would still refuse reading %s (a built-in protection or a wider deny_read "+
		"covers it), not allow it", k, e, s)
}

// neverRead is a block of a read an fs.ask_read entry E asked about: "never" instead of "ask". At E's own scope E
// moves from ask_read to deny_read with the same spelling (and any ask_read entry beneath it goes, denyRead); a
// narrower scope adds a deny_read for that path alone, nearer than E, and E keeps asking about the rest; a wider one
// refuses the wider path, the ask entries beneath it dropped.
func (p *planner) neverRead(s, what, e string) (string, error) {
	r := p.resolve(e)
	if r == "" {
		return "", refuse("the entry %q names a path under the home, and no home was given to read it", e)
	}
	// The event still names the ask entry that decided it, but this file may since have made it a refusal (this
	// very change, confirmed a moment ago, then the preview reopened): a deny_read at or above s already does what
	// Never allow asks, but only when it is the entry that decides reads of s. The nearest entry wins (SEMANTICS
	// §2): an fs.write or fs.ask_read entry strictly beneath the deny_read and at or above s reopens s, and calling
	// that "already never allowed" would be a false assurance that also hides the narrowing below. Without this
	// check spelledHere would wrongly call the moved entry a profile's.
	for _, d := range list(p.top, "fs.deny_read") {
		if rd := p.resolve(d); rd != "" && within(s, rd) && !p.reopenedBetween(rd, s) {
			return "", nothing("reads of %s are already never allowed: this file refuses them (fs.deny_read[%s])", what, d)
		}
	}
	switch {
	case s == r:
		if err := p.spelledHere("fs.ask_read", e); err != nil {
			return "", err
		}
		p.denyRead(s, e)
		return "refuse reads of " + what + " without asking you first", nil
	case within(s, r):
		p.denyRead(s, p.spell(s))
		return "refuse reads of " + what + " without asking you first (the rest of " + e + " still asks)", nil
	}
	p.denyRead(s, p.spell(s))
	return "refuse reads of " + what + " without asking you first", nil
}

// reopenedBetween reports whether an fs.write or fs.ask_read entry of this file lies strictly beneath the refused
// path rd and at or above s: such an entry is nearer to s than the deny_read at rd, so it, not rd, decides reads of
// s (SEMANTICS §2; cgroup/policy.go applies the same nearest-wins rule).
func (p *planner) reopenedBetween(rd, s string) bool {
	for _, k := range []string{"fs.write", "fs.ask_read"} {
		for _, e := range list(p.top, k) {
			if r := p.resolve(e); r != "" && r != rd && within(r, rd) && within(s, r) {
				return true
			}
		}
	}
	return false
}

// neverWrite is a block of a write an fs.ask scope E asked about. At E's scope or wider the fs.ask entries at or
// beneath the scope go, so a write there is outside the contract again (none lies beneath a write entry: an ask
// there never asks, ADR 0057 D3, so a write grant covering the scope is answered with a deny_write instead); a
// narrower scope adds a deny_write, which is kept from every approval inside the ask scope (SEMANTICS §2, ADR 0071).
func (p *planner) neverWrite(s, what, e string) (string, error) {
	r := p.resolve(e)
	if r == "" {
		return "", refuse("the entry %q names a path under the home, and no home was given to read it", e)
	}
	for _, w := range list(p.top, "fs.write") {
		if within(s, p.resolve(w)) {
			p.add("fs.deny_write", p.spell(s))
			return "refuse writes to " + what, nil
		}
	}
	if within(s, r) && s != r {
		p.add("fs.deny_write", p.spell(s))
		return "refuse writes to " + what + " without asking you first (the rest of " + e + " still asks)", nil
	}
	if s == r {
		if err := p.spelledHere("fs.ask", e); err != nil {
			return "", err
		}
	}
	if p.dropUnder("fs.ask", s) == 0 {
		return "", refuse("no fs.ask entry of this file lies at or beneath %s; %s was decided by %s", s, p.t.Path, p.t.Rule)
	}
	return "refuse writes to " + what + " without asking you first", nil
}

func (p *planner) planWrite() (string, error) {
	s, err := p.subject()
	if err != nil {
		return "", err
	}
	what := s
	if p.req.level() > 0 {
		what = "files under " + s + "/"
	}
	askE, asked := p.askedBy("fs.ask")
	switch p.req.Action {
	case Block:
		if asked {
			return p.neverWrite(s, what, askE)
		}
		if p.t.Refused {
			return "", nothing("the write to %s was already refused (%s)", p.t.Path, p.t.Rule)
		}
		p.add("fs.deny_write", p.spell(s))
		return "refuse writes to " + what, nil
	case Ask:
		k, e, err := p.decidedBy("fs.write", "fs.deny_write", "fs.ask")
		if err != nil {
			return "", err
		}
		switch k {
		case "fs.ask":
			return "", nothing("the write to %s is already asked about (%s)", p.t.Path, p.t.Rule)
		case "fs.write", "fs.deny_write":
			if r := p.resolve(e); r != s {
				return "", refuse("the entry %s[%s] covers %s and decides before an fs.ask scope beneath it; "+
					"tego rule cannot narrow it to %s", k, e, r, s)
			}
			p.remove(k, e)
		}
		p.add("fs.ask", p.spell(s))
		return "ask you before it writes to " + what, nil
	case Allow:
	}
	if !p.t.Refused && !asked {
		return "", nothing("the write to %s was already allowed", p.t.Path)
	}
	k, e, err := p.decidedBy("fs.deny_write")
	if err != nil {
		return "", err
	}
	if k != "" {
		if err := p.narrow(e, s); err != nil {
			return "", err
		}
		p.remove(k, e)
		return "allow writes to " + what, nil
	}
	if e := p.spelled("fs.ask", s); e != "" {
		p.remove("fs.ask", e)
	}
	p.add("fs.write", p.spell(s))
	return "allow writes to " + what, nil
}

// command is the contract's own program: the first word of command:.
func (p *planner) command() string { return ownCommand(p.top) }

func (p *planner) planExec() (string, error) {
	prog := p.t.Path
	base := path.Base(prog)
	own := p.command()
	isOwn := own != "" && (own == prog || path.Base(own) == base)
	allowKey := has(p.top, "exec.allow")
	denyList := !allowKey && (has(p.top, "exec.deny") || has(p.top, "exec.ask"))
	if p.req.Command {
		return p.planCommand(prog, isOwn, allowKey || denyList)
	}
	if p.req.Action == Block {
		if p.t.Refused {
			return "", nothing("running %s was already refused (%s)", prog, p.t.Rule)
		}
		if isOwn {
			return "", refuse("%s is the run's own command; blocking it would stop every run of this contract", prog)
		}
		k, e, ok := ruleEntry(p.t.Rule)
		if ok && k == "exec.allow" && slices.Contains(list(p.top, k), e) && (e == prog || e == base) {
			p.remove(k, e)
			return "refuse to run " + prog, nil
		}
		if !allowKey && !denyList {
			return "", refuse("this contract's exec: section has neither allow nor deny, and adding exec.deny would let " +
				"every other program run (deny-list mode); add an exec.allow list first")
		}
		p.add("exec.deny", base)
		return "refuse to run " + base, nil
	}
	if !p.t.Refused {
		return "", nothing("running %s was already allowed", prog)
	}
	k, e, ok := ruleEntry(p.t.Rule)
	if ok && k == "exec.deny" {
		if !slices.Contains(list(p.top, k), e) {
			return "", refuse("running %s was refused by %s, which this file does not spell; tego rule never changes it", prog, p.t.Rule)
		}
		if e != base {
			return "", refuse("the entry exec.deny[%s] is a command rule; tego rule removes only a whole-program entry", e)
		}
		p.remove(k, e)
		return "allow " + base + " to run", nil
	}
	if !allowKey {
		return "", refuse("this contract has no exec.allow list; running %s was refused by %s, which tego rule does not lift", prog, p.t.Rule)
	}
	p.add("exec.allow", prog)
	return "allow " + prog + " to run", nil
}

func (p *planner) planNet() (string, error) {
	d := p.t.Dest
	if p.req.HostOnly {
		return p.planHost(d)
	}
	if e, asked := p.askedBy("net.ask"); asked {
		if err := p.spelledHere("net.ask", e); err != nil {
			return "", err
		}
		switch p.req.Action {
		case Block:
			p.remove("net.ask", e)
			return "refuse connections to " + e + " without asking you first", nil
		case Ask:
			return "", nothing("connecting to %s is already asked about (%s)", d, p.t.Rule)
		case Allow:
		}
		p.remove("net.ask", e)
		p.add("net.allow", e) // the entry's own spelling: the ledger target may be the address alone
		return "allow connections to " + e, nil
	}
	if !has(p.top, "net") {
		if p.req.Action == Allow {
			return "", nothing("this contract has no net: section, so the network is not restricted")
		}
		return "", refuse("this contract has no net: section, so the run's network is not restricted; adding one would " +
			"refuse every other destination: write the net: section yourself")
	}
	switch p.req.Action {
	case Block, Ask:
		k, e, ok := ruleEntry(p.t.Rule)
		if !p.t.Refused && ok && k == "net.allow" {
			if !slices.Contains(list(p.top, k), e) {
				return "", refuse("%s was allowed by %s, which this file does not spell; tego rule never changes it", d, p.t.Rule)
			}
			if e != d {
				return "", refuse("the entry net.allow[%s] covers more than %s; removing it would block more than this event", e, d)
			}
			p.remove(k, e)
		} else if !p.t.Refused && p.req.Action == Block {
			return "", refuse("%s was allowed by %s, which tego rule does not narrow", d, p.t.Rule)
		}
		if p.req.Action == Block {
			if p.t.Refused {
				return "", nothing("connecting to %s was already refused (%s)", d, p.t.Rule)
			}
			return "refuse connections to " + d, nil
		}
		if slices.Contains(list(p.top, "net.ask"), d) {
			return "", nothing("connecting to %s is already asked about", d)
		}
		p.add("net.ask", d)
		return "ask you before it connects to " + d, nil
	case Allow:
	}
	if !p.t.Refused {
		return "", nothing("connecting to %s was already allowed", d)
	}
	if slices.Contains(list(p.top, "net.ask"), d) {
		p.remove("net.ask", d)
	}
	p.add("net.allow", d)
	return "allow connections to " + d, nil
}
