// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"maps"
	"path"
	"slices"
	"strings"
)

// Form is how the kernel runs an image.
type Form uint8

// Forms.
const (
	// FormDirect is an image run as itself (an ELF).
	FormDirect Form = iota
	// FormScript is a #! script, with its interpreter chain in Facts.Interp.
	FormScript
	// FormUnknown is an image whose header could not be read (an execute-only file at tier 1).
	FormUnknown
)

// String is the form's name.
func (f Form) String() string {
	switch f {
	case FormDirect:
		return "direct"
	case FormScript:
		return "script"
	case FormUnknown:
		return "unknown"
	}
	return "unknown"
}

// ID is a file's identity, (dev, ino).
type ID struct{ Dev, Ino uint64 }

// Stage is one #! interpreter of a script's chain: its path as the #! line spells it, its optional argument, and
// the file its walk reached, read as Facts reads a direct image: the basename of the walked image's link, and its
// identity when HasID. An interpreter reached through a symlink is read by all three.
type Stage struct {
	Path, Arg string
	// EmptyArg says the line has an argument and it is empty (agent.ShebangArgv): the interpreter gets an empty element.
	EmptyArg bool
	// Image is the walked interpreter's basename (the walk's link); "" when unknown.
	Image string
	ID    ID
	HasID bool
}

// hasArg reports whether binfmt_script gives the interpreter an argument element for this stage.
func (st Stage) hasArg() bool { return st.Arg != "" || st.EmptyArg }

// Facts are what an exec's decision reads, copied by the caller (ADR 0048 (2)). The matcher reads nothing else.
type Facts struct {
	// Requested is the requested pathname's basename, "" for an image named by descriptor alone; Image is the
	// resolved image's basename (the walk's link); Argv0 is argv[0] (its basename is read).
	Requested, Image, Argv0 string
	// Path is the requested pathname as passed, the script argument binfmt_script gives a #! interpreter; "" when
	// unknown.
	Path string
	// ID is the image's identity when HasID.
	ID    ID
	HasID bool
	// Form is how the kernel runs the image; Interp is a script's #! chain.
	Form   Form
	Interp []Stage
	// Argv is the copied vector, or the prefix of it the decision needed when ArgvComplete is false.
	Argv         []string
	ArgvComplete bool
	// Loaded is the program a directly-invoked dynamic loader runs in-process; nil for any other exec. Its argv is
	// part of Argv, so ArgvComplete covers it too.
	Loaded *Loaded
}

// Via names the interpretation that read an invocation, as the record's command_via spells it.
type Via uint8

// Interpretations (ADR 0048 (2)).
const (
	// ViaName is the requested pathname's basename.
	ViaName Via = iota + 1
	// ViaImage is the resolved image's basename.
	ViaImage
	// ViaArgv0 is argv[0]'s basename.
	ViaArgv0
	// ViaIdentity is the image's (dev, ino), when compile resolved a ruled command to a file of one link.
	ViaIdentity
	// ViaDashed is a <tool>-<sub> name.
	ViaDashed
	// ViaMulticall is a multicall binary's applet in argv[1].
	ViaMulticall
	// ViaInterpreter is an interpreter's module or script operand.
	ViaInterpreter
	// ViaShebang is the argv binfmt_script gives a #! interpreter.
	ViaShebang
	// ViaClosure marks an invocation admitted by an allowed entry's helper closure.
	ViaClosure
)

// String is the record's spelling.
func (v Via) String() string {
	switch v {
	case ViaName:
		return "name"
	case ViaImage:
		return "image"
	case ViaArgv0:
		return "argv0"
	case ViaIdentity:
		return "identity"
	case ViaDashed:
		return "dashed"
	case ViaMulticall:
		return "multicall"
	case ViaInterpreter:
		return "interpreter"
	case ViaShebang:
		return "shebang"
	case ViaClosure:
		return "closure"
	case ViaLoader:
		return "loader"
	case ViaOverflow:
		return "overflow"
	}
	return "unknown"
}

// Invocation is one interpretation of an exec: the tool it is, the tokens it reads, and (for a tool with a row and
// a rule) every reading the row makes of them.
type Invocation struct {
	Tool     string
	Row      *Row
	Via      Via
	Tokens   []string
	Readings []Reading
	// Open says Tokens end where a staged read stopped, not where the vector ends (Facts.ArgvComplete false).
	Open bool
	// Argv0 is the exec's argv[0] as it was given, whole, on an interpretation of the exec's own image (by its name,
	// image, argv[0] or identity); "" on every other. Only a runtime grant's exact pattern reads it (ExactPattern).
	Argv0 string
}

// maxInterpretations bounds one exec's interpretations; maxDispatch bounds interpreter dispatch depth.
const (
	maxInterpretations = 32
	maxDispatch        = 4
)

// base is a name's basename, "" for "".
func base(s string) string {
	if s == "" {
		return ""
	}
	return path.Base(s)
}

// Interpretations is the set of invocations an exec's facts yield (ADR 0048 (2)): by each name, by identity, dashed
// forms, multicall dispatch, interpreter dispatch and the #! chain. Readings are filled for the tools the index
// holds rules for. A caller-chosen argv[0] can add an interpretation, never remove one: the only reading it changes
// is a row whose tool dispatches on argv[0] itself (git run as git-<cmd> runs <cmd>).
func (ix *Index) Interpretations(f *Facts) []Invocation {
	var argv1 []string
	argv0 := base(f.Argv0)
	if len(f.Argv) > 0 {
		argv1 = f.Argv[1:]
		if argv0 == "" {
			argv0 = base(f.Argv[0])
		}
	}
	b := builder{ix: ix, open: !f.ArgvComplete, argv0: f.Argv0}
	if b.argv0 == "" && len(f.Argv) > 0 {
		b.argv0 = f.Argv[0]
	}
	names := [...]struct {
		name string
		via  Via
	}{{base(f.Requested), ViaName}, {base(f.Image), ViaImage}, {argv0, ViaArgv0}}
	for _, n := range names {
		ix.addName(&b, n.name, n.via, argv0, argv1)
	}
	login := undashed(argv0)
	ix.addName(&b, login, ViaArgv0, login, argv1)
	if f.HasID {
		if tool, ok := ix.ids[f.ID]; ok {
			row := ix.rows.Lookup(tool)
			toks := argv1
			if row != nil {
				toks = ix.dispatchArgv0(row, argv0, argv1)
			}
			b.add(tool, row, ViaIdentity, toks)
			ix.addInvokedAs(&b, row, argv0, argv1)
		}
	}
	if f.Form == FormScript && len(f.Interp) > 0 {
		script := f.Path
		if script == "" {
			script = f.Requested
		}
		chain := []string{script}
		for _, st := range f.Interp {
			toks := make([]string, 0, len(chain)+1+len(argv1))
			if st.hasArg() {
				toks = append(toks, st.Arg)
			}
			toks = append(toks, chain...)
			toks = append(toks, argv1...)
			// binfmt_script runs the interpreter with argv[0] the #! line's path: read it by that name, by the
			// walked image's name and by its identity, as a direct image is read.
			name := base(st.Path)
			ix.addName(&b, name, ViaShebang, name, toks)
			ix.addName(&b, st.Image, ViaShebang, name, toks)
			if st.HasID {
				if tool, ok := ix.ids[st.ID]; ok {
					row := ix.rows.Lookup(tool)
					stoks := toks
					if row != nil {
						stoks = ix.dispatchArgv0(row, name, toks)
					}
					b.add(tool, row, ViaShebang, stoks)
					ix.addInvokedAs(&b, row, name, toks)
				}
			}
			next := []string{st.Path}
			if st.hasArg() {
				next = append(next, st.Arg)
			}
			chain = append(next, chain...)
		}
	}
	// The program a directly-invoked loader runs is read as a direct image is, with the argv the loader gives it: no
	// execve of its own follows (ADR 0048 (2)).
	if f.Loaded != nil {
		lf := f.loadedFacts()
		for _, inv := range ix.Interpretations(&lf) {
			if inv.Via == ViaOverflow {
				// The program's own reading overflowed: it is this exec's, and fails it closed too. Re-added as an
				// invocation it would be dropped (it names no tool), and the exec read as if fully resolved.
				b.overflow = true
				continue
			}
			b.add(inv.Tool, inv.Row, ViaLoader, inv.Tokens)
		}
	}
	// Multicall and interpreter dispatch, over what is found so far and what they add, to a bounded depth. A
	// dispatcher the bounds stop this from fully resolving (a multicall binary that re-dispatches to itself, such
	// as busybox's own `busybox` applet, nested past maxDispatch; or a fan-out that reaches maxInterpretations) could
	// still reach a ruled tool, so the loop fails closed: it leaves a ViaOverflow sentinel that Decide refuses under
	// command-unresolved, rather than dropping the interpretation and reading the exec as unmatched (2026-10-06; it
	// mirrors NormalizeOpen's Unlocatable, and R7's bound on argv).
	depth := map[int]int{}
	overflow := false
	for i := 0; i < len(b.out); i++ {
		inv := b.out[i]
		if inv.Row == nil || !(inv.Row.Multicall || inv.Row.Interp != nil) {
			continue
		}
		if depth[i] >= maxDispatch || len(b.out) >= maxInterpretations {
			if ix.wouldDispatch(inv) {
				overflow = true
			}
			continue
		}
		n := len(b.out)
		switch {
		case inv.Row.Multicall:
			if applet, toks, ok := multicallApplet(inv.Row, inv.Tokens); ok {
				if r := ix.rows.Lookup(applet); r != nil {
					b.add(r.Tool, r, ViaMulticall, toks)
				} else if r := ix.rows.dispatcherNamed(applet); r != nil {
					b.add(r.Tool, r, ViaMulticall, toks)
				} else {
					b.add(applet, nil, ViaMulticall, toks)
				}
			}
		case inv.Row.Interp != nil:
			ix.dispatchInterp(&b, inv)
		}
		for j := n; j < len(b.out); j++ {
			depth[j] = depth[i] + 1
		}
	}
	if overflow || b.overflow {
		// One sentinel past the bound: Decide refuses any exec that holds it, command-unresolved, via overflow.
		b.out = append(b.out, Invocation{Via: ViaOverflow})
	}
	for i := range b.out {
		inv := &b.out[i]
		if inv.Row != nil && ix.Ruled(inv.Tool) {
			inv.Readings = ix.normalizer(inv.Row).NormalizeOpen(inv.Tokens, inv.Open)
		}
	}
	return b.out
}

// addName adds the invocations one name yields (ADR 0048 (2)): the tool or row it names, read under argv0, a row
// that runs a subcommand under this name, a multicall dispatcher's argv[0] applet, and a dashed <tool>-<sub> form.
func (ix *Index) addName(b *builder, name string, via Via, argv0 string, argv1 []string) {
	if name == "" {
		return
	}
	row := ix.rows.Lookup(name)
	if row != nil {
		b.add(row.Tool, row, via, ix.dispatchArgv0(row, argv0, argv1))
	} else {
		b.add(name, nil, via, argv1)
		if r := ix.rows.dispatcherNamed(name); r != nil && name == argv0 {
			b.add(r.Tool, r, via, argv1)
		}
	}
	if r, sub, ok := ix.argv0Sub(name); ok {
		b.add(r.Tool, r, via, prepend(sub, argv1))
	}
	if via != ViaArgv0 {
		ix.addInvokedAs(b, row, argv0, argv1)
	}
	if row != nil && row.Multicall && row.Argv0Strip != "" && via != ViaArgv0 {
		// The dispatcher is the file that runs: it reads its applet from argv[0] after dropping the prefix.
		if applet, ok := strings.CutPrefix(argv0, row.Argv0Strip); ok && applet != "" {
			b.add2(ix, applet, ViaArgv0, argv1)
		}
	}
	if i := strings.IndexByte(name, '-'); i > 0 && i < len(name)-1 {
		if r := ix.rows.Lookup(name[:i]); r != nil && r.Dashed {
			sub, toks := name[i+1:], argv1
			if r.DashedRepeat && len(toks) > 0 && toks[0] == sub {
				toks = toks[1:]
			}
			b.add(r.Tool, r, ViaDashed, prepend(sub, toks))
		}
	}
}

// undashed is argv[0]'s basename without the leading '-' a login shell's name carries, "" when it has none or nothing
// is left. busybox drops it before it looks the applet up (appletlib.c, probed), so every exec reads this name too. It
// can only add a reading, which is the direction argv[0] may move a decision.
func undashed(argv0 string) string {
	name, _ := strings.CutPrefix(argv0, "-")
	if name == argv0 {
		return ""
	}
	return name
}

// addInvokedAs adds the subcommand a row runs when the file that runs is the row's and argv[0] contains one of the
// row's Argv0Subs names (Row.Argv0Subs). The caller holds that the file is the row's, nil when it has none: a program
// called asphalt is not halt, and systemctl called asphalt is.
func (ix *Index) addInvokedAs(b *builder, row *Row, argv0 string, argv1 []string) {
	if row == nil {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(row.Argv0Subs)) {
		if strings.Contains(argv0, name) {
			b.add(row.Tool, row, ViaArgv0, prepend(row.Argv0Subs[name], argv1))
		}
	}
}

// dispatchArgv0 is the tokens a row reads under argv[0]: a row that dispatches on argv[0] (git) runs <sub> with
// argv[1:] when argv[0] is <tool>-<sub>, whatever file it is.
func (ix *Index) dispatchArgv0(row *Row, argv0 string, argv1 []string) []string {
	if row.Argv0Dispatch {
		if sub, ok := strings.CutPrefix(argv0, row.Tool+"-"); ok && sub != "" {
			return prepend(sub, argv1)
		}
	}
	return argv1
}

// argv0Sub finds a row that runs a subcommand when called by this name (systemctl as reboot).
func (ix *Index) argv0Sub(name string) (*Row, string, bool) {
	for _, r := range ix.rows.All() {
		if sub, ok := r.Argv0Subs[name]; ok {
			return r, sub, true
		}
	}
	return nil, "", false
}

// dispatchInterp adds the invocation an interpreter runs: python -m <module>'s module, or the first operand that is a
// script, through the row's module and entry-script tables. Code given with -c or -e is opaque.
func (ix *Index) dispatchInterp(b *builder, inv Invocation) {
	spec := inv.Row.Interp
	for _, r := range ix.normalizer(inv.Row).NormalizeOpen(inv.Tokens, inv.Open) {
		if r.Unlocatable {
			// Past MaxReadings no reading names the script, and any of them could be the one a deny entry names: the
			// exec fails closed rather than read as if it dispatched to nothing (ADR 0048 R4).
			b.overflow = true
			continue
		}
		code, module, after := false, "", -1
		for _, h := range r.Hits {
			if h.Opt == nil {
				continue
			}
			for _, c := range spec.Code {
				if h.Opt.Name == c {
					code = true
				}
			}
			if spec.Module != "" && h.Opt.Name == spec.Module && h.HasValue {
				module, after = h.Value, r.DispatchAfter
			}
		}
		switch {
		case code:
		case module != "":
			top, _, _ := strings.Cut(module, ".")
			tool := top
			if t, ok := spec.Modules[top]; ok {
				tool = t
			}
			b.add2(ix, tool, ViaInterpreter, tail(inv.Tokens, after))
		case r.Dispatch >= 0:
			script := base(inv.Tokens[r.Dispatch])
			tool := script
			if t, ok := spec.Scripts[script]; ok {
				tool = t
			}
			b.add2(ix, tool, ViaInterpreter, tail(inv.Tokens, r.Dispatch+1))
		}
	}
}

// wouldDispatch reports whether a dispatcher invocation, left unresolved by the depth or interpretation bounds, would
// still dispatch to another command: a multicall binary with a resolvable applet, or an
// interpreter whose operands name a module or script. Only then does the bound fail closed, so a dispatcher that
// runs no further command (a bare `busybox`, `sh -c <code>`) is not over-refused.
func (ix *Index) wouldDispatch(inv Invocation) bool {
	switch {
	case inv.Row == nil:
		return false
	case inv.Row.Multicall:
		_, _, ok := multicallApplet(inv.Row, inv.Tokens)
		return ok
	case inv.Row.Interp != nil:
		var scratch builder
		ix.dispatchInterp(&scratch, inv)
		return len(scratch.out) > 0 || scratch.overflow
	}
	return false
}

// multicallApplet is the applet a multicall dispatcher runs and the tokens it reads: the first token's basename when
// it is not an option, or the applet the row's ProgOption names (GNU coreutils' --coreutils-prog=PROG, and its
// -shebang form, whose next token is the script and becomes the applet's argv[0]).
func multicallApplet(row *Row, toks []string) (applet string, rest []string, ok bool) {
	if len(toks) == 0 || toks[0] == "" {
		return "", nil, false
	}
	t := toks[0]
	if t[0] != '-' {
		return base(t), toks[1:], true
	}
	if row.ProgOption == "" {
		return "", nil, false
	}
	if p, found := strings.CutPrefix(t, "--"+row.ProgOption+"="); found {
		return base(p), toks[1:], p != ""
	}
	if p, found := strings.CutPrefix(t, "--"+row.ProgOption+"-shebang="); found {
		return base(p), tail(toks, 2), p != ""
	}
	return "", nil, false
}

// tail is toks[i:], empty when i is out of range.
func tail(toks []string, i int) []string {
	if i < 0 || i > len(toks) {
		return nil
	}
	return toks[i:]
}

// prepend returns [s] + toks in a new slice.
func prepend(s string, toks []string) []string {
	out := make([]string, 0, len(toks)+1)
	out = append(out, s)
	return append(out, toks...)
}

// builder collects distinct invocations; open marks every one of an argv prefix (each one's tokens end where argv
// does). overflow records that a distinct invocation was dropped at maxInterpretations, or that a loaded program's
// own reading overflowed: Interpretations then ends with the ViaOverflow sentinel.
type builder struct {
	ix       *Index
	out      []Invocation
	open     bool
	overflow bool
	// argv0 is the exec's whole argv[0], kept on the interpretations of its own image (Invocation.Argv0).
	argv0 string
}

// add appends an invocation unless one of the same tool and tokens is already there. Past maxInterpretations a new
// one is not kept, and the builder overflows (fails closed, ADR 0048 (2)): any interpretation could be the one that
// reaches a ruled tool, and one dropped in silence read the exec as if it had none (an exec whose reading needs more
// than the bound was decided on the first 32 and could be allowed unmatched).
func (b *builder) add(tool string, row *Row, via Via, toks []string) {
	if tool == "" {
		return
	}
	for _, o := range b.out {
		if o.Tool == tool && sameTokens(o.Tokens, toks) {
			return
		}
	}
	if len(b.out) >= maxInterpretations {
		b.overflow = true
		return
	}
	inv := Invocation{Tool: tool, Row: row, Via: via, Tokens: toks, Open: b.open}
	if via.direct() {
		inv.Argv0 = b.argv0
	}
	b.out = append(b.out, inv)
}

// add2 adds an invocation of a tool named by an interpreter's module or script: its row's tool when a row has the name.
func (b *builder) add2(ix *Index, name string, via Via, toks []string) {
	if r := ix.rows.Lookup(name); r != nil {
		b.add(r.Tool, r, via, toks)
		return
	}
	b.add(name, nil, via, toks)
}

// sameTokens reports whether two token lists are equal.
func sameTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
