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
	// NodeVersion is attested from this interpreter image, never its name or argv.
	NodeVersion string
	Path, Arg   string
	// EmptyArg says the line has an argument and it is empty (agent.ShebangArgv): the interpreter gets an empty element.
	EmptyArg bool
	// Image is the walked interpreter's basename (the walk's link); "" when unknown.
	Image string
	ID    ID
	HasID bool
	// Links is the walked interpreter's link count, read as Facts.Links is; 0 when unknown.
	Links uint64
}

// hasArg reports whether binfmt_script gives the interpreter an argument element for this stage.
func (st Stage) hasArg() bool { return st.Arg != "" || st.EmptyArg }

// Facts are what an exec's decision reads, copied by the caller (ADR 0048 (2)). The matcher reads nothing else.
type Facts struct {
	// NodeVersion is the version of an exact inventoried executable build,
	// attested by the I/O caller. Empty selects the compatibility row.
	NodeVersion string
	// Requested is the requested pathname's basename, "" for an image named by descriptor alone; Image is the
	// resolved image's basename (the walk's link); Argv0 is argv[0] (its basename is read).
	Requested, Image, Argv0 string
	// Path is the requested pathname as passed, the script argument binfmt_script gives a #! interpreter; "" when
	// unknown.
	Path string
	// ID is the image's identity when HasID.
	ID    ID
	HasID bool
	// Links is the image's link count (st_nlink), read by the same fstat of the walk's own descriptor that gave ID; 0
	// when unknown (compile --test and the gate stat no file). More than one marks a multicall image (multicall.go).
	Links uint64
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
	// ViaMulticall is a multicall binary's applet: in argv[1], or (for deny and ask entries, on a multicall image) the
	// one uutils picks by a name that ends with it (multicall.go).
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
	// scanArgv0 is the actual argv[0] for interpreter pre-scanners (including #!).
	scanArgv0 string
	// interpFinal caches two-reader settlement for an interpreter with no command rules.
	interpFinal bool
	// NodeVersion follows the image that supplied this invocation.
	NodeVersion     string
	Tool            string
	Row             *Row
	Via             Via
	Tokens          []string
	Readings        []Reading
	releaseReadings []Reading
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
	b := builder{ix: ix, open: !f.ArgvComplete, argv0: f.Argv0, scanArgv0: f.Argv0, nodeVersion: f.NodeVersion}
	if b.argv0 == "" && len(f.Argv) > 0 {
		b.argv0 = f.Argv[0]
		b.scanArgv0 = f.Argv[0]
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
			ix.addInvokedAs(&b, row, ViaArgv0, argv0, argv1)
			ix.addStrippedApplet(&b, row, argv0, argv1)
		}
	}
	f.eachStage(argv1, func(st Stage, toks []string) {
		b.nodeVersion = st.NodeVersion
		b.scanArgv0 = st.Path
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
				ix.addInvokedAs(&b, row, ViaShebang, name, toks)
				ix.addStrippedApplet(&b, row, name, toks)
			}
		}
	})
	// The program a directly-invoked loader runs is read as a direct image is, with the argv the loader gives it: no
	// execve of its own follows (ADR 0048 (2)).
	if f.Loaded != nil {
		for _, lf := range f.loadedReadings() {
			b.nodeVersion = lf.NodeVersion
			for _, inv := range ix.Interpretations(&lf) {
				if inv.Via == ViaOverflow {
					// The program's own reading overflowed: it is this exec's, and fails it closed too. Re-added as an
					// invocation it would be dropped (it names no tool), and the exec read as if fully resolved.
					b.overflow = true
					continue
				}
				b.nodeVersion = inv.NodeVersion
				b.scanArgv0 = inv.scanArgv0
				b.add(inv.Tool, inv.Row, ViaLoader, inv.Tokens)
			}
		}
	}
	return ix.resolve(&b)
}

// resolve finishes a builder's interpretations: multicall and interpreter dispatch over them, the overflow sentinel,
// and the readings of every ruled tool's invocation.
func (ix *Index) resolve(b *builder) []Invocation {
	// Multicall and interpreter dispatch, over what is found so far and what they add, to a bounded depth. A
	// dispatcher the bounds stop this from fully resolving (a multicall binary that re-dispatches to itself, such
	// as busybox's own `busybox` applet, nested past maxDispatch; or a fan-out that reaches maxInterpretations) could
	// still reach a ruled tool, so the loop fails closed: it leaves a ViaOverflow sentinel that Decide refuses under
	// command-unresolved, rather than dropping the interpretation and reading the exec as unmatched (2026-10-06; it
	// mirrors NormalizeOpen's Unlocatable, and R7's bound on argv).
	depth := map[int]int{}
	overflow := false
	for i := 0; i < len(b.out); i++ {
		ix.fillReadings(&b.out[i])
		inv := b.out[i]
		b.nodeVersion = inv.NodeVersion
		b.scanArgv0 = inv.scanArgv0
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
			ix.dispatchInterp(b, inv)
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
		ix.fillReadings(inv)
		if inv.Row != nil && inv.Row.Interp != nil && !ix.Ruled(inv.Tool) {
			inv.interpFinal = ix.interpSettled(inv)
			// Public invocation readings belong to ruled tools. Unruled interpreter
			// readings have finished dispatch; retain only their settlement result.
			inv.Readings, inv.releaseReadings = nil, nil
		}
	}
	return b.out
}

// fillReadings computes both readers once, before either dispatch or a decision.
func (ix *Index) fillReadings(inv *Invocation) {
	if inv.Row == nil || !(ix.Ruled(inv.Tool) || inv.Row.Interp != nil) {
		return
	}
	nz := ix.normalizer(inv.Row)
	if inv.Readings == nil {
		inv.Readings = nz.NormalizeOpen(inv.Tokens, inv.Open)
	}
	if inv.releaseReadings == nil {
		inv.releaseReadings = newReleaseNormalizer(inv.Row, nz.cand).NormalizeOpen(inv.Tokens, inv.Open)
	}
}

// eachStage calls fn for each stage of a script's #! chain with the tokens binfmt_script gives its interpreter after
// argv[0]: the line's argument when it has one, the chain of scripts it runs, then the exec's argv[1:]. A direct
// image has no stage.
func (f *Facts) eachStage(argv1 []string, fn func(st Stage, toks []string)) {
	if f.Form != FormScript || len(f.Interp) == 0 {
		return
	}
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
		fn(st, toks)
		next := []string{st.Path}
		if st.hasArg() {
			next = append(next, st.Arg)
		}
		chain = append(next, chain...)
	}
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
		origin := ViaArgv0
		if via == ViaShebang {
			origin = ViaShebang
		}
		ix.addInvokedAs(b, row, origin, argv0, argv1)
		ix.addStrippedApplet(b, row, argv0, argv1)
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
func (ix *Index) addInvokedAs(b *builder, row *Row, via Via, argv0 string, argv1 []string) {
	if row == nil {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(row.Argv0Subs)) {
		if strings.Contains(argv0, name) {
			b.add(row.Tool, row, via, prepend(row.Argv0Subs[name], argv1))
		}
	}
}

// addStrippedApplet reads a proven dispatcher's argv[0] applet. Its tokens
// belong to dispatch, never to the exec's direct runtime exact-grant target.
func (ix *Index) addStrippedApplet(b *builder, row *Row, argv0 string, argv1 []string) {
	if row == nil || !row.Multicall || row.Argv0Strip == "" {
		return
	}
	if applet, ok := strings.CutPrefix(argv0, row.Argv0Strip); ok && applet != "" {
		b.add2(ix, applet, ViaMulticall, argv1)
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

// runsCode reports whether a reading runs code given on the command line in place of a module or script (R1): one of
// the row's Code options holds its code, a value it took (python's -c, node's -e) or, for a flag, the operand it makes
// code (sh's -c), and no CodeUnless option stands with it. A Code option that took no value gives none: node's -p
// before an option, which node reads as a flag and then runs the script after its options (ArgNextWord), or -e where
// a staged prefix ends. Under node's -i the code gives none either: node runs the script. On a row with CodeUnless
// options, a reading that holds an option the row does not list gives none: that option could be another spelling of
// one of them, or one a later version adds, so the reading is read for its script too (the fail-closed direction:
// --build_snapshot was such a spelling until the node row read Underscores).
func (spec *InterpSpec) runsCode(r *Reading) bool {
	if len(spec.CodeUnless) > 0 && r.Unknown {
		return false
	}
	code := false
	for _, h := range r.Hits {
		switch {
		case h.Opt == nil:
		case slices.Contains(spec.CodeUnless, h.Opt.Name) && !h.Neg:
			return false
		case slices.Contains(spec.Code, h.Opt.Name) && (h.HasValue || h.Opt.Arg == ArgNone && !h.Neg):
			code = true
		}
	}
	return code
}

// dispatchInterp adds the invocations an interpreter runs: python -m <module>'s module, or the first operand that is a
// script, through the row's module and entry-script tables, and each module a Preload or Loaders option names (node's
// -r, --import and --loader), whether the reading runs code or a script. Code given with -c or -e is opaque
// (InterpSpec.runsCode).
func (ix *Index) dispatchInterp(b *builder, inv Invocation) {
	spec := inv.Row.Interp
	for _, readings := range [2][]Reading{inv.Readings, inv.releaseReadings} {
		if len(readings) == 0 {
			b.overflow = true
			continue
		}
		for _, r := range readings {
			if r.Unlocatable {
				// Past MaxReadings no reading names the script, and any of them could be the one a deny entry names: the
				// exec fails closed rather than read as if it dispatched to nothing (ADR 0048 R4).
				b.overflow = true
				continue
			}
			code, module, after := spec.runsCode(&r), "", -1
			for _, h := range r.Hits {
				if h.Opt != nil && spec.Module != "" && h.Opt.Name == spec.Module && h.HasValue {
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
				for _, tool := range spec.scriptTools(inv.Tokens[r.Dispatch]) {
					b.add2(ix, tool, ViaInterpreter, tail(inv.Tokens, r.Dispatch+1))
				}
			}
			// A preloaded module runs with the arguments past the first operand, a loader's with none. Where a loader is
			// given, the loaders' thread runs the preloaded modules too, with no arguments (node runs -r's there, probed;
			// --import's it does not, so that reading only refuses more).
			var args []string
			if r.Dispatch >= 0 {
				args = tail(inv.Tokens, r.Dispatch+1)
			}
			loader := slices.ContainsFunc(r.Hits, func(h Hit) bool {
				return h.Opt != nil && h.HasValue && !h.Neg && slices.Contains(spec.Loaders, h.Opt.Name)
			})
			for _, h := range r.Hits {
				switch {
				case h.Opt == nil || !h.HasValue || h.Neg:
				case slices.Contains(spec.Preload, h.Opt.Name):
					for _, tool := range spec.moduleTools(h.Value) {
						b.add2(ix, tool, ViaInterpreter, args)
						if loader {
							b.add2(ix, tool, ViaInterpreter, nil)
						}
					}
				case slices.Contains(spec.Loaders, h.Opt.Name):
					for _, tool := range spec.moduleTools(h.Value) {
						b.add2(ix, tool, ViaInterpreter, nil)
					}
				}
			}
		}
	}
}

// scriptTools are the tools a script an interpreter runs may be: for the basename of its path, cleaned lexically as
// node's path.resolve cleans it (`node ./deploy.js/x/.. publish` runs deploy.js, probed on 20.19.4), and for that
// basename with each of the row's Extensions, the entry-script table's tool, else the basename itself. Cleaning
// changes the name only where the path ends in `.` or `..`, which python and the shells run as a directory or not at
// all, so reading it cleaned only refuses more there.
func (spec *InterpSpec) scriptTools(script string) []string {
	if script == "" {
		return nil
	}
	name := path.Base(path.Clean(script))
	names := []string{name}
	for _, ext := range spec.Extensions {
		names = append(names, name+ext)
	}
	for i, n := range names {
		if t, ok := spec.Scripts[n]; ok {
			names[i] = t
		}
	}
	return names
}

// moduleTools are the tools a module a Preload or Loaders option names may be: scriptTools of the value as written
// and, when it starts with `\-`, without the backslash, which is how node reads that value given separately
// (src/node_options-inl.h: "Treat \- as escaping an -"); attached, node reads it as written.
func (spec *InterpSpec) moduleTools(value string) []string {
	tools := spec.scriptTools(value)
	if v, ok := strings.CutPrefix(value, `\`); ok && strings.HasPrefix(v, "-") {
		tools = append(tools, spec.scriptTools(v)...)
	}
	return tools
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
	argv0       string
	scanArgv0   string
	nodeVersion string
}

// add appends an invocation unless one of the same tool, row and tokens is already there. Past maxInterpretations a new
// one is not kept, and the builder overflows (fails closed, ADR 0048 (2)): any interpretation could be the one that
// reaches a ruled tool, and one dropped in silence read the exec as if it had none (an exec whose reading needs more
// than the bound was decided on the first 32 and could be allowed unmatched).
func (b *builder) add(tool string, row *Row, via Via, toks []string) {
	if row != nil && row.Interp != nil && len(row.Interp.Versions) > 0 && !slices.Contains(row.Interp.Versions, b.nodeVersion) {
		row = row.Interp.Fallback
		if row == nil {
			b.overflow = true
			return
		}
	}
	// Inspect every raw observation before deduplicating. A different argv[0]
	// can trigger a Node pre-scanner even when tool, row and tokens coincide.
	if row != nil && row.Interp != nil && row.Interp.ArgvRewrite != nil && row.Interp.ArgvRewrite(prepend(b.scanArgv0, toks)) {
		b.overflow = true
		return
	}
	if tool == "" {
		return
	}
	for _, o := range b.out {
		if o.Tool == tool && o.Row == row && sameTokens(o.Tokens, toks) {
			return
		}
	}
	if len(b.out) >= maxInterpretations {
		b.overflow = true
		return
	}
	inv := Invocation{scanArgv0: b.scanArgv0, NodeVersion: b.nodeVersion, Tool: tool, Row: row, Via: via, Tokens: toks, Open: b.open}
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
