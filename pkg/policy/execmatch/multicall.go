// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"slices"
	"sort"
	"strings"
)

// The applet a multicall image runs by its program name (ADR 0048 (2) 4, amended 2026-11-11).
//
// A multicall binary is one file under many names, and it picks what it does from a name. Interpretations already
// reads every exec by its exact names and by busybox's and toybox's argv[0] forms. Upstream uutils picks more widely
// (src/bin/coreutils.rs and src/common/validation.rs, main a4b65e12 and release 0.12.0, read, not run):
//
//   - the program path is AT_EXECFN, the pathname as passed to execve; or argv[0] when the two basenames are equal
//     (0.12.0), when AT_EXECFN starts with /proc/ or /dev/fd/, or when uutils can open AT_EXECFN and it starts with
//     #!; and argv[0] always on musl. The program name is that path's file stem (the name without its last
//     extension);
//   - the applet is the longest utility name the stem ends with (xrm, farm and uu-rm run rm), unless the stem ends with
//     utils;
//   - else a stem ending with utils or box runs the applet argv[1] names, with argv[2:];
//   - else, in main only, the name a symlink at the program path points to (one readlink, read the same way).
//
// The matcher cannot know which build, libc or patch a file is, so on a multicall image it reads the requested
// pathname, the walked image's name and argv[0] (for a #! interpreter: the requested pathname, the #! path and the
// interpreter's walked name). These readings serve deny and ask entries only (Index.Decide): they never admit an exec
// and never make a constrained tool's invocation unlisted, so the allow side's own answer is unchanged; a deny entry
// they meet refuses an exec an allow entry admits, as deny entries do over every reading. A multicall image is a file
// of more than one link (Facts.Links) whose walked name a uutils build links its file under (linkName), or one named
// as a dispatcher row that lists Applets (coreutils). busybox and toybox take their applet from argv[0]'s exact
// basename and a busybox or toybox prefix, which addName already reads on every exec, so a file named busybox or
// toybox is not read this way unless it has more than one link.

// initMulticall finds the row whose Applets the readings use and the names of every tool a deny or ask entry names: the
// tool and its row's names. Without either, nothing is read.
func (ix *Index) initMulticall() {
	for _, r := range ix.rows.All() {
		if len(r.Applets) > 0 {
			ix.mc = r
			break
		}
	}
	if ix.mc == nil {
		return
	}
	ix.mcApplets = make(map[string]bool, len(ix.mc.Applets))
	for _, a := range ix.mc.Applets {
		ix.mcApplets[a] = true
		ix.mcLongest = max(ix.mcLongest, len(a))
	}
	seen := map[string]bool{}
	for tool, tr := range ix.tools {
		if len(tr.deny)+len(tr.ask) == 0 {
			continue
		}
		names := []string{tool}
		if r := ix.rows.Lookup(tool); r != nil && r.Tool == tool {
			names = append(names, r.Names...)
		}
		for _, n := range names {
			if n != "" && !seen[n] {
				seen[n] = true
				ix.mcNames = append(ix.mcNames, n)
			}
		}
	}
	sort.Strings(ix.mcNames)
}

// multicallOn reports whether the index reads multicall applets: a row lists them and some deny or ask entry exists.
func (ix *Index) multicallOn() bool { return ix != nil && ix.mc != nil && len(ix.mcNames) > 0 }

// multicallImage reports whether a walked file is read for its multicall applets: more than one link and a name a
// uutils build links its file under (linkName), or a name that is a dispatcher row listing Applets. image is the walk's
// name, or the requested name when the walk's is unknown.
func (ix *Index) multicallImage(links uint64, image string) bool {
	if ix.mc == nil {
		return false
	}
	if links > 1 && ix.linkName(image) {
		return true
	}
	r := ix.rows.Lookup(image)
	return r != nil && r.Multicall && len(r.Applets) > 0
}

// linkName reports whether a uutils build could link its file under this walked name: its stem ends with a listed
// applet (ls, xrm, uu-rm, sha3-256sum), it dispatches on argv[1] (coreutils, busybox), or it is one of the row's
// LinkNames ([, relpath). fs.protected_hardlinks keeps an agent from adding a link of its own to a root-owned file, so
// on a uutils host every name of that file is one of these; a hard-linked program of another name (unzip and zipinfo,
// perl and perl5.40.1) is not read. A file the agent owns, linked under any name, is a copy (R2).
func (ix *Index) linkName(image string) bool {
	stem := programStem(image)
	if stem == "" {
		return false
	}
	return ix.longestApplet(stem) > 0 || ix.argv1Dispatch(stem) || slices.Contains(ix.mc.LinkNames, stem)
}

// longestApplet is the length of the longest listed applet the stem ends with, 0 for none: its suffixes no longer
// than the longest listed name, longest first.
func (ix *Index) longestApplet(stem string) int {
	for i := max(0, len(stem)-ix.mcLongest); i < len(stem); i++ {
		if ix.mcApplets[stem[i:]] {
			return len(stem) - i
		}
	}
	return 0
}

// programStem is the program name uutils reads from a path: Rust's Path::file_name (the last component, after
// dropping empty and "." components; none for ".." or no component), then file_stem (the name before its last '.',
// unless the name starts with its only '.'). "" for none.
func programStem(p string) string {
	name := ""
	for end := len(p); end > 0; {
		start := strings.LastIndexByte(p[:end], '/') + 1
		if c := p[start:end]; c != "" && c != "." {
			name = c
			break
		}
		end = start - 1
	}
	if name == "" || name == ".." {
		return ""
	}
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return name
	}
	return name[:i]
}

// appletsOf calls fn with each deny- or ask-ruled name the stem runs as a suffix applet: a name it ends with that no
// longer listed applet it ends with outranks. A stem ending with NoAppletEnding has none.
func (ix *Index) appletsOf(stem string, fn func(name string)) {
	if stem == "" || ix.mc.NoAppletEnding != "" && strings.HasSuffix(stem, ix.mc.NoAppletEnding) {
		return
	}
	longest := ix.longestApplet(stem)
	for _, n := range ix.mcNames {
		if len(n) >= longest && strings.HasSuffix(stem, n) {
			fn(n)
		}
	}
}

// argv1Dispatch reports whether a stem runs the applet argv[1] names.
func (ix *Index) argv1Dispatch(stem string) bool {
	for _, e := range ix.mc.Argv1Endings {
		if stem != "" && strings.HasSuffix(stem, e) {
			return true
		}
	}
	return false
}

// addApplets adds the invocations a multicall image runs under any of names, with toks its argv[1:]: each suffix
// applet with toks, and, for a stem that dispatches on argv[1], the dispatcher row itself with toks, read as
// `coreutils <toks>` is. resolve dispatches that to the applet toks[0] names (and again for an applet that is itself
// a dispatcher); on an argv prefix that ends before argv[1] it has no tokens, so dispatchSettled keeps the decision
// open and the staged read goes on to argv[1].
func (ix *Index) addApplets(b *builder, toks []string, names ...string) {
	for _, n := range names {
		stem := programStem(n)
		ix.appletsOf(stem, func(name string) { b.add2(ix, name, ViaMulticall, toks) })
		if ix.argv1Dispatch(stem) {
			b.add(ix.mc.Tool, ix.mc, ViaMulticall, toks)
		}
	}
}

// appletsGuarded reports, from names alone, whether a multicall image could run a deny- or ask-ruled tool under any of
// them: a suffix applet, or a stem that dispatches on argv[1] (which the staged read then reaches).
func (ix *Index) appletsGuarded(names ...string) bool {
	for _, n := range names {
		stem := programStem(n)
		found := false
		ix.appletsOf(stem, func(string) { found = true })
		if found || ix.argv1Dispatch(stem) {
			return true
		}
	}
	return false
}

// requestedPath is the requested pathname as passed, or its basename when only that is known.
func (f *Facts) requestedPath() string {
	if f.Path != "" {
		return f.Path
	}
	return f.Requested
}

// imageName is a walked file's name for multicallImage: the walk's, else the name it was reached by.
func imageName(image, reached string) string {
	if image != "" {
		return image
	}
	return base(reached)
}

// argv0Of is argv[0] as the facts give it.
func (f *Facts) argv0Of() string {
	if f.Argv0 == "" && len(f.Argv) > 0 {
		return f.Argv[0]
	}
	return f.Argv0
}

// multicallGuarded is Guarded's multicall half: a multicall image (the exec's own, a #! interpreter, a loader's
// program) whose names could run a deny- or ask-ruled tool.
func (ix *Index) multicallGuarded(f *Facts) bool {
	if !ix.multicallOn() {
		return false
	}
	if ix.multicallImage(f.Links, imageName(f.Image, f.requestedPath())) && ix.appletsGuarded(f.requestedPath(), f.Image, f.argv0Of()) {
		return true
	}
	if f.Form == FormScript {
		for _, st := range f.Interp {
			if ix.multicallImage(st.Links, imageName(st.Image, st.Path)) && ix.appletsGuarded(f.requestedPath(), st.Path, st.Image) {
				return true
			}
		}
	}
	if f.Loaded != nil {
		lf := f.loadedFacts()
		return ix.multicallGuarded(&lf)
	}
	return false
}

// multicallInterpretations are the invocations a multicall image runs by its names that Interpretations does not read
// (the file comment): the exec's own image by its requested pathname, its walked name and argv[0]; each #! interpreter
// that is one by the exec's requested pathname, its #! path and its walked name (uutils reads argv[0], the #! path,
// when it can open AT_EXECFN and read #!, and AT_EXECFN, the script's own pathname, when it cannot: an execute-only
// script); and a loader's program by its operand, walked name and argv[0]. nil when the index reads none. Index.Decide holds them to
// deny and ask entries only.
func (ix *Index) multicallInterpretations(f *Facts, have []Invocation) []Invocation {
	if !ix.multicallOn() {
		return nil
	}
	b := builder{ix: ix, open: !f.ArgvComplete, scanArgv0: f.argv0Of(), nodeVersion: f.NodeVersion}
	var argv1 []string
	if len(f.Argv) > 0 {
		argv1 = f.Argv[1:]
	}
	if ix.multicallImage(f.Links, imageName(f.Image, f.requestedPath())) {
		ix.addApplets(&b, argv1, f.requestedPath(), f.Image, f.argv0Of())
	}
	f.eachStage(argv1, func(st Stage, toks []string) {
		if ix.multicallImage(st.Links, imageName(st.Image, st.Path)) {
			b.nodeVersion, b.scanArgv0 = st.NodeVersion, st.Path
			ix.addApplets(&b, toks, f.requestedPath(), st.Path, st.Image)
		}
	})
	if f.Loaded != nil {
		lf := f.loadedFacts()
		for _, inv := range ix.multicallInterpretations(&lf, nil) {
			if inv.Via == ViaOverflow {
				b.overflow = true
				continue
			}
			b.nodeVersion, b.scanArgv0 = inv.NodeVersion, inv.scanArgv0
			b.add(inv.Tool, inv.Row, ViaMulticall, inv.Tokens)
		}
	}
	// An invocation Interpretations already holds (rm read by its own name) was met by the deny and ask entries there,
	// and so was all it dispatches to: it is not read again.
	b.out = slices.DeleteFunc(b.out, func(inv Invocation) bool {
		return slices.ContainsFunc(have, func(h Invocation) bool {
			return h.Tool == inv.Tool && h.Row == inv.Row && sameTokens(h.Tokens, inv.Tokens)
		})
	})
	if len(b.out) == 0 && !b.overflow {
		return nil
	}
	return ix.resolve(&b)
}

// denyRuled reports whether a deny or ask entry names the tool.
func (ix *Index) denyRuled(tool string) bool {
	tr := ix.tools[tool]
	return tr != nil && len(tr.deny)+len(tr.ask) > 0
}

// denySettled is settled for the multicall invocations, which only deny and ask entries read: dispatch is settled,
// and no deny- or ask-ruled invocation could still match with more argv (a generic tool's always could; a row's could
// while a reading has not located its path or is pending, as settled reads Reading.Pending, or an entry whose path it
// matches names options or operands).
func (ix *Index) denySettled(invs []Invocation) bool {
	if !ix.dispatchSettled(invs) {
		return false
	}
	for i := range invs {
		inv := &invs[i]
		if !ix.denyRuled(inv.Tool) {
			continue
		}
		if inv.Row == nil {
			return false
		}
		tr := ix.tools[inv.Tool]
		for j := range inv.Readings {
			r := &inv.Readings[j]
			if r.Unlocatable || !r.Located || r.Pending {
				return false
			}
			for _, ps := range [...][]*Pattern{tr.deny, tr.ask} {
				for _, p := range ps {
					if !p.Bare && p.NamesArgs() && p.pathMatches(r) {
						return false
					}
				}
			}
		}
	}
	return true
}
