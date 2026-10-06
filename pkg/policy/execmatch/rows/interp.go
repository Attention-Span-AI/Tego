// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"strconv"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// pythonModules maps a module run with -m to the tool it is (ADR 0048 (2), interpretation 5); any other module is
// its own name.
var pythonModules = map[string]string{"pip": "pip", "pip3": "pip", "twine": "twine", "pipx": "pipx", "poetry": "poetry", "uv": "uv"}

// entryScripts maps an entry script's basename to the tool it is: `node /usr/share/nodejs/npm/bin/npm-cli.js publish`
// is `npm publish`.
var entryScripts = map[string]string{"npm-cli.js": "npm", "npx-cli.js": "npx", "pnpm.cjs": "pnpm", "pnpm.js": "pnpm", "yarn.js": "yarn", "yarn.cjs": "yarn"}

// interpreters are the interpreter rows: python (probed 3.13), node (probed 20), sh, bash and dash (probed), zsh,
// perl and ruby (documented). Each reads its own options up to the script, module or code; dispatch is by the
// module and entry-script tables, else the script's basename. Code given with -c or -e is opaque (R1).
func interpreters() []*execmatch.Row {
	var py []string
	for i := 0; i <= 20; i++ {
		py = append(py, "python3."+strconv.Itoa(i))
	}
	py = append(py, "python3", "python2", "python2.7", "pypy3", "pypy")
	pythonSyn := execmatch.Syntax{Clusters: true, ShortAttach: true, LongEquals: true, LongSep: true}
	stop := func(o execmatch.Opt) execmatch.Opt { o.Stop = true; return o }
	python := &execmatch.Row{
		Tool: "python", Names: py, Version: "3.13.7", Docs: "python(1), Python/getopt.c", Source: execmatch.SourceProbed,
		Root: leaf(pythonSyn,
			stop(val("c", "c")), stop(val("m", "m")), val("W", "W"), val("X", "X"), val("check-hash-based-pycs", ""),
			flag("b", "b"), flag("B", "B"), flag("d", "d"), flag("E", "E"), flag("h", "h?", "help", "help-env", "help-xoptions", "help-all"),
			flag("i", "i"), flag("I", "I"), flag("O", "O"), flag("P", "P"), flag("q", "q"), flag("s", "s"), flag("S", "S"),
			flag("u", "u"), flag("v", "v"), flag("V", "V", "version"), flag("x", "x"), flag("R", "R")),
		Interp: &execmatch.InterpSpec{Module: "m", Code: []string{"c"}, Modules: pythonModules, Scripts: entryScripts},
	}
	nodeSyn := execmatch.Syntax{LongEquals: true, LongSep: true}
	node := &execmatch.Row{
		Tool: "node", Names: []string{"nodejs"}, Version: "20.19.4", Docs: "node(1)", Source: execmatch.SourceProbed,
		Root: leaf(nodeSyn,
			val("eval", "e"), val("print", "p"), flag("check", "c"), flag("interactive", "i"), flag("version", "v"), flag("help", "h"),
			val("require", "r"), val("import", ""), val("loader", "", "loader", "experimental-loader"), val("conditions", "C"),
			opt("inspect", ""), opt("inspect-brk", ""), val("inspect-port", ""), val("input-type", ""), val("env-file", ""),
			val("title", ""), val("stack-size", ""), val("max-old-space-size", ""), flag("enable-source-maps", ""),
			flag("no-warnings", ""), flag("trace-warnings", ""), flag("experimental-vm-modules", ""), flag("preserve-symlinks", ""),
			flag("test", ""), flag("watch", "")),
		Interp: &execmatch.InterpSpec{Code: []string{"eval", "print"}, Scripts: entryScripts},
	}
	shSyn := execmatch.Syntax{Clusters: true, LongEquals: true, LongSep: true, PlusOptions: true, DashEnds: true}
	shOpts := func() []execmatch.Opt {
		return []execmatch.Opt{
			flag("c", "c"), flag("s", "s"), val("o", "o"), val("O", "O"), flag("i", "i"), flag("l", "l", "login"),
			flag("r", "r", "restricted"), flag("e", "e"), flag("u", "u"), flag("x", "x"), flag("v", "v", "verbose"),
			flag("n", "n"), flag("f", "f"), flag("a", "a"), flag("b", "b"), flag("h", "h"), flag("k", "k"), flag("m", "m"),
			flag("p", "p"), flag("t", "t"), flag("C", "C"), flag("E", "E"), flag("H", "H"), flag("P", "P"), flag("T", "T"),
			flag("B", "B"), val("rcfile", "", "rcfile", "init-file"), flag("norc", ""), flag("noprofile", ""), flag("posix", ""),
			flag("noediting", ""), flag("version", ""), flag("help", ""), flag("debugger", ""), flag("dump-strings", "D"),
		}
	}
	shell := func(tool string, names []string, src execmatch.Source, version string) *execmatch.Row {
		return &execmatch.Row{
			Tool: tool, Names: names, Version: version, Docs: tool + "(1)", Source: src,
			Root:   leaf(shSyn, shOpts()...),
			Interp: &execmatch.InterpSpec{Code: []string{"c", "s"}, Scripts: entryScripts},
		}
	}
	perl := &execmatch.Row{
		Tool: "perl", Names: []string{"perl5"}, Version: "5", Docs: "perlrun(1)", Source: execmatch.SourceDocumented,
		Root: leaf(execmatch.Syntax{Clusters: true, ShortAttach: true},
			val("e", "e"), val("E", "E"), val("I", "I"), opt("M", "M"), opt("m", "m"), opt("x", "x"), opt("i", "i"),
			opt("0", "0"), opt("C", "C"), opt("d", "d"), opt("D", "D"), val("F", "F"), opt("l", "l"),
			flag("n", "n"), flag("p", "p"), flag("a", "a"), flag("c", "c"), flag("s", "s"), flag("S", "S"), flag("T", "T"),
			flag("t", "t"), flag("u", "u"), flag("U", "U"), flag("v", "v"), flag("V", "V"), flag("w", "w"), flag("W", "W"), flag("X", "X")),
		Interp: &execmatch.InterpSpec{Code: []string{"e", "E"}, Scripts: entryScripts},
	}
	ruby := &execmatch.Row{
		Tool: "ruby", Version: "3", Docs: "ruby(1)", Source: execmatch.SourceDocumented,
		Root: leaf(execmatch.Syntax{Clusters: true, ShortAttach: true, LongEquals: true, LongSep: true},
			val("e", "e"), val("I", "I"), val("r", "r"), val("C", "C"), opt("x", "x"), opt("i", "i"), opt("0", "0"),
			opt("E", "E", "encoding"), opt("W", "W"), opt("enable", ""), opt("disable", ""),
			flag("a", "a"), flag("c", "c"), flag("d", "d", "debug"), flag("l", "l"), flag("n", "n"), flag("p", "p"),
			flag("s", "s"), flag("S", "S"), flag("v", "v", "verbose"), flag("w", "w"), flag("y", "y", "yydebug"),
			flag("version", ""), flag("help", "h")),
		Interp: &execmatch.InterpSpec{Code: []string{"e"}, Scripts: entryScripts},
	}
	return []*execmatch.Row{
		python, node,
		shell("sh", nil, execmatch.SourceProbed, "dash 0.5.12 (as /bin/sh)"),
		shell("bash", []string{"rbash"}, execmatch.SourceProbed, "5.2"),
		shell("dash", nil, execmatch.SourceProbed, "0.5.12"),
		shell("zsh", nil, execmatch.SourceDocumented, "5.9"),
		shell("ksh", []string{"mksh", "ksh93"}, execmatch.SourceDocumented, "93u+m"),
		perl, ruby,
	}
}

// multicall are the multicall dispatchers: busybox and the uutils coreutils binary (probed where installed, both
// here), toybox (documented). Each runs the applet argv[1] names; one called by an applet's name is that applet,
// which the name interpretation already reads. The coreutils row also reads GNU coreutils' single binary (the
// coreutils-single package of Fedora, RHEL and UBI-minimal images), which dispatches on --coreutils-prog=PROG and
// --coreutils-prog-shebang=PROG, and runs PROG when called as lt-PROG (src/coreutils.c, documented: no GNU single
// binary is installed here; uutils 0.2.2 refuses all three, "function/utility not found" and "does not match
// executable name", so reading them adds no reading uutils makes).
func multicall() []*execmatch.Row {
	mc := func(tool, version string, src execmatch.Source) *execmatch.Row {
		return &execmatch.Row{Tool: tool, Version: version, Docs: tool + " --help", Source: src, Multicall: true,
			Root: leaf(execmatch.Syntax{}), Residual: tool + "'s sh runs its applets in process (R1)"}
	}
	coreutils := mc("coreutils", "uutils 0.2.2", execmatch.SourceProbed)
	coreutils.ProgOption, coreutils.Argv0Strip = "coreutils-prog", "lt-"
	coreutils.Docs = "coreutils --help; GNU coreutils src/coreutils.c (--coreutils-prog)"
	busybox := mc("busybox", "1.37.0", execmatch.SourceProbed)
	busybox.Argv0Prefix = true
	toybox := mc("toybox", "0.8", execmatch.SourceDocumented)
	toybox.Argv0Prefix = true // toy_find: the multiplexer's name works as a prefix
	return []*execmatch.Row{busybox, coreutils, toybox}
}
