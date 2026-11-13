// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"strings"
)

// Loaded is the program a directly-invoked dynamic loader runs (`ld-linux-x86-64.so.2 /usr/bin/rm -rf tree`): the
// loader opens the program, maps it and jumps to it inside the same process, so the program's own invocation makes no
// execve anyone sees. The decision reads it as the exec's image, by its operand's name, by the walked file's name and
// by its identity, with the argv the loader gives it (ADR 0048 (2), as amended).
type Loaded struct {
	// NodeVersion is attested from the loaded program image, not the loader.
	NodeVersion string
	// Path is the program operand as the loader's argv spells it.
	Path string
	// Image is the walked program's basename (the walk's link); "" when it was not walked.
	Image string
	ID    ID
	HasID bool
	// Links is the walked program's link count, read as Facts.Links is; 0 when unknown.
	Links uint64
	// Argv is the program's vector as the loader passes it: argv[0] (the operand, or --argv0's value), then the
	// words after the operand.
	Argv []string
}

// ViaLoader is an interpretation of the program a directly-invoked dynamic loader runs.
const ViaLoader Via = ViaClosure + 1

// ViaOverflow marks the sentinel interpretation a dispatcher leaves when the matcher cannot resolve its dispatch
// within the depth or interpretation bounds (ADR 0048 (2)): the exec could still reach a ruled
// tool, so the decision fails closed under command-unresolved rather than dropping the interpretation. It is defined
// here, after ViaLoader, to stay out of the iota block ViaClosure ends.
const ViaOverflow Via = ViaLoader + 1

// loaderPrefixes and loaderNames are the basenames of the dynamic loaders (PT_INTERP files) a distribution ships:
// glibc's ld-linux-<arch>.so.N, ld-linux.so.2 and ld64.so.N, its historical ld-<version>.so and ld.so, and musl's
// ld-musl-<arch>.so.1.
var (
	loaderPrefixes = []string{"ld-linux", "ld-musl-", "ld64.so.", "ld-2.", "ld-uClibc"}
	loaderNames    = map[string]bool{"ld.so": true, "ld.so.1": true, "ld.so.2": true}
)

// LoaderName reports whether a basename is a dynamic loader's. A loader run as a command is a program loader: its
// first operand is the program it runs, in-process.
func LoaderName(name string) bool {
	name = base(name)
	if loaderNames[name] {
		return true
	}
	if !strings.Contains(name, ".so") {
		return false
	}
	for _, p := range loaderPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Loader reports whether a file's identity is one of the host's dynamic loaders compile found (IndexOptions.Loaders).
func (ix *Index) Loader(id ID) bool { return ix.lds[id] }

// LoaderOutcome is what a loader's command line asks it to do.
type LoaderOutcome uint8

// Loader outcomes.
const (
	// LoaderRuns: the loader runs the program at the returned index.
	LoaderRuns LoaderOutcome = iota + 1
	// LoaderExits: the loader runs no program (--help, --version, a missing operand, an option missing its value).
	LoaderExits
	// LoaderUnknown: an option the loaders this reads do not have. glibc's and musl's both exit on one, but a later
	// version's option could take a value, which would move the program operand: a caller that cannot tell fails
	// closed.
	LoaderUnknown
)

// loaderValueOptions take the next word as their value (glibc's rtld and musl's ldso); loaderFlagOptions take none;
// loaderExitOptions print and exit.
var (
	loaderValueOptions = map[string]bool{
		"library-path": true, "inhibit-rpath": true, "audit": true, "preload": true, "argv0": true,
		"glibc-hwcaps-prepend": true, "glibc-hwcaps-mask": true,
	}
	loaderFlagOptions = map[string]bool{"list": true, "verify": true, "inhibit-cache": true}
	loaderExitOptions = map[string]bool{"help": true, "version": true, "list-tunables": true, "list-diagnostics": true}
)

// LoaderProgram reads a loader's argv as glibc's rtld (elf/rtld.c dl_main) and musl's ldso (__dls3) read it: options
// start with "--", "--" ends them, a value option takes the next word (or, in musl, "=value"), and the first word
// that is not an option is the program, which runs with argv[0] that word, or --argv0's value, and the words after it.
// i is the program operand's index in argv.
func LoaderProgram(argv []string) (i int, progArgv []string, out LoaderOutcome) {
	argv0 := ""
	for i = 1; i < len(argv); i++ {
		w := argv[i]
		if !strings.HasPrefix(w, "--") {
			break
		}
		opt := w[2:]
		if opt == "" {
			i++
			break
		}
		name, val, hasVal := strings.Cut(opt, "=")
		switch {
		case loaderExitOptions[opt]:
			return 0, nil, LoaderExits
		case loaderFlagOptions[opt]:
		case loaderValueOptions[name] && hasVal:
			if name == "argv0" {
				argv0 = val
			}
		case loaderValueOptions[opt]:
			if i+1 >= len(argv) {
				return 0, nil, LoaderExits // glibc reads it as unknown and exits; musl finds no program
			}
			i++
			if opt == "argv0" {
				argv0 = argv[i]
			}
		default:
			return 0, nil, LoaderUnknown
		}
	}
	if i >= len(argv) {
		return 0, nil, LoaderExits
	}
	if argv0 == "" {
		argv0 = argv[i]
	}
	progArgv = make([]string, 0, len(argv)-i)
	progArgv = append(progArgv, argv0)
	progArgv = append(progArgv, argv[i+1:]...)
	return i, progArgv, LoaderRuns
}

// loadedFacts are the facts of the program a loader runs, read as a direct image: its operand is its requested name
// and path, its walk its image and identity, and its argv the one the loader gives it.
func (f *Facts) loadedFacts() Facts {
	l := f.Loaded
	lf := Facts{
		NodeVersion: l.NodeVersion, Requested: base(l.Path), Path: l.Path, Image: l.Image, ID: l.ID, HasID: l.HasID,
		Links: l.Links, Form: FormDirect, Argv: l.Argv, ArgvComplete: f.ArgvComplete,
	}
	if len(l.Argv) > 0 {
		lf.Argv0 = l.Argv[0]
	}
	return lf
}

// ScriptArgv is the vector binfmt_script gives the last interpreter of a script's #! chain, the program the kernel
// finally runs: its #! path as argv[0], its line's argument, the chain of scripts and the exec's argv[1:]. nil for
// an exec that is no script.
func (f *Facts) ScriptArgv() []string {
	if f.Form != FormScript || len(f.Interp) == 0 {
		return nil
	}
	var argv1 []string
	if len(f.Argv) > 0 {
		argv1 = f.Argv[1:]
	}
	script := f.Path
	if script == "" {
		script = f.Requested
	}
	chain := []string{script}
	var last []string
	for _, st := range f.Interp {
		last = make([]string, 0, len(chain)+2+len(argv1))
		last = append(last, st.Path)
		if st.hasArg() {
			last = append(last, st.Arg)
		}
		last = append(last, chain...)
		last = append(last, argv1...)
		next := []string{st.Path}
		if st.hasArg() {
			next = append(next, st.Arg)
		}
		chain = append(next, chain...)
	}
	return last
}
