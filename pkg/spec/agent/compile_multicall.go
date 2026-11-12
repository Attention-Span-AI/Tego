// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// MulticallFile is the program file an exec name leads to, as compile's exec-multicall note and doctor's layout line
// read it: by stat alone, never by opening or running it.
type MulticallFile struct {
	// Resolved is the name with every symlink followed: the link the kernel loads.
	Resolved string `json:"resolved"`
	// Links is the file's hard link count (st_nlink): how many names lead to this one file.
	Links uint64 `json:"links"`
	// Dispatcher is true when Resolved's last element is a multi-call dispatcher's name (multicallDispatcher).
	Dispatcher bool `json:"dispatcher,omitempty"`
}

// multicallDispatcher reports whether a file's name is one a multi-call program answers to as itself, which then runs
// the program argv[1] names: busybox and toybox, whose names count as a prefix as the command matcher reads them
// (pkg/policy/execmatch/rows multicall: Argv0Prefix, so busybox.static is busybox), and coreutils (uutils' file, and GNU
// coreutils' single binary).
func multicallDispatcher(name string) bool {
	return name == "coreutils" || strings.HasPrefix(name, "busybox") || strings.HasPrefix(name, "toybox")
}

// MulticallOf reads the file path leads to, following every symlink, and reports whether it may be a multi-call
// program: a regular file with more than one hard link, or one named busybox, toybox or coreutils. A path that leads
// nowhere, or to anything but a regular file, is not one. It stats only (SEMANTICS §4: which program such a file runs
// is its own choice from argv[0] or argv[1], which no stat can tell).
func MulticallOf(path string) (MulticallFile, bool) {
	m, _, ok := multicallAt(resolvePath(path))
	return m, ok
}

// multicallAt is MulticallOf on a path already resolved, with the file's identity (fileKey: one key per file,
// whatever names lead to it).
func multicallAt(resolved string) (MulticallFile, fileKey, bool) {
	var st unix.Stat_t
	if resolved == "" || unix.Stat(resolved, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return MulticallFile{}, fileKey{}, false
	}
	// Nlink is uint32 on arm64, and Dev and Ino are not uint64 everywhere (fileKeyOf).
	links := uint64(st.Nlink)                                //nolint:unconvert // uint64 on amd64 only
	key := fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)} //nolint:unconvert // as fileKeyOf
	m := MulticallFile{Resolved: resolved, Links: links, Dispatcher: multicallDispatcher(filepath.Base(resolved))}
	return m, key, m.Links > 1 || m.Dispatcher
}

// multicallFix is exec-multicall's fix line.
const multicallFix = "list such a file only where every program it holds may run; docs/GAPS.md says what each tier and each coreutils build admits"

// multicallNamed is how many entry names a finding spells out before it says how many more there are: on Ubuntu
// 25.10 and later a contract can list dozens of names of one file.
const multicallNamed = 8

// execMulticall is the exec-multicall note (SEMANTICS §4, the multi-call paragraph): one per file that an allowed exec
// entry leads to and that MulticallOf reads as a possible multi-call program, at the first such entry's line, naming
// every entry that leads to it. When any of those entries reaches the file by a dispatcher's name, the note is the
// dispatcher's, whatever the entries' order. An exec section that restricts no image (none, or a deny-list) admits
// every file anyway, so it gets none; a directory entry names no one file. Helper images (git's) and the runtime's own
// grants are not the author's entries and are left out.
//
// It is a note (Diagnostic.Informational) and touches nothing but the diagnostics: the rules the table holds are the
// same whether the file has one name or many (TestExecMulticallChangesNoRule). What it states is SEMANTICS §4's
// meaning of an entry on such a host, which the author settles when writing the contract; the run enforces what the
// table holds, so `tego run` leaves the note out of its start unless -v, and `tego compile` and the dashboard's
// contract check print it. On Ubuntu 25.10 and later nearly every coreutils name leads to one file, so a run that
// repeated it would print it at every start.
func (k *compiler) execMulticall() {
	if k.rt.ExecUnrestricted() {
		return
	}
	type group struct {
		file  MulticallFile
		first Pos
		names []string
	}
	var order []fileKey
	groups := map[fileKey]*group{}
	for _, r := range k.rt.Exec {
		if r.IsDir || r.Verdict != VerdictAllow || r.Runtime != "" || !authorEntry(r.Source) {
			continue
		}
		at := r.Resolved
		if at == "" {
			at = k.resolve(r.Path)
		}
		m, key, ok := multicallAt(at)
		if !ok {
			continue
		}
		g, seen := groups[key]
		if !seen {
			g = &group{file: m, first: r.Pos}
			groups[key] = g
			order = append(order, key)
		} else if m.Dispatcher && !g.file.Dispatcher {
			// One file, reached by a plain name and by its dispatcher's (Ubuntu's ls and /usr/bin/coreutils): the
			// listed dispatcher runs whatever argv[1] names at every tier, whichever entry came first, so the note
			// says that, under the dispatcher's name.
			g.file = m
		}
		g.names = append(g.names, rawOr(r.Raw, r.Path))
	}
	for _, key := range order {
		g := groups[key]
		what, leads := "the exec entries "+quotedList(g.names), "lead"
		if len(g.names) == 1 {
			what, leads = "the exec entry "+strconv.Quote(g.names[0]), "leads"
		}
		if g.file.Dispatcher {
			links := ""
			if g.file.Links > 1 {
				links = fmt.Sprintf(" (%d names, hard links)", g.file.Links)
			}
			k.ds.warnf(g.first, CodeExecMulticall, "%s %s to %s%s, a multi-call program, which runs the program argv[0] or argv[1] names. "+
				"A listed name admits every program it holds, at every tier", what, leads, g.file.Resolved, links).
				fix("%s", multicallFix).info()
			continue
		}
		k.ds.warnf(g.first, CodeExecMulticall, "%s %s to one program file, %s, with %d names (hard links). "+
			"Tiers cgroup and bpflsm admit only the names listed; tier landlock admits the file by any of its names to an agent "+
			"that wins the exec race, and a multi-call build that reads argv[0] (busybox, uutils without Ubuntu's patch) runs "+
			"any program it holds through a listed name", what, leads, g.file.Resolved, g.file.Links).
			fix("%s", multicallFix).info()
	}
}

// authorEntry reports whether an exec rule's sources hold one the contract wrote or implies from what it wrote: its
// command, an MCP server's command, an exec.allow entry, or a script's #! interpreter. A helper image alone (git's
// re-executed helpers, ADR 0048 (2)) is not.
func authorEntry(source string) bool {
	for _, s := range strings.Split(source, ",") {
		kind, _, _ := strings.Cut(s, ":")
		switch kind {
		case ExecSourceCommand, ExecSourceAllow, ExecSourceMCP, ExecSourceInterpreter:
			return true
		}
	}
	return false
}

// quotedList is names quoted and joined as a sentence lists them ("a", "b" and "c"), the first multicallNamed of them
// and then how many more.
func quotedList(names []string) string {
	shown := names
	more := 0
	if len(names) > multicallNamed {
		shown, more = names[:multicallNamed], len(names)-multicallNamed
	}
	q := make([]string, len(shown))
	for i, n := range shown {
		q[i] = strconv.Quote(n)
	}
	if more > 0 {
		return strings.Join(q, ", ") + " and " + strconv.Itoa(more) + " more"
	}
	if len(q) == 1 {
		return q[0]
	}
	return strings.Join(q[:len(q)-1], ", ") + " and " + q[len(q)-1]
}
