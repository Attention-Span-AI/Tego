// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// ExecReach is what an exec block's value reaches on this machine now beyond the name it is written as (ReachOf), for
// the words a writer adds when it places one. The launcher matches an absolute value by name and by the identity of
// the file it leads to (Resolved.Files: stat(2), links followed), so the block refuses that file under every name it
// has: each of its hard links, and every symbolic link that leads to it. A multi-call program (uutils' or a
// single-binary GNU coreutils, busybox) is one such file, so a block on /bin/ls refuses cat and sleep too. A bare name
// is matched by the last element of a program's name alone, wherever the program lies.
type ExecReach struct {
	// File is the file an absolute value leads to now (RealPath, within its budget; the value itself when it is
	// reached through no link, or when the walk ran out of budget). "" for a bare name or a folder, and for a value
	// that is no regular file here now.
	File string
	// Names is how many names File has, its hard links: above 1, the block refuses it under each of them.
	Names uint64
	// Renamed: the value leads to File through a link whose last element is another (/bin/ls to /bin/busybox), so
	// the block refuses File under every name that leads there, not under the value's own name alone.
	Renamed bool
	// Missing: the value names nothing here now, an absolute path stat(2) cannot read, or a bare name no folder of the
	// PATH searched holds as a program. The block refuses it all the same if one appears.
	Missing bool
}

// ReachOf is the ExecReach of an exec block's value (normalized) now. path is the PATH a bare name is looked up on,
// colon-separated; "" looks a bare name up nowhere, so it is never Missing.
func ReachOf(value, path string) ExecReach {
	switch {
	case strings.HasSuffix(value, "/"):
		return ExecReach{}
	case !strings.HasPrefix(value, "/"):
		return ExecReach{Missing: path != "" && !onPath(value, path)}
	}
	var st unix.Stat_t
	if err := unix.Stat(value, &st); err != nil {
		return ExecReach{Missing: true}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return ExecReach{} // a folder named without its "/" matches no program image by identity
	}
	r := ExecReach{File: value, Names: uint64(st.Nlink)} // Nlink is narrower than uint64 on some architectures
	if real, err := RealPath(value); err == nil && real != "" {
		r.File = real
	}
	r.Renamed = filepath.Base(r.File) != filepath.Base(value)
	return r
}

// maxScan bounds the folder entries OtherNames reads.
const maxScan = 4096

// OtherNames is up to max other names file has in its own folder, sorted: the entries there that lead to the same file
// (its hard links, and symbolic links to it), other than file's own name. They are names a block that matches the file
// refuses beside its own, for a writer's words: a multi-call program keeps its applets in one folder (uutils' in
// /usr/lib/cargo/bin/coreutils, busybox's links beside it). None when file or its folder cannot be read; at most
// maxScan entries of the folder are looked at.
func OtherNames(file string, max int) []string {
	var st unix.Stat_t
	if max <= 0 || unix.Stat(file, &st) != nil {
		return nil
	}
	dir, own := filepath.Split(file)
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	ents, _ := f.ReadDir(maxScan)
	_ = f.Close() // read only
	var out []string
	for _, e := range ents {
		var o unix.Stat_t
		if n := e.Name(); n != own && unix.Stat(filepath.Join(dir, n), &o) == nil && o.Dev == st.Dev && o.Ino == st.Ino {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// onPath reports whether a folder of path holds name as a program: a regular file, links followed, with an execute
// bit. Empty and relative entries are skipped, so the answer does not hang on the working directory.
func onPath(name, path string) bool {
	for _, d := range filepath.SplitList(path) {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(filepath.Join(d, name), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o111 != 0 {
			return true
		}
	}
	return false
}

// SameFileNote reads one refused exec line: rule is the rule it carries and path the program path it names (the
// line's path). A block on an absolute program path matches the file the path leads to, under every name that file has
// (a multi-call program's applets are one file), and a block placed from a rules change (Entry.Match) the file its
// entry granted, by any name that reaches it there: so when rule is such a block's (live.block[exec:/bin/ls]) and the
// line names another path, the exec was refused as another name of the same program file. SameFileNote is then
// the words that say so, "same program file as /bin/ls, which is blocked", for the run summary, the receipt and the
// dashboard's refused row; "" for every other line. The record holds no field for it: the rule and the path are the
// facts, and this is the one place that reads them together.
func SameFileNote(rule, path string) string {
	v, ok := strings.CutPrefix(rule, "live.block["+string(KindExec)+":")
	if !ok {
		return ""
	}
	v, ok = strings.CutSuffix(v, "]")
	if !ok || !linkable(KindExec, v) || !filepath.IsAbs(path) || filepath.Clean(path) == v {
		return ""
	}
	return "same program file as " + v + ", which is blocked"
}
