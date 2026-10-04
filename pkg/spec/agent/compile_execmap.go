// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Native code a decision plane refuses to map (ADR 0027; agent-contract.md E39; enforce-plane R26). At tiers 2 and 3
// with a plane, a PROT_EXEC map of a file under a write entry that no exec.allow entry covers is refused, so an
// interpreter's import of a native module the agent installed or built there, or a dlopen of it, fails at run time.
// execMapNative says so at compile, with the exec.allow line that keeps it working.
var (
	// execMapScanMax bounds the directory entries execMapNative reads under one write entry: a write entry may be a
	// home directory, and compile must not walk it whole. The bound is on the listing itself (listDir), so one
	// directory of millions of entries the agent planted is read no further than it (I6).
	execMapScanMax = 20000
	// execMapScanMaxTime bounds the whole scan, every write entry together: the entries are where the agent writes,
	// so it chooses how many there are and what each costs to list or open.
	execMapScanMaxTime = 2 * time.Second
)

// execMapDepthMax bounds how deep it looks: a virtual environment's extension sits about seven levels down.
const execMapDepthMax = 10

// execMapRoots are the directory names that root a native-module tree: a Python virtual environment and its
// site-packages, a Node project's node_modules, a Rust or CMake build tree. A native file beneath one is named by the
// outermost such directory under the write entry, so one exec.allow line covers the tree.
var execMapRoots = []string{".venv", "venv", "site-packages", "node_modules", "target", "build"}

// execMapTreeAlways are the roots that warn by existing, native file or not: a virtual environment and a Rust target/
// fill with native code once the run installs or builds into them.
var execMapTreeAlways = []string{".venv", "target"}

// execMapNative is ADR 0027's warning: in a contract with an exec: section whose run may land at tier cgroup or
// bpflsm, each native-module tree under a write entry that no exec.allow directory covers warns exec-map, once, with
// the entry to add. Tier landlock decides no mapping (SEMANTICS §4), so a run that can land nowhere else is not warned.
func (k *compiler) execMapNative() {
	if k.rt.Contract == nil || k.rt.ExecUnrestricted() {
		return
	}
	if !k.mayLand(backend.TierCgroup) && !k.mayLand(backend.TierBPFLSM) {
		return
	}
	var covers []string
	for _, r := range k.rt.Exec {
		if r.IsDir {
			if resolved := k.resolve(r.Path); resolved != "" {
				covers = append(covers, resolved)
			}
		}
	}
	covered := func(p string) bool {
		for _, c := range covers {
			if isAncestorOrSelf(c, p) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	end := time.Now().Add(execMapScanMaxTime)
	for _, w := range k.rt.FS {
		if w.Kind != FSWrite || w.Raw == "" || w.Resolved == "" {
			continue
		}
		trees, cut, late := nativeTrees(w.Resolved, end)
		for _, tree := range trees {
			if seen[tree] || covered(tree) {
				continue
			}
			seen[tree] = true
			rel, err := filepath.Rel(w.Resolved, tree)
			if err != nil {
				continue
			}
			entry := strings.TrimSuffix(w.Raw, "/") + "/" + filepath.ToSlash(rel) + "/"
			k.ds.warnf(w.Pos, CodeExecMap, "%s under the writable %s holds native code the agent maps executable, which no "+
				"exec.allow entry covers: at tiers cgroup and bpflsm the decision plane refuses that map, so its import or "+
				"dlopen fails", tree, w.Raw).
				fix("exec.allow: add %q, as for a binary built or installed there", entry)
		}
		// A scan cut short names nothing past where it stopped, and the author reads silence as no native code.
		switch {
		case late:
			k.ds.warnf(w.Pos, CodeExecMap, "the scan of the writable %s for native code ran out of its time limit, %s, so "+
				"native code beyond where it stopped is not named here, and its import or dlopen fails at tiers cgroup and "+
				"bpflsm", w.Raw, execMapScanMaxTime).
				fix("name the native-module trees under %s in exec.allow yourself", w.Raw)
		case cut:
			k.ds.warnf(w.Pos, CodeExecMap, "the scan of the writable %s for native code read its %d directory entries and "+
				"left more unread, so native code among them is not named here, and its import or dlopen fails at tiers "+
				"cgroup and bpflsm", w.Raw, execMapScanMax).
				fix("name the native-module trees under %s in exec.allow yourself", w.Raw)
		}
	}
}

// nativeTrees scans root, breadth first and bounded, for native code: an ELF shared object (named *.so or *.so.N)
// or a Node addon (*.node), and a known tree that fills with them (execMapTreeAlways). Each is reported by its
// outermost native-tree root under root (execMapRoots), else by its own directory; symlinks are not followed and
// .git is skipped. root is a write entry, so what is beneath it is the agent's choice, and every read goes the
// bounded way (I6): each directory through listDir with what is left of execMapScanMax, each candidate file
// through openData (isELF). filepath.WalkDir read and sorted a whole directory before any bound was asked, and
// os.Open waited on a FIFO swapped in for a *.so, or on a file its owner held a lease on. cut says entries were
// left unread, late that the scan stopped at end.
func nativeTrees(root string, end time.Time) (out []string, cut, late bool) {
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	treeOf := func(dir string) string {
		rel, err := filepath.Rel(root, dir)
		if err != nil || rel == "." {
			return dir
		}
		parts := strings.Split(rel, string(filepath.Separator))
		for i, part := range parts {
			if slices.Contains(execMapRoots, part) {
				return filepath.Join(append([]string{root}, parts[:i+1]...)...)
			}
		}
		return dir
	}
	type dir struct {
		path  string
		depth int
	}
	left := execMapScanMax
	queue := []dir{{root, 0}}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if left <= 0 {
			return out, true, false
		}
		if time.Now().After(end) {
			return out, cut, true
		}
		es, more, _ := listDir(d.path, left)
		left -= len(es)
		cut = cut || more
		for _, e := range es {
			p := filepath.Join(d.path, e.Name())
			if e.IsDir() {
				if e.Name() == ".git" || d.depth+1 > execMapDepthMax {
					continue
				}
				if slices.Contains(execMapTreeAlways, e.Name()) {
					add(treeOf(p))
				}
				queue = append(queue, dir{p, d.depth + 1})
				continue
			}
			if !e.Type().IsRegular() || !nativeName(e.Name()) {
				continue
			}
			if time.Now().After(end) {
				return out, cut, true
			}
			if isELF(p) {
				add(treeOf(d.path))
			}
		}
	}
	return out, cut, false
}

// nativeName reports whether a file name is a shared object's (lib.so, lib.so.1, x.cpython-313-x86_64-linux-gnu.so)
// or a Node addon's.
func nativeName(name string) bool {
	if strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".node") {
		return true
	}
	i := strings.Index(name, ".so.")
	if i < 0 {
		return false
	}
	for _, c := range name[i+4:] {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// isELF reports whether the regular file at p starts with the ELF magic. It is read through openData, never
// following a final link: the name was a regular file when listed, and a FIFO, a device or a link swapped in
// since is refused rather than opened, as is a file on a file system not known to store data; a lease its owner
// holds is EWOULDBLOCK, not a wait.
func isELF(p string) bool {
	fd, _, err := openData(p, false)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	var magic [4]byte
	if n, err := preadFull(fd, magic[:], 0); err != nil || n != len(magic) {
		return false
	}
	return string(magic[:]) == "\x7fELF"
}
