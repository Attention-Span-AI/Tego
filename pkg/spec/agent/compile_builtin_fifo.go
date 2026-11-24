// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The inventory's two bounds. Files are the entries the walk stats one by one (a FIFO can only be one of
// those). Directories are the entries it opens and lists: a name the parent's listing already gave, with no stat of
// its own and nothing to spend but one open and one read. A desktop's /run/user/<uid>/gnupg holds one directory per
// GNUPGHOME ever used (4043 on the dev box); charged as files they used up the 4096 and every later folder (systemd,
// pulse) was refused whole. The directory bound is four times the file bound: a listing costs about what a stat does,
// and the walk still ends in time on a hostile tree.
const (
	builtinFIFOFiles = 4096
	builtinFIFODirs  = 16384
)

// Existing screen FIFO endpoints become ordinary immutable deny-read nodes.
// Never open a FIFO for data. The bounded directory walker fails closed rather
// than silently omitting endpoints when it cannot finish the snapshot.
func (k *compiler) builtinFIFOs() {
	b := k.rt.Builtins
	if b == nil {
		return
	}
	queue := append(slices.Clone(b.Runtime), b.IPCDirs...)
	seen := map[string]bool{}
	left, dirsLeft := builtinFIFOFiles, builtinFIFODirs
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		skip := false
		for _, d := range b.TegoDirs {
			if Covers(d, dir) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		entries, more, err := listDir(dir, left+dirsLeft)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				// Refuse this entire unreadable subtree instead of silently
				// omitting potential FIFO endpoints. This also survives a later
				// chmod by an outside process. Root lists it and refuses only its
				// FIFOs, so a root-tier prediction is unknown.
				k.builtinCut(dir, err)
				k.builtinReadTarget(dir)
				continue
			}
			if resolved, e := filepath.EvalSymlinks(dir); e == nil && resolved != dir {
				queue = append(queue, resolved)
				continue
			}
			// A fixed directory name occupied by a non-directory holds no FIFO.
			if st, e := os.Stat(dir); e == nil && !st.IsDir() {
				continue
			}
			k.ds.errorf(k.cpos, CodeUnenforced, "builtin.host_ipc cannot inventory FIFO endpoints in %s: %v", dir, err)
			return
		}
		files, dirs := 0, 0
		for _, e := range entries {
			if e.IsDir() {
				dirs++
			} else {
				files++
			}
		}
		if more || files > left || dirs > dirsLeft {
			// A large runtime alias must not force an unbounded scan or omit
			// unknown FIFO nodes. Protect this subtree in full instead.
			k.builtinReadTarget(dir)
			left, dirsLeft = 0, 0
			continue
		}
		left -= files
		dirsLeft -= dirs
		protected := false
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				queue = append(queue, p)
				continue
			}
			st, err := os.Stat(p)
			if err != nil {
				if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
					// A disappearing entry or dangling link also gets a subtree
					// refusal: normal runtime churn must not remove coverage.
					// Listing permission does not imply search permission. An
					// outside chmod must not expose FIFOs omitted by this stat.
					if !protected {
						k.builtinCut(p, err) // root stats it: a root-tier prediction is unknown
						k.builtinReadTarget(dir)
						protected = true
					}
					if errors.Is(err, os.ErrPermission) {
						break
					}
					continue
				}
				k.ds.errorf(k.cpos, CodeUnenforced, "builtin.host_ipc cannot stat FIFO inventory entry %s: %v", p, err)
				return
			}
			if st.Mode()&os.ModeSocket != 0 {
				for _, root := range b.Runtime {
					if Covers(root, p) && sshSocket(strings.TrimPrefix(p, root+"/")) {
						b.PeerSockets = append(b.PeerSockets, p)
					}
				}
			}
			if st.IsDir() {
				resolved, err := filepath.EvalSymlinks(p)
				if err != nil {
					if errors.Is(err, os.ErrPermission) {
						k.builtinCut(p, err) // root resolves it: a root-tier prediction is unknown
						k.builtinReadTarget(dir)
						break
					}
					k.ds.errorf(k.cpos, CodeUnenforced, "builtin.host_ipc cannot resolve FIFO inventory directory %s: %v", p, err)
					return
				}
				queue = append(queue, resolved)
				continue
			}
			if st.Mode()&os.ModeNamedPipe == 0 {
				continue
			}
			k.builtinReadTarget(p)
		}
	}
}

func (k *compiler) builtinReadTarget(p string) {
	resolved := k.resolve(p)
	if resolved == "" {
		resolved = p
	}
	un := false
	for _, w := range k.rt.FS {
		if w.Kind == FSWrite && Covers(w.Canonical(), resolved) {
			un = true
			if k.nestedWrite == nil {
				k.nestedWrite = map[string]writePath{}
			}
			k.nestedWrite[p] = writePath{declared: w.Path, resolved: w.Canonical()}
			break
		}
	}
	k.rt.FS = append(k.rt.FS, FSRule{Path: p, Resolved: resolved, Kind: FSDenyRead, BuiltIn: true, BuiltinRule: BuiltinHostIPC, Unenforced: un})
}
