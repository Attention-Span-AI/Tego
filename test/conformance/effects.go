// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The effect judge (ADR 0017 (c), "a refused create leaves no file"): the kernel runner snapshots the project tree
// before and after a fixture's run, and each cell's side effect is read off the two. A refusal that left its effect
// behind is a fail-open, on every axis, never baselined: the agent got what the result says it did not. Tier cgroup's
// fanotify listener on its own answers a permission event for an O_CREAT open after the kernel has created the inode,
// so a create it alone refuses leaves an empty file (docs/p0/enforce-cgroup-observe.md, the refused-O_CREAT residue).
// A run on that axis is not the listener alone: the supervisor refuses a create, a creat or any other mutation the
// contract refuses before the kernel acts (ADR 0021 (5), fallbackMutation), so no refused create may leave even an
// empty file there, and the judge grants no axis a residue. A success that left no effect is an effect failure of
// its own: the actor reported something the tree does not show.

// snapshotHashMax bounds the files whose content the snapshot hashes: the fixtures' own files are a few bytes, and
// the copies of the actor (megabytes, never written by a cell) are compared by size and mode alone.
const snapshotHashMax = 64 << 10

// Node is one name of a snapshot, as lstat sees it.
type Node struct {
	// Mode holds the type bits and the permission bits.
	Mode fs.FileMode
	Size int64
	// Sum is the sha256 of a regular file of at most snapshotHashMax bytes, "" otherwise.
	Sum string
	// Link is a symlink's target as written.
	Link string
	// UID and GID are the owner; Xattrs is the sha256 of the user.* xattrs and the access ACL, by name, "" for none
	// (space 4's chown, setxattr and setfacl).
	UID, GID uint32
	Xattrs   string
}

// Tree maps each name below a root, relative to it, to its Node; the root itself is not in it.
type Tree map[string]Node

// Snapshot walks root without following symlinks.
func Snapshot(root string) (Tree, error) {
	t := Tree{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		n := Node{Mode: info.Mode(), Size: info.Size()}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			n.UID, n.GID = st.Uid, st.Gid
		}
		if n.Xattrs, err = xattrSum(p); err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			if n.Link, err = os.Readlink(p); err != nil {
				return err
			}
		case info.Mode().IsRegular() && info.Size() <= snapshotHashMax:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			n.Sum = hex.EncodeToString(sum[:])
		}
		t[rel] = n
		return nil
	})
	return t, err
}

// xattrSum hashes p's user.* xattrs and its access ACL, by name, without following a symlink; "" when it has none.
// A filesystem without xattrs has none.
func xattrSum(p string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Llistxattr(p, buf)
	switch {
	case errors.Is(err, unix.ENOTSUP):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("llistxattr %s: %w", p, err)
	}
	var names []string
	for _, name := range strings.Split(string(buf[:n]), "\x00") {
		if strings.HasPrefix(name, "user.") || name == "system.posix_acl_access" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	slices.Sort(names)
	h := sha256.New()
	for _, name := range names {
		v := make([]byte, 4096)
		m, err := unix.Lgetxattr(p, name, v)
		if err != nil {
			return "", fmt.Errorf("lgetxattr %s %s: %w", p, name, err)
		}
		fmt.Fprintf(h, "%s=%x\n", name, v[:m])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// resolve is where the kernel finds path in the tree: each directory component spelled through a symlink is
// replaced by what the link names, and the last one too when follow is set (an open, a creat, a truncate or a chmod
// follows it; a create with O_EXCL, an unlink, an rmdir, a mkdir, a rename, an exchange, a link and a symlink do
// not). A trailing slash leaves the last one unfollowed too when follow is not set: a syscall that makes, removes or
// renames a name strips it and looks the name up in its directory (filename_parentat), so an rmdir of "lk/" acts on
// lk itself; only a link's old name, looked up whole, follows a final link before a slash, and its caller asks
// follow. Nothing is cleaned first: a ".." is the parent of the
// directory reached so far, every link before it followed, and a link's body is walked as written, as the kernel walks
// both. ok is false for a path that leaves the tree (an absolute path or link, a ".." above the root) or loops.
func (t Tree) resolve(path string, follow bool) (string, bool) {
	if filepath.IsAbs(path) {
		return "", false
	}
	parts := strings.Split(path, "/")
	cur := ""
	for hops := 0; len(parts) > 0; {
		c := parts[0]
		parts = parts[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if cur == "" {
				return "", false
			}
			if cur = filepath.Dir(cur); cur == "." {
				cur = ""
			}
			continue
		}
		next := filepath.Join(cur, c)
		n, ok := t[next]
		if !ok || n.Mode&fs.ModeSymlink == 0 || (!follow && strings.Trim(strings.Join(parts, "/"), "/") == "") {
			cur = next
			continue
		}
		if hops++; hops > 40 || filepath.IsAbs(n.Link) {
			return "", false
		}
		// The link's body is walked from the directory it sits in, which is cur.
		parts = append(strings.Split(n.Link, "/"), parts...)
	}
	if cur == "" {
		return "", false
	}
	return cur, true
}

// EffectClass is what the judge found of one cell's side effect.
type EffectClass string

// The classes. EffectNone is a cell with no side effect to judge: a read, an exec, a map, a connect, a write-open
// (O_APPEND, nothing written), and an action that failed with neither a success nor a refusal.
const (
	EffectNone     EffectClass = ""
	EffectHeld     EffectClass = "held"
	EffectFailOpen EffectClass = "fail-open"
	EffectMissing  EffectClass = "missing"
)

// Effect is the judge's finding for one cell.
type Effect struct {
	Class EffectClass
	// Detail says what the tree shows, for a fail-open or a missing effect.
	Detail string
}

// JudgeEffects judges the side effect of every cell of fx from the trees before and after its run and each cell's
// outcome (keyed by cell ID). Every axis is judged alike, none with a residue (the note above). A cell is judged on the tree the cells ahead of it left: their successful renames applied to the
// before tree (renamed), so a name spelled through a link an earlier cell replaced with a real directory is where the
// kernel's walk found it, not where the starting tree's link pointed (refer's replaced-link cells). A later cell's
// successful rename moves the names beneath its source, so a name is looked up in the after tree where the renames
// that ran after its own action put it.
func JudgeEffects(fx *Fixture, before, after Tree, results map[string]Outcome) map[string]Effect {
	at := make([]Tree, len(fx.Cells))           // at[i] is the tree cell i found
	renames := make([][2]string, len(fx.Cells)) // cell i's successful rename, source to destination, in at[i]
	cur := before
	for i := range fx.Cells {
		at[i] = cur
		r := &fx.Cells[i]
		if r.Op != OpRename || !results[fx.ID(r)].OK {
			continue
		}
		src, ok1 := cur.resolve(r.Path, false)
		dst, ok2 := cur.resolve(r.Dest, false)
		if ok1 && ok2 {
			renames[i] = [2]string{src, dst}
			cur = cur.renamed(src, dst)
		}
	}
	out := map[string]Effect{}
	for i := range fx.Cells {
		c := &fx.Cells[i]
		o, ran := results[fx.ID(c)]
		if !ran {
			continue
		}
		var moves [][2]string // the successful renames after this cell, source to destination, in order
		for j := i + 1; j < len(fx.Cells); j++ {
			if renames[j][0] != "" {
				moves = append(moves, renames[j])
			}
		}
		out[fx.ID(c)] = judgeEffect(c, o, at[i], after, moves)
	}
	return out
}

// renamed is t after rename(2) moved the name src, and every name beneath it, to dst, replacing what dst held.
func (t Tree) renamed(src, dst string) Tree {
	if src == dst {
		return t
	}
	n := make(Tree, len(t))
	for p, node := range t {
		if !under(dst, p) && !under(src, p) {
			n[p] = node
		}
	}
	for p, node := range t {
		if under(src, p) {
			n[filepath.Join(dst, strings.TrimPrefix(p, src))] = node
		}
	}
	return n
}

// same says two nodes are one name's same object as far as a cell can tell: the type, a regular file's content and
// a symlink's target. A directory's size follows its entries, which other cells change.
func same(a, b Node) bool {
	return a.Mode.Type() == b.Mode.Type() && a.Sum == b.Sum && a.Link == b.Link && (a.Mode.IsDir() || a.Size == b.Size)
}

// refilled reports whether a later successful rename in moves put another object at the name p or above it: a rename
// cell's source then exists again (refer's S1 cells put a fresh directory, holding a fresh exec.allow directory, where
// the one moved away was), and the later cell's own effect is judged on it.
func refilled(p string, moves [][2]string) bool {
	for _, m := range moves {
		if under(m[1], p) {
			return true
		}
	}
	return false
}

// moved is where the renames in moves left the name p.
func moved(p string, moves [][2]string) string {
	for _, m := range moves {
		if under(m[0], p) {
			p = filepath.Join(m[1], strings.TrimPrefix(p, m[0]))
		}
	}
	return p
}

func judgeEffect(c *Cell, o Outcome, before, after Tree, moves [][2]string) Effect {
	// A link's old name is looked up whole (filename_lookup), so a trailing slash follows its final link.
	follow := c.Op == OpWriteOpen || c.Op == OpCreat || c.Op == OpOpenTrunc || c.Op == OpTruncate || c.Op == OpChmod ||
		c.Op == OpChown || c.Op == OpSetxattr || c.Op == OpSetfacl || (c.Op == OpLink && strings.HasSuffix(c.Path, "/"))
	switch c.Op {
	case OpCreate, OpCreat, OpMkdir, OpSymlink, OpUnlink, OpRmdir, OpOpenTrunc, OpTruncate, OpChmod, OpRename, OpExchange, OpLink,
		OpChown, OpSetxattr, OpSetfacl, OpMknod, OpRaceSymlinkWrite:
	default:
		return Effect{}
	}
	if !o.OK && !o.Refusal() {
		return Effect{}
	}
	path := c.Path
	if c.Op == OpRaceSymlinkWrite {
		path = c.canon() // the link is the actor's own; the effect is on the target
	}
	p, ok := before.resolve(path, follow)
	if !ok {
		return Effect{Class: EffectMissing, Detail: fmt.Sprintf("%s leaves the project tree; its effect cannot be judged", path)}
	}
	var d string
	if c.Op == OpRename || c.Op == OpExchange || c.Op == OpLink {
		if d, ok = before.resolve(c.Dest, false); !ok {
			return Effect{Class: EffectMissing, Detail: fmt.Sprintf("%s leaves the project tree; its effect cannot be judged", c.Dest)}
		}
	}
	was, had := before[p]
	now, has := after[moved(p, moves)]
	held := Effect{Class: EffectHeld}
	if o.Refusal() {
		bad := func(format string, a ...any) Effect {
			return Effect{Class: EffectFailOpen, Detail: "the action was refused but " + fmt.Sprintf(format, a...)}
		}
		switch c.Op {
		case OpCreate, OpCreat, OpMkdir, OpSymlink, OpMknod:
			// No residue, not even an empty file on the listener's axis: there the supervisor refuses a create,
			// whether an O_CREAT open or a creat, before the kernel makes anything (fallbackMutation), and an empty
			// file with the listener's own FAN_DENY after the create is that refusal missing (ADR 0021 (5)).
			switch {
			case had && (!has || !same(now, was)):
				return bad("%s, which existed, changed", p)
			case had || !has:
				return held
			}
			return bad("%s exists (%v, %d bytes)", p, now.Mode, now.Size)
		case OpLink:
			dWas, dHad := before[d]
			dNow, dHas := after[moved(d, moves)]
			if dHas && (!dHad || !same(dNow, dWas)) {
				return bad("the new name %s exists", d)
			}
			return held
		case OpUnlink, OpRmdir:
			if had && (!has || now.Mode.Type() != was.Mode.Type()) {
				return bad("%s is gone", p)
			}
			return held
		case OpRename:
			dWas, dHad := before[d]
			dNow, dHas := after[moved(d, moves)]
			switch {
			case had && (!has || now.Mode.Type() != was.Mode.Type()):
				return bad("the source %s is gone", p)
			case dHas && (!dHad || !same(dNow, dWas)):
				return bad("the destination %s exists", d)
			}
			return held
		case OpExchange:
			// Both names existed and keep what they held.
			dWas, dHad := before[d]
			dNow, dHas := after[moved(d, moves)]
			if (had && (!has || !same(now, was))) || (dHad && (!dHas || !same(dNow, dWas))) {
				return bad("%s and %s no longer hold what they held", p, d)
			}
			return held
		case OpTruncate, OpOpenTrunc:
			if had && (!has || now.Size != was.Size || now.Sum != was.Sum) {
				return bad("the content of %s changed (%d bytes, was %d)", p, now.Size, was.Size)
			}
			return held
		case OpChmod, OpSetfacl:
			if had && (!has || now.Mode != was.Mode || now.Xattrs != was.Xattrs) {
				return bad("the mode or ACL of %s changed (%v, was %v)", p, now.Mode, was.Mode)
			}
			return held
		case OpChown:
			if had && (!has || now.UID != was.UID || now.GID != was.GID) {
				return bad("the owner of %s changed (%d:%d, was %d:%d)", p, now.UID, now.GID, was.UID, was.GID)
			}
			return held
		case OpSetxattr:
			if had && (!has || now.Xattrs != was.Xattrs) {
				return bad("the xattrs of %s changed", p)
			}
			return held
		case OpRaceSymlinkWrite:
			if had && (!has || now.Size != was.Size || now.Sum != was.Sum) {
				return bad("the target %s was written through the link (%d bytes, was %d)", p, now.Size, was.Size)
			}
			return held
		}
	}
	// The kernel allowed: the action's effect is in the tree.
	missing := func(format string, a ...any) Effect {
		return Effect{Class: EffectMissing, Detail: "the action succeeded but " + fmt.Sprintf(format, a...)}
	}
	switch c.Op {
	case OpCreate, OpCreat:
		if !has || !now.Mode.IsRegular() {
			return missing("no file %s exists", p)
		}
	case OpMkdir:
		if !has || !now.Mode.IsDir() {
			return missing("no directory %s exists", p)
		}
	case OpSymlink:
		if !has || now.Link != c.Dest {
			return missing("no symlink %s to %s exists", p, c.Dest)
		}
	case OpLink:
		if _, dHas := after[moved(d, moves)]; !dHas {
			return missing("the new name %s does not exist", d)
		}
	case OpUnlink, OpRmdir:
		if has {
			return missing("%s still exists", p)
		}
	case OpExchange:
		// Each name holds what the other held.
		dWas := before[d]
		dNow, dHas := after[moved(d, moves)]
		if !has || !dHas || !same(now, dWas) || !same(dNow, was) {
			return missing("%s and %s were not exchanged", p, d)
		}
	case OpRename:
		if _, dHas := after[moved(d, moves)]; !dHas {
			return missing("the destination %s does not exist", d)
		}
		if has && p != d && !refilled(p, moves) {
			return missing("the source %s still exists", p)
		}
	case OpTruncate, OpOpenTrunc:
		if !has || now.Size != 0 {
			return missing("%s is not empty", p)
		}
	case OpChmod:
		if !has || now.Mode.Perm() != 0o600 {
			return missing("%s's mode is not 0600", p)
		}
	case OpSetfacl:
		if !has || now.Mode.Perm() != 0o640 {
			return missing("%s's mode is not the ACL's 0640", p)
		}
	case OpSetxattr:
		if !has || now.Xattrs == "" {
			return missing("%s has no user xattr", p)
		}
	case OpMknod:
		if !has || now.Mode.Type() != fs.ModeNamedPipe {
			return missing("no FIFO %s exists", p)
		}
	case OpRaceSymlinkWrite:
		if !has || now.Size == was.Size {
			return missing("the target %s did not grow", p)
		}
	}
	return held
}
