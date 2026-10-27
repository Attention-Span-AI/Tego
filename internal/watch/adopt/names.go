// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Whether the name /proc gives a held file is a path of tego's own mount namespace (FD.Unnamed, Mapping.Unnamed),
// and by which other paths of that namespace the same file is reached (FD.Aliases, Mapping.Aliases).
//
// /proc/<pid>/fd/<n> and smaps name a file by d_path from the reader's root, through the mount the file was opened
// through. When that mount is one of tego's own namespace (a line of tego's /proc/self/mountinfo, which lists only
// the mounts under tego's root), the name is the file's path there, a holder in a chroot included. When it is not,
// the name stops at that mount's root: a detached clone (open_tree OPEN_TREE_CLONE) of $HOME or a bind of it that was
// lazily unmounted names ~/.ssh/id_ed25519 "/.ssh/id_ed25519", which no rule names, while the decision plane decides
// by the dentries (bpf/decide.bpf.c tego_walk_step looks up each one's inode row before it crosses at the mount's
// root) and refuses a read of the key through either. Such a file is Unnamed: the count cannot ask the rows about it
// and says so. So is one whose mount cannot be read (no STATX_MNT_ID, a mapping's
// map_files entry tego may not follow), and one whose name, not deleted, now leads to another file or to none.
//
// A file whose mount is tego's may still be reached through another mount of the same filesystem (a bind of a
// directory above it): the plane's walk meets every directory between the file and its mount's root, which a rule may
// name by its path through that other mount, while the rows asked by the name alone would not see it. Aliases are
// those paths, one per other mount of tego's namespace that shows the file's directory (the same device, a root at
// or above the file's place in its filesystem), so the count asks the rows about each (and, for a hard link, by the
// inode: FD.ID) and, of the files /proc lists, the count can be high, never low. Past maxAliases the file is Unnamed.
//
// Rejected: comparing only the name's (dev, ino) with the held file's, which leaves a deleted file through a
// detached mount (no name to stat) uncounted, and on btrfs compares a stat's subvolume device with the smaps line's
// superblock device; and counting every file through a mount other than its filesystem's first, which would make a
// btrfs /home subvolume, mounted beside /, an unread process in every adoption.

// maxAliases bounds the other paths Aliases gives one file.
const maxAliases = 16

// ownMountinfo is tego's own mount table: the names it compares are resolved by tego's own syscalls in its own
// namespace, whatever /proc root an FS reads the holder from.
const ownMountinfo = "/proc/self/mountinfo"

// mountEntry is one mount of tego's namespace: its filesystem's device, the directory of that filesystem it shows
// (root) and where (at).
type mountEntry struct {
	dev      devID
	root, at string
}

// mountTable is tego's namespace's mounts by mount id (mountinfo's first field, statx's stx_mnt_id).
type mountTable map[uint64]mountEntry

// readOwnMounts reads tego's own mount table.
func readOwnMounts() (mountTable, error) {
	b, err := os.ReadFile(ownMountinfo)
	if err != nil {
		return nil, err
	}
	return parseMountinfo(b)
}

// parseMountinfo reads a /proc/<pid>/mountinfo: per line, the mount id, the parent's id, major:minor (in decimal),
// the root and the mount point (octal-escaped).
func parseMountinfo(b []byte) (mountTable, error) {
	out := mountTable{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		id, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return nil, errors.New("mountinfo: a mount id " + strconv.Quote(f[0]))
		}
		dev, ok := parseDev(f[2], 10)
		if !ok {
			return nil, errors.New("mountinfo: a device " + strconv.Quote(f[2]))
		}
		out[id] = mountEntry{dev: dev, root: unescapeMountinfo(f[3]), at: unescapeMountinfo(f[4])}
	}
	if len(out) == 0 {
		return nil, errors.New("mountinfo: no mount")
	}
	return out, nil
}

// unescapeMountinfo undoes mountinfo's escaping of a space, tab, newline and backslash as \ and three octal digits.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// heldID is a held file as a statx through /proc reads it: its device (st_dev), inode and mount id, and whether the
// kernel gave the mount id (STATX_MNT_ID, Linux 5.8).
type heldID struct {
	dev, ino, mnt uint64
	mntKnown      bool
}

// file is the held file's device and inode as a FileID.
func (h heldID) file() FileID { return FileID{Dev: h.dev, Ino: h.ino} }

// statHeld statx-es path, following a /proc magic link to the file it holds, for its device, inode and mount id.
func statHeld(path string) (heldID, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_SYNC_AS_STAT, unix.STATX_INO|unix.STATX_MNT_ID, &st); err != nil {
		return heldID{}, err
	}
	return heldID{dev: unix.Mkdev(st.Dev_major, st.Dev_minor), ino: st.Ino, mnt: st.Mnt_id,
		mntKnown: st.Mask&unix.STATX_MNT_ID != 0 && st.Mask&unix.STATX_INO != 0}, nil
}

// naming is what namer.name says of one held file.
type naming struct {
	unnamed bool
	aliases []string
	// id is the file's device and inode, when idKnown (FS.Maps sets them from its statx; the namer does not).
	id      FileID
	idKnown bool
}

// namer answers, for the files of one listing, whether a name is a path of tego's namespace and its aliases there.
type namer struct {
	mounts mountTable
	// broken: the mount table could not be read, so every file is unnamed.
	broken bool
	seen   map[namingKey]naming
}

type namingKey struct {
	id      heldID
	path    string
	deleted bool
}

// newNamer is a namer over the mount table read gives; one it cannot read leaves every file unnamed (fail-closed).
func newNamer(read func() (mountTable, error)) *namer {
	if read == nil {
		return nil
	}
	m, err := read()
	return &namer{mounts: m, broken: err != nil, seen: map[namingKey]naming{}}
}

// name says whether path (deleted: /proc's name for it ended in " (deleted)", stripped) names the file id in tego's
// namespace, and the other paths there that reach it. A nil namer (an FS built without a mount table) names every
// file as itself.
func (n *namer) name(path string, deleted bool, id heldID) naming {
	if n == nil {
		return naming{}
	}
	if n.broken {
		return naming{unnamed: true}
	}
	k := namingKey{id, path, deleted}
	if v, ok := n.seen[k]; ok {
		return v
	}
	v := n.decide(path, deleted, id)
	n.seen[k] = v
	return v
}

func (n *namer) decide(path string, deleted bool, id heldID) naming {
	m, ok := n.mounts[id.mnt]
	if !id.mntKnown || !ok || !filepath.IsAbs(path) {
		return naming{unnamed: true} // a mount of no place in tego's namespace: a detached or lazily unmounted one
	}
	if !deleted {
		// The name is the file's place as /proc read it; one that now leads elsewhere (renamed over, a mount laid on
		// it since) is no name of the file tego can ask the rows about.
		var st unix.Statx_t
		if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_SYNC_AS_STAT, unix.STATX_INO, &st); err != nil ||
			unix.Mkdev(st.Dev_major, st.Dev_minor) != id.dev || st.Ino != id.ino {
			return naming{unnamed: true}
		}
	}
	rel, ok := beneath(m.at, path)
	if !ok {
		return naming{unnamed: true}
	}
	place := filepath.Join(m.root, rel) // the file's place in its filesystem
	var aliases []string
	for mid, o := range n.mounts {
		if mid == id.mnt || o.dev != m.dev {
			continue
		}
		r, ok := beneath(o.root, place)
		if !ok {
			continue
		}
		if a := filepath.Join(o.at, r); a != path && !slices.Contains(aliases, a) {
			if len(aliases) == maxAliases {
				return naming{unnamed: true}
			}
			aliases = append(aliases, a)
		}
	}
	slices.Sort(aliases)
	return naming{aliases: aliases}
}

// beneath is p relative to dir ("." for dir itself) when p is dir or beneath it.
func beneath(dir, p string) (string, bool) {
	switch {
	case p == dir:
		return ".", true
	case dir == "/":
		return strings.TrimPrefix(p, "/"), strings.HasPrefix(p, "/")
	case strings.HasPrefix(p, dir+"/"):
		return p[len(dir)+1:], true
	}
	return "", false
}
