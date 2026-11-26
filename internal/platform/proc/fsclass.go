// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Which filesystem a location is on, from this process's own mount table (ADR 0144, "A local location is a busy disk,
// not a stuck mount"). The question is whether a check of the location can stop answering because something outside
// this computer went away (a server, a network, a user-space process): then a wait for it has no end of its own. A
// filesystem on this computer's own storage always answers in the end, only slowly when its disk is busy.
//
// The answer is read from /proc/self/mountinfo and never from the location: no statfs, stat or open of the path is
// made, because that call is the one that could hang. The mount is the one with the longest mount point that is the
// path or one of its parent directories, which is also right for a path that does not exist yet, for a bind mount
// (mountinfo names the type of the filesystem underneath) and for nested mounts. Anything this file cannot say is the
// class that may stop answering: an unreadable or unparsable table, a type it does not know, a path that is not
// absolute, an overlay whose layers cannot all be shown to be local.

// Mount is one line of /proc/self/mountinfo, with the octal escapes the kernel writes (\040 for a space, \011, \012,
// \134 for a backslash) undone.
type Mount struct {
	Point  string // where it is mounted, relative to this process's root
	Type   string // the filesystem type, "ext4", "nfs4", "fuse.sshfs"
	Source string // the device or remote it was mounted from
	Super  string // the superblock options, "rw,lowerdir=..." for an overlay
}

// ParseMountInfo decodes the text of /proc/self/mountinfo. A line it cannot decode (no " - " separator, too few
// fields) is left out, never an error: the lines that remain are still true, and a path that no remaining line covers
// is classed as one that may stop answering.
func ParseMountInfo(data []byte) []Mount {
	var out []Mount
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, " ")
		dash := -1
		for i := 6; i < len(fields); i++ { // six fixed fields, then the optional ones, then "-"
			if fields[i] == "-" {
				dash = i
				break
			}
		}
		if dash < 0 || len(fields) < dash+3 {
			continue
		}
		point, ok := unescapeMount(fields[4])
		if !ok || !filepath.IsAbs(point) {
			continue
		}
		m := Mount{Point: filepath.Clean(point), Type: fields[dash+1]}
		m.Source, _ = unescapeMount(fields[dash+2])
		if dash+3 < len(fields) {
			m.Super = strings.Join(fields[dash+3:], " ")
		}
		out = append(out, m)
	}
	return out
}

// unescapeMount undoes the kernel's octal escapes (a backslash and three octal digits). A backslash that does not
// start one is malformed.
func unescapeMount(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", false
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), true
}

// maxMountInfo is the most of /proc/self/mountinfo that is read: 2 MiB, about fourteen thousand mounts, many times what a
// machine or a container host has. A larger table is not read to its end (a request must not pay for it) and is the
// class that may stop answering.
const maxMountInfo = 2 << 20

// ErrMountInfoTooLarge is the refusal to classify by a mount table larger than maxMountInfo.
var ErrMountInfoTooLarge = errors.New("the mount table is too large to classify by")

// ReadMountInfo reads this process's mount table. A read of /proc/self/mountinfo is the kernel listing this process's
// own mount namespace from memory: it never calls into a filesystem, so it cannot wait for a mount that does not answer,
// and it is the one call of this classification made outside a helper. Its size is bounded (maxMountInfo).
func ReadMountInfo() ([]Mount, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readMountInfo(f, maxMountInfo)
}

func readMountInfo(r io.Reader, limit int64) ([]Mount, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrMountInfoTooLarge
	}
	return ParseMountInfo(data), nil
}

// mountIndex is the mounts of a table by mount point; of two lines at one point the later one, which is stacked over the
// other and is the one a path under it is on, is kept.
type mountIndex map[string]Mount

func indexMounts(mounts []Mount) mountIndex {
	ix := make(mountIndex, len(mounts))
	for _, m := range mounts {
		ix[m.Point] = m
	}
	return ix
}

// of is the mount a path is on: the longest mount point that is the path or a parent directory of it, found by
// walking up from the path, so a table of any size costs the depth of the path. path must be clean and absolute.
func (ix mountIndex) of(path string) (Mount, bool) {
	for p := path; ; p = filepath.Dir(p) {
		if m, ok := ix[p]; ok {
			return m, true
		}
		if p == "/" || p == "." {
			return Mount{}, false
		}
	}
}

// pseudoLocal are the filesystems the kernel keeps in memory or in its own control files: nothing outside this
// computer is behind them.
var pseudoLocal = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "securityfs": true,
	"debugfs": true, "tracefs": true, "pstore": true, "bpf": true, "mqueue": true, "configfs": true, "efivarfs": true,
	"binfmt_misc": true, "nsfs": true, "fusectl": true, "selinuxfs": true, "rpc_pipefs": true, "nfsd": true,
	"tmpfs": true, "ramfs": true, "hugetlbfs": true,
}

// onDisk are the filesystems that live on a block device of this computer. zfs names a dataset, not a device.
var onDisk = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "f2fs": true, "bcachefs": true, "zfs": true,
	"jfs": true, "reiserfs": true, "nilfs2": true,
}

// onImage are the formats usually mounted from a removable medium, a partition or an image: local only when the
// source is a device node (/dev/...), which keeps a mount whose source is something else (a user-space server that
// answers to this type name) in the class that may stop answering.
var onImage = map[string]bool{
	"vfat": true, "msdos": true, "exfat": true, "ntfs3": true, "hfs": true, "hfsplus": true, "udf": true, "iso9660": true,
	"squashfs": true, "erofs": true, "cramfs": true,
}

// mayStop are the types that can stop answering because something outside this computer went away. It adds nothing
// to the rule (a type not known to be local is in the class anyway); it is the list the decision was made against,
// and the one a type must be taken out of before it can be added to the local ones.
var mayStop = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "9p": true, "ceph": true, "afs": true,
	"fuse": true, "fuseblk": true, "autofs": true, "ncpfs": true, "coda": true, "lustre": true, "gfs2": true, "ocfs2": true,
	"glusterfs": true, "orangefs": true, "virtiofs": true, "vboxsf": true, "vmhgfs": true, "ecryptfs": true, "aufs": true,
	"panfs": true, "beegfs": true,
}

// networkBlock names the block devices that are a network behind a device node: ext4 on one is still a mount that can
// stop answering.
func networkBlock(source string) bool {
	for _, p := range []string{"/dev/nbd", "/dev/rbd", "/dev/drbd", "/dev/ublk"} {
		if strings.HasPrefix(source, p) {
			return true
		}
	}
	return false
}

// localType says whether the mount's own filesystem is on this computer's storage, an overlay not counted.
func localType(m Mount) bool {
	t := m.Type
	switch {
	case mayStop[t], t == "fuse", strings.HasPrefix(t, "fuse."):
		return false
	case pseudoLocal[t]:
		return true
	case onDisk[t]:
		return !networkBlock(m.Source)
	case onImage[t]:
		return strings.HasPrefix(m.Source, "/dev/") && !networkBlock(m.Source)
	}
	return false // a type this table does not know
}

// local reports whether path is on a filesystem of this computer's own storage, by mounts as ParseMountInfo gave
// them: the mount is of a local type, or an overlay all of whose layers (lowerdir, upperdir, workdir, in any of the
// spellings of the option) are on a local mount that is not an overlay. An overlay whose layers are not named in its
// options, are not in this table (a container's overlay root names the host's directories) or are on another overlay
// is not shown to be local. path must be absolute; it is cleaned here, never resolved.
func (ix mountIndex) local(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	m, ok := ix.of(filepath.Clean(path))
	if !ok {
		return false
	}
	if m.Type != "overlay" {
		return localType(m)
	}
	layers := overlayLayers(m.Super)
	if len(layers) == 0 {
		return false
	}
	for _, l := range layers {
		lm, ok := ix.of(l)
		if !ok || lm.Type == "overlay" || !localType(lm) {
			return false
		}
	}
	return true
}

// overlayLayers are the directories an overlay is made of, from its superblock options. A layer path that is not
// absolute, or has a character mountinfo cannot show unambiguously (the escaped colon), gives none, which is "not
// shown to be local".
func overlayLayers(super string) []string {
	var out []string
	for _, opt := range strings.Split(super, ",") {
		key, val, ok := strings.Cut(opt, "=")
		if !ok {
			continue
		}
		switch strings.TrimSuffix(key, "+") {
		case "lowerdir", "datadir", "upperdir", "workdir":
		default:
			continue
		}
		val, ok = unescapeMount(val)
		if !ok || strings.Contains(val, `\`) {
			return nil
		}
		// lowerdir=a:b::data is a list; the empty piece is the separator of the data-only layers.
		for _, p := range strings.Split(val, ":") {
			if p == "" {
				continue
			}
			if !filepath.IsAbs(p) {
				return nil
			}
			out = append(out, filepath.Clean(p))
		}
	}
	return out
}

// PathsLocal reads this process's mount table now and reports whether every one of paths is local. It is false for
// no path at all (nothing is known to be local), for a path that is empty or not absolute, and when the table cannot
// be read. Each call reads the table again: a filesystem mounted over a location after an earlier call is seen by
// the next.
func PathsLocal(paths ...string) bool {
	mounts, err := ReadMountInfo()
	if err != nil {
		return false
	}
	return PathsLocalIn(mounts, paths...)
}

// PathsLocalIn is PathsLocal over a table already read.
func PathsLocalIn(mounts []Mount, paths ...string) bool {
	seen := false
	ix := indexMounts(mounts)
	for _, p := range paths {
		if p == "" {
			continue
		}
		if !ix.local(p) {
			return false
		}
		seen = true
	}
	return seen
}
