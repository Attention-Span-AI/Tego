// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// mount is one row of /proc/self/mountinfo the compile print needs: the mount point, the filesystem type, and the
// device (maj:min) and root within it a bind's exposure is judged by (bindExposed); and, for MountOf, the source
// (unescaped) and the super options (as the table spells them: a value's escapes are undone after the split on ',').
type mount struct {
	point  string
	fstype string
	dev    string
	root   string
	source string
	super  string
}

// mountTable answers "which mount holds this path" by longest-prefix match.
type mountTable struct {
	mounts []mount // sorted by descending mount point length
	// probed says a mount table was asked for, where a disabled probe (WithMountInfo("")) has no mount facts by the
	// caller's choice. A probed table that holds no mount of a path, one that could not be read among them, cannot
	// say where the path lies in its filesystem.
	probed bool
}

// loadMountTable parses a mountinfo file; a missing or unreadable file
// yields an empty table (the print then shows no mount metadata) and the
// error for the caller to warn on.
func loadMountTable(path string) (*mountTable, error) {
	t := &mountTable{}
	if path == "" {
		return t, nil
	}
	t.probed = true
	f, err := os.Open(path)
	if err != nil {
		return t, fmt.Errorf("mountinfo: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if m, ok := parseMountLine(sc.Text()); ok {
			t.mounts = append(t.mounts, m)
		}
	}
	if err := sc.Err(); err != nil {
		t.mounts = nil // a table read in part shows nothing reliable
		return t, fmt.Errorf("mountinfo: %w", err)
	}
	t.order()
	return t, nil
}

// order puts the rows in lookup's order, longest mount point first. Mounts stacked on one point are listed bottom
// first, and the last is the one a path there reaches: the rows are reversed before the stable sort so it comes first
// among its point's, where lookup takes it.
func (t *mountTable) order() {
	slices.Reverse(t.mounts)
	sort.SliceStable(t.mounts, func(i, j int) bool { return len(t.mounts[i].point) > len(t.mounts[j].point) })
}

// FileMount is what a mountinfo table shows of the mount holding a path and of the other names it gives the path's file
// or tree (MountOf; ADR 0064 D2: the harness hook's grant holds every name of the binary to the write entries).
type FileMount struct {
	// Held says the table shows a mount holding the path. When it does not, every other field is zero and says
	// nothing: the path's place within its filesystem is unknown, so no bind the table shows can be matched to it
	// (a chroot whose root is no mount point skips the mount above it, yet lists the binds beneath its root). A caller
	// that must see every name treats such a path as one whose names it cannot
	// list.
	Held bool
	// Aliases are the other places the table shows the path: a bind mount of a directory above it, or of its whole
	// filesystem, elsewhere.
	Aliases []string
	// Beneath are the places the table shows a directory strictly beneath the path, mounted elsewhere: a bind of
	// part of the tree at p. A file has none.
	Beneath []string
	// Layers are the layer directories of the overlay holding the path, as its mount options spell them (upperdir,
	// workdir, each lowerdir, lowerdir+ and datadir+): the files whose contents the overlay shows.
	Layers []string
	// Unmapped names a stacking filesystem holding the path whose layers the table does not name (a FUSE mirror, an
	// eCryptfs, aufs or shiftfs mount, or an overlay whose options name a relative layer or none): what the
	// filesystem shows is another file's content by a name no table lists. "" when there is none.
	Unmapped string
	// Device and Source are the holding mount's device (maj:min) and source field, unescaped: where an image or a
	// block device beneath the filesystem is found.
	Device, Source string
}

// MountOf is what a mountinfo table shows of the mount holding p, a clean absolute path where it resolves, and of
// p's other names. p's place within its filesystem is the root of the mount holding it joined with its path below that
// mount's point; every other mount of the same device whose root lies at or above that place shows p below its own
// point (Aliases), and one whose root lies strictly beneath it shows part of p's tree at its point (Beneath). Lines are
// parsed as parseMountLine does. Hard links are names no table shows (st_nlink counts them), and so are names a
// filesystem's own source gives (a loop device's backing file, a second superblock of one network export).
func MountOf(mountinfo []byte, p string) FileMount {
	t := &mountTable{}
	for line := range strings.SplitSeq(string(mountinfo), "\n") {
		if m, ok := parseMountLine(line); ok {
			t.mounts = append(t.mounts, m)
		}
	}
	t.order()
	m, _, ok := t.lookup(p)
	if !ok || m.dev == "" {
		return FileMount{}
	}
	fm := FileMount{Held: true, Device: m.dev, Source: m.source}
	fm.Layers, fm.Unmapped = stackLayers(m.fstype, m.super)
	place := filepath.Join(m.root, strings.TrimPrefix(p, m.point))
	for _, n := range t.mounts {
		if n.dev != m.dev || (n.point == m.point && n.root == m.root) {
			continue
		}
		switch {
		case isAncestorOrSelf(n.root, place):
			if alias := filepath.Join(n.point, strings.TrimPrefix(place, n.root)); alias != p && !slices.Contains(fm.Aliases, alias) {
				fm.Aliases = append(fm.Aliases, alias)
			}
		case isAncestorOrSelf(place, n.root) && !slices.Contains(fm.Beneath, n.point):
			fm.Beneath = append(fm.Beneath, n.point)
		}
	}
	return fm
}

// stackLayers is the layer directories of a stacking filesystem of type fstype with super options super, or the reason
// its layers cannot be named. An overlay names its layers in its options, each escaped as seq_show_option escapes a
// value (octal for ',', '=', space, tab, newline and backslash): lowerdir is a ':' list ("\:" a literal colon, "::"
// before data-only layers), lowerdir+ and datadir+ one layer each (Linux 6.7 on); a relative layer cannot be placed.
// FUSE, eCryptfs, aufs and shiftfs show another tree's files by names their options do not give.
func stackLayers(fstype, super string) (layers []string, unmapped string) {
	switch {
	case fstype == "fuse" || fstype == "fuseblk" || strings.HasPrefix(fstype, "fuse.") ||
		fstype == "ecryptfs" || fstype == "aufs" || fstype == "shiftfs":
		return nil, fstype
	case fstype != "overlay":
		return nil, ""
	}
	lowers := 0
	for opt := range strings.SplitSeq(super, ",") {
		key, val, ok := strings.Cut(opt, "=")
		if !ok {
			continue
		}
		var dirs []string
		switch key {
		case "lowerdir":
			dirs = splitLowerdir(unescapeMount(val))
			lowers += len(dirs)
		case "lowerdir+", "datadir+":
			dirs = []string{unescapeMount(val)}
			lowers++
		case "upperdir", "workdir":
			dirs = []string{unescapeMount(val)}
		}
		for _, d := range dirs {
			if !filepath.IsAbs(d) {
				return nil, "overlay (a layer " + strconv.Quote(d) + " it cannot place)"
			}
			layers = append(layers, filepath.Clean(d))
		}
	}
	if lowers == 0 {
		return nil, "overlay (no lower layer named in its options)"
	}
	return layers, ""
}

// splitLowerdir splits an overlay lowerdir list as overlayfs does: on its unescaped colons, a backslash keeping the
// byte after it ("\:" a colon); it drops the empty element "::" leaves before data-only layers.
func splitLowerdir(s string) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			b.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			if b.Len() > 0 {
				out = append(out, b.String())
			}
			b.Reset()
		default:
			b.WriteByte(s[i])
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// parseMountLine reads "id parent maj:min root mountpoint opts... - fstype src super". The kernel separates
// fields with a space and escapes only space, tab, newline and backslash in a path, so a field is split on
// spaces alone: strings.Fields also split on \v, \r and U+00A0, which a mount point may hold unescaped, and
// read such a mount point as two fields.
func parseMountLine(line string) (mount, bool) {
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' })
	if len(fields) < 7 {
		return mount{}, false
	}
	// The separator follows the mount options (field 5) and any optional fields; a root or mount point that
	// is "-" itself comes before it and is not the separator.
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(fields) {
		return mount{}, false
	}
	m := mount{point: unescapeMount(fields[4]), fstype: fields[sep+1], dev: fields[2], root: unescapeMount(fields[3])}
	if sep+2 < len(fields) {
		m.source = unescapeMount(fields[sep+2])
	}
	if sep+3 < len(fields) {
		m.super = fields[sep+3]
	}
	return m, true
}

// MountPoints lists the mount point (field 5, unescaped) of every well-formed line of a mountinfo table, in
// table order, parsed as parseMountLine parses a line: fields split on spaces alone, a line without the "-"
// separator skipped.
func MountPoints(mountinfo []byte) []string {
	var out []string
	for line := range strings.SplitSeq(string(mountinfo), "\n") {
		if m, ok := parseMountLine(line); ok {
			out = append(out, m.point)
		}
	}
	return out
}

// unescapeMount decodes the \040-style octal escapes mountinfo uses.
func unescapeMount(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// lookup returns the mount holding path and whether path is the mount point itself.
func (t *mountTable) lookup(path string) (m mount, isPoint bool, ok bool) {
	for _, m := range t.mounts {
		if path == m.point {
			return m, true, true
		}
		if m.point == "/" || strings.HasPrefix(path, m.point+"/") {
			return m, false, true
		}
	}
	return mount{}, false, false
}

// bindExposed reports whether the table shows a directory at or beneath scope (a clean absolute path) mounted at a
// point outside it (ADR 0043 D6 (f)): a file there is reached without passing scope, so the kernel's climb from it
// never meets the scope's row. The scope's place within its filesystem is its mount's root joined with its path
// below the mount point; another mount of that device whose root lies at or beneath that place, mounted outside
// scope, exposes it. A probed table that holds no mount of the scope (one that could not be read, or a chroot's, which
// skips the mount above a root that is no mount point) cannot place it, so it cannot show that nothing exposes it:
// the scope counts as exposed, which keeps its rows. A disabled probe exposes
// nothing.
func (t *mountTable) bindExposed(scope string) bool {
	if t == nil || !t.probed {
		return false
	}
	m, _, ok := t.lookup(scope)
	if !ok || m.dev == "" {
		return true
	}
	place := filepath.Join(m.root, strings.TrimPrefix(scope, m.point))
	for _, n := range t.mounts {
		if n.dev != m.dev || (n.point == m.point && n.root == m.root) || isAncestorOrSelf(scope, n.point) {
			continue
		}
		if isAncestorOrSelf(place, n.root) {
			return true
		}
	}
	return false
}

// nlinkOf returns st_nlink of an Lstat result, 0 when unavailable.
func nlinkOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink) // st_nlink is a uint32 on some architectures
	}
	return 0
}

// deviceOf returns st_dev of an Lstat result, 0 when unavailable.
func deviceOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}
