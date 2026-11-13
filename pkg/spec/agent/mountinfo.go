// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// This file is the one reader of /proc/self/mountinfo for every security decision: compile's (R10, ADR 0059's
// compile-time mount boundary) and a root tier's at run start (ADR 0011, ADR 0025). One acquisition
// (ReadMountSnapshot), one strict record parser (parseMountRecord), one graph check (validateMountGraph) and one
// parsed representation (mountTable, which MountTable carries) serve both. No lenient reader of a table remains.

// mount is one row of a mountinfo table: its id and its parent's (fields 1 and 2, canonical decimal), the mount point
// and the root within its filesystem (decoded once), the filesystem type, the device (maj:min, canonical decimal),
// the source (decoded once), and the super options as the table spells them (a value's escapes are undone after the
// split on ',', in stackLayers).
type mount struct {
	id     string
	parent string
	point  string
	fstype string
	dev    string
	root   string
	source string
	super  string
}

// mountTable is a parsed mount table: its rows and the indexes every question about it is answered from. Which mount
// a path reaches is decided by parent edges and, for the calling process's own table, by statx (lookup), never by the
// printed order of rows or the longest mount point text alone.
type mountTable struct {
	mounts []mount // sorted by descending mount point length
	// A covered mount's child retains its printed point without being reachable.
	mountIDs        map[string]int
	visiblePoints   map[string]int
	uncertainPoints map[string]string // points whose position or visibility cannot be established
	live            bool              // only the calling process's actual mount table can be checked with statx
	// roots holds, per device, the rows of each filesystem root (in mounts order), and sorted each device's roots, so
	// the rows of a device whose root lies at, above or beneath a place are found without a scan of every row.
	roots  map[string]map[string][]int
	sorted map[string][]string
	// err is why a probed table could not be read whole and strictly (unreadable, malformed, past a bound, or
	// changing while it was read): R10's checks by mount identity then cannot show a write entry stays off what
	// they protect.
	err error
	// probed says a mount table was asked for, where a disabled probe (WithMountInfo("")) has no mount facts by the
	// caller's choice. A probed table that holds no mount of a path, one that could not be read among them, cannot
	// say where the path lies in its filesystem.
	probed bool
}

// The bounds of a mount table Tego reads: past any of them the table is refused (ErrMountSnapshot), so a mount
// namespace with a huge table costs a compile or a run start at most this much, and no check decides on part of it.
const (
	maxMountTableBytes = 8 << 20
	maxMountRows       = 32768
	maxMountRowBytes   = 1 << 20
)

// liveMountInfo is the calling process's own table, the one whose rows statx can check.
const liveMountInfo = "/proc/self/mountinfo"

// ErrMountSnapshot is a mount table a security decision cannot rely on: malformed, larger than its bounds, or
// changing while it was read.
var ErrMountSnapshot = errors.New("the mount table cannot be read as one well-formed snapshot")

// loadMountTable reads compile's mount facts (ReadMountSnapshot). A disabled probe (path "") yields an empty table
// that says nothing. Facts that cannot be read whole and strictly yield an empty, probed table carrying the error:
// every R10 check by mount identity then refuses, and bindExposed retains scopes whose lack of aliases cannot be
// established.
func loadMountTable(path string) (*mountTable, error) {
	if path == "" {
		return &mountTable{}, nil
	}
	mt, _, err := ReadMountSnapshot(path)
	if err != nil {
		return &mountTable{probed: true, live: path == liveMountInfo, err: err}, err
	}
	return &mt.t, nil
}

// ReadMountSnapshot reads the mount table at path for a security decision: at most maxMountTableBytes, read twice and
// compared, up to three times, then parsed strictly (parseMountSnapshot). Equal reads detect a change seen while
// reading; they cannot exclude a change and its reversal between the reads, or a change after. It returns the table
// and the bytes it parsed. The table of the calling process (/proc/self/mountinfo) is checked against statx as it is
// indexed and at each lookup.
func ReadMountSnapshot(path string) (*MountTable, []byte, error) {
	read := func() ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return io.ReadAll(io.LimitReader(f, maxMountTableBytes+1))
	}
	for range 3 {
		a, err := read()
		if err != nil {
			return nil, nil, fmt.Errorf("mountinfo: %w", err)
		}
		b, err := read()
		if err != nil {
			return nil, nil, fmt.Errorf("mountinfo: %w", err)
		}
		if !bytes.Equal(a, b) {
			continue
		}
		mt, err := parseMountSnapshot(a, path, path == liveMountInfo)
		if err != nil {
			return nil, nil, err
		}
		return mt, a, nil
	}
	return nil, nil, fmt.Errorf("%w: %s changed while it was read, three times", ErrMountSnapshot, path)
}

// ParseMountTableStrict parses supplied mountinfo bytes as ReadMountSnapshot parses what it reads, without statx
// checks (the bytes need not be the calling process's table). Invalid or oversized input is an error wrapping
// ErrMountSnapshot, never a table with a row left out.
func ParseMountTableStrict(mountinfo []byte) (*MountTable, error) {
	return parseMountSnapshot(mountinfo, "supplied mountinfo", false)
}

// parseMountSnapshot is the one parser. Rows are separated by newline alone; every other byte, a carriage return
// included, stays in its row (mountinfo escapes a newline inside a value and leaves a carriage return literal). The
// byte bound counts the input as given, delimiters and an unterminated last row included. A blank row, a row longer
// than maxMountRowBytes, more than maxMountRows rows, a record parseMountRecord refuses, or a graph
// validateMountGraph refuses refuses the whole table.
func parseMountSnapshot(b []byte, name string, live bool) (*MountTable, error) {
	if len(b) > maxMountTableBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes or %d mounts", ErrMountSnapshot, name, maxMountTableBytes, maxMountRows)
	}
	var mounts []mount
	for rest, n := b, 1; len(rest) > 0; n++ {
		row := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			row, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		if len(row) >= maxMountRowBytes {
			return nil, fmt.Errorf("%w: %s line %d is longer than %d bytes", ErrMountSnapshot, name, n, maxMountRowBytes)
		}
		if len(mounts) >= maxMountRows {
			return nil, fmt.Errorf("%w: %s is larger than %d bytes or %d mounts", ErrMountSnapshot, name, maxMountTableBytes, maxMountRows)
		}
		m, ok := parseMountRecord(string(row))
		if !ok {
			return nil, fmt.Errorf("%w: %s line %d is not a whole mountinfo record", ErrMountSnapshot, name, n)
		}
		mounts = append(mounts, m)
	}
	if err := validateMountGraph(mounts); err != nil {
		return nil, fmt.Errorf("%w (%s)", err, name)
	}
	mt := &MountTable{records: make([]MountRecord, 0, len(mounts))}
	for _, m := range mounts {
		major, minor, _ := mountDevice(m.dev)
		id, _ := strconv.Atoi(m.id)
		mt.records = append(mt.records, MountRecord{ID: id, Point: m.point, Major: major, Minor: minor})
	}
	mt.t = mountTable{mounts: mounts, probed: true, live: live}
	mt.t.order()
	return mt, nil
}

// parseMountRecord reads one complete record, "id parent maj:min root mountpoint opts [optional...] - fstype source
// super", for a security decision. A bad row cannot be skipped: it might be the protected mount. Fields are separated
// by single spaces (an empty field is a malformed row); no field holds a NUL or a tab, which the kernel escapes. The
// separator follows the mount options and the optional fields and is followed by exactly three fields. The ids and the
// device numbers are canonical decimal (no sign, no leading zero; an id is not 0), so one device has one spelling.
// The root and the mount point carry only the escapes the kernel writes in a path (\040 \011 \012 \134) and are
// decoded once; they must be clean absolute paths, except an nsfs root, which names a namespace ("net:[4026532008]")
// and is no place. A canonical absolute root followed by the kernel suffix "//deleted"
// is an unlinked name, never a filesystem-relative alias spelling. The source is decoded once;
// the super options stay as the table spells them.
func parseMountRecord(line string) (mount, bool) {
	fields := strings.Split(line, " ")
	if len(fields) < 10 || strings.ContainsRune(line, 0) {
		return mount{}, false
	}
	for _, f := range fields {
		if f == "" || strings.ContainsAny(f, "\t\n") {
			return mount{}, false
		}
	}
	sep := 6
	for sep < len(fields) && fields[sep] != "-" {
		sep++
	}
	if sep != len(fields)-4 {
		return mount{}, false
	}
	number := func(s string, zero bool) bool {
		n, err := strconv.ParseUint(s, 10, 32)
		return err == nil && (zero || n != 0) && strconv.FormatUint(n, 10) == s
	}
	major, minor, cut := strings.Cut(fields[2], ":")
	if !number(fields[0], false) || !number(fields[1], true) || !cut || !number(major, true) || !number(minor, true) {
		return mount{}, false
	}
	for _, path := range fields[3:5] {
		for i := 0; i < len(path); i++ {
			if path[i] != '\\' {
				continue
			}
			if i+3 >= len(path) {
				return mount{}, false
			}
			switch path[i : i+4] {
			case `\040`, `\011`, `\012`, `\134`:
			default:
				return mount{}, false
			}
			i += 3
		}
	}
	m := mount{id: fields[0], parent: fields[1], dev: fields[2], root: unescapeMount(fields[3]), point: unescapeMount(fields[4]),
		fstype: fields[sep+1], source: unescapeMount(fields[sep+2]), super: fields[sep+3]}
	if !filepath.IsAbs(m.point) || filepath.Clean(m.point) != m.point || strings.ContainsRune(m.root+m.point, 0) {
		return mount{}, false
	}
	// Namespace handles are kernel objects, not filesystem-relative paths. Accept their documented nsfs spelling
	// without treating it as a place.
	rootPath := filepath.IsAbs(m.root) && filepath.Clean(m.root) == m.root
	if m.unlinkedRoot() {
		// A linked path cannot contain two adjacent separators in the kernel's
		// dentry spelling. Only the exact terminal marker after a clean name is
		// unambiguous; never clean a malformed prefix into an accepted name.
		name := strings.TrimSuffix(m.root, "//deleted")
		rootPath = filepath.IsAbs(name) && name != "/" && filepath.Clean(name) == name
	}
	if !rootPath && m.fstype == "nsfs" {
		kind, handle, found := strings.Cut(m.root, ":[")
		rootPath = found && kind != "" && strings.HasSuffix(handle, "]") && number(strings.TrimSuffix(handle, "]"), false)
	}
	if !rootPath {
		return mount{}, false
	}
	return m, true
}

// validateMountGraph refuses a table whose parent edges a lookup cannot follow: ids are unique; exactly one row, at
// /, has no listed parent (or is its own); every other row's parent is listed and mounted at or above the row's
// mount point; and every row reaches that root without a cycle. Rows hidden by later mounts are held to the same
// rules: they still take part in the same-device alias search.
func validateMountGraph(mounts []mount) error {
	byID := make(map[string]int, len(mounts))
	for i, m := range mounts {
		if _, exists := byID[m.id]; exists {
			return fmt.Errorf("%w: duplicate mount id %s", ErrMountSnapshot, m.id)
		}
		byID[m.id] = i
	}
	hasRoot := slices.ContainsFunc(mounts, func(m mount) bool { return m.point == "/" })
	if !hasRoot {
		return fmt.Errorf("%w: Tego is running inside a root that is not a mount point, so the kernel does not show the filesystem under it; make the root a mount point, for example bind the folder onto itself before entering it, or run Tego outside that root", ErrMountSnapshot)
	}
	root := -1
	for i, m := range mounts {
		parent, listed := byID[m.parent]
		if !listed || m.parent == m.id {
			if m.point != "/" || root >= 0 {
				return fmt.Errorf("%w: mount %s does not connect to one root at /", ErrMountSnapshot, m.id)
			}
			root = i
		} else if !isAncestorOrSelf(mounts[parent].point, m.point) {
			return fmt.Errorf("%w: mount %s lies outside its parent %s", ErrMountSnapshot, m.id, m.parent)
		}
	}
	if root < 0 {
		return fmt.Errorf("%w: no root mount", ErrMountSnapshot)
	}
	state := make([]uint8, len(mounts))
	var path []int
	for i := range mounts {
		path = path[:0]
		for cur := i; state[cur] != 2; cur = byID[mounts[cur].parent] {
			if state[cur] == 1 {
				return fmt.Errorf("%w: parent cycle at mount %s", ErrMountSnapshot, mounts[cur].id)
			}
			state[cur] = 1
			path = append(path, cur)
			if cur == root {
				break
			}
		}
		for _, cur := range path {
			state[cur] = 2
		}
	}
	return nil
}

// order indexes a table without treating its printed order as stacking order: rows sorted by descending mount
// point length (the alias search's and the advisory scans' order), visibility by parent edges, and the per-device
// root index.
func (t *mountTable) order() {
	sort.SliceStable(t.mounts, func(i, j int) bool { return len(t.mounts[i].point) > len(t.mounts[j].point) })
	t.indexVisibility()
	t.indexRoots()
}

// indexRoots builds roots and sorted from mounts.
func (t *mountTable) indexRoots() {
	t.roots = map[string]map[string][]int{}
	t.sorted = map[string][]string{}
	for i, m := range t.mounts {
		if m.unlinkedRoot() {
			continue // an old unlinked name establishes no tree alias
		}
		byRoot := t.roots[m.dev]
		if byRoot == nil {
			byRoot = map[string][]int{}
			t.roots[m.dev] = byRoot
		}
		if len(byRoot[m.root]) == 0 {
			t.sorted[m.dev] = append(t.sorted[m.dev], m.root)
		}
		byRoot[m.root] = append(byRoot[m.root], i)
	}
	for _, rs := range t.sorted {
		slices.Sort(rs)
	}
}

// indexVisibility follows parent edges, resolving shorter mountpoints first.
// At one point a mount above another has that mount as its parent. Independent
// chains and cycles establish no top. Multiple tops remain unknown before live
// verification, which also checks rows ancestry would otherwise discard as hidden.
func (t *mountTable) indexVisibility() {
	t.mountIDs = make(map[string]int, len(t.mounts))
	t.visiblePoints = make(map[string]int, len(t.mounts))
	t.uncertainPoints = make(map[string]string)
	groups := make(map[string][]int, len(t.mounts))
	var points []string
	for i, m := range t.mounts {
		t.mountIDs[m.id] = i
		if _, exists := groups[m.point]; !exists {
			points = append(points, m.point)
		}
		groups[m.point] = append(groups[m.point], i)
	}
	omitted := t.lineageRoots()
	state := make([]uint8, len(t.mounts)) // 0 unseen, 1 on this walk, 2 decided
	attached := make([]bool, len(t.mounts))
	invalid := make([]bool, len(t.mounts))
	for _, point := range slices.Backward(points) {
		ancestor, hasAncestor := t.visibleIndex(filepath.Dir(point))
		if point != "/" && t.uncertaintyAt(filepath.Dir(point)) != "" {
			t.uncertainPoints[point] = "its ancestor's mount visibility is unknown"
			continue
		}
		for _, start := range groups[point] {
			if state[start] == 2 {
				continue
			}
			var trail []int
			at, reaches, broken := start, false, false
			for {
				if state[at] == 2 {
					reaches, broken = attached[at], invalid[at]
					break
				}
				if state[at] == 1 {
					broken = true // a parent cycle establishes no position
					break
				}
				state[at] = 1
				trail = append(trail, at)
				m := t.mounts[at]
				parent, exists := t.mountIDs[m.parent]
				if !exists {
					// Only the root row has no listed parent in a table validateMountGraph admits. A table built
					// otherwise (a test's) may omit a parent: a visible ancestor still covers older children attached
					// to that omitted mount.
					reaches = !hasAncestor
					// Distinct omitted parents give no evidence that this
					// row and the visible ancestor share an enclosing mount.
					broken = hasAncestor && omitted[t.mounts[ancestor].id] != m.parent
					break
				}
				if parent == at {
					reaches, broken = point == "/", point != "/"
					break
				}
				if t.mounts[parent].point != point {
					reaches = hasAncestor && parent == ancestor
					// A parent outside the path ancestry is not a hidden mount.
					broken = !isAncestorOrSelf(t.mounts[parent].point, point)
					break
				}
				at = parent
			}
			for _, i := range trail {
				state[i], attached[i], invalid[i] = 2, reaches, broken
			}
		}
		covered := make(map[int]bool, len(groups[point]))
		broken := false
		for _, i := range groups[point] {
			broken = broken || invalid[i]
			if parent, ok := t.mountIDs[t.mounts[i].parent]; ok && parent != i && attached[i] && t.mounts[parent].point == point {
				covered[parent] = true
			}
		}
		var tops []int
		for _, i := range groups[point] {
			if attached[i] && !covered[i] {
				tops = append(tops, i)
			}
		}
		// ADR 0059: live identity cannot clear ambiguous parent relationships.
		// Preserve the read-denial reader's refusal before choosing a live top.
		if len(tops) > 1 {
			t.uncertainPoints[point] = "parent relationships do not establish one visible top"
			continue
		}
		if t.live {
			id, supported, err := liveMountID(point)
			if err != nil {
				t.uncertainPoints[point] = err.Error()
				continue
			}
			if supported {
				verified := -1
				for _, i := range tops {
					if t.mounts[i].id == id {
						verified = i
					}
				}
				if !broken && verified >= 0 {
					t.visiblePoints[point] = verified
					continue
				}
				if !broken && len(tops) == 0 && hasAncestor && t.mounts[ancestor].id == id {
					continue // the live covering ancestor confirms these rows are hidden
				}
				t.uncertainPoints[point] = "live mount identity disagrees with its parent relationships"
				continue
			}
		}
		switch {
		case broken:
			t.uncertainPoints[point] = "parent relationships do not establish one visible top"
		case len(tops) == 1:
			t.visiblePoints[point] = tops[0]
		}
	}
}

// lineageRoots records each parent chain's omitted parent (or self-parented
// root). Memoizing every visited edge keeps partial-chroot checks linear, even
// for deep stacks. A cycle has no established root.
func (t *mountTable) lineageRoots() map[string]string {
	roots := make(map[string]string, len(t.mounts))
	for id := range t.mountIDs {
		if _, done := roots[id]; done {
			continue
		}
		var trail []string
		seen := make(map[string]bool)
		at, end := id, ""
		for {
			if known, done := roots[at]; done {
				end = known
				break
			}
			if seen[at] {
				break
			}
			i, exists := t.mountIDs[at]
			if !exists {
				end = at
				break
			}
			seen[at] = true
			trail = append(trail, at)
			parent := t.mounts[i].parent
			if parent == at {
				end = at
				break
			}
			at = parent
		}
		for _, visited := range trail {
			roots[visited] = end
		}
	}
	return roots
}

// uncertaintyAt is an unknown mount at or above p. It must shadow the known
// ancestor rather than let lookup silently fall back through an ambiguous stack.
func (t *mountTable) uncertaintyAt(p string) string {
	if !filepath.IsAbs(p) {
		return ""
	}
	for p = filepath.Clean(p); ; p = filepath.Dir(p) {
		if why, ok := t.uncertainPoints[p]; ok {
			return fmt.Sprintf("mount visibility at %s is unknown (%s)", p, why)
		}
		if p == "/" {
			return ""
		}
	}
}

// grantUncertainty includes descendants because a recursive grant reaches their
// mounts even when the grant's own holding identity is known.
func (t *mountTable) grantUncertainty(p string) string {
	if why := t.uncertaintyAt(p); why != "" {
		return why
	}
	for _, m := range t.mounts {
		if why, ok := t.uncertainPoints[m.point]; ok && isAncestorOrSelf(p, m.point) {
			return fmt.Sprintf("mount visibility at %s is unknown (%s)", m.point, why)
		}
	}
	return ""
}

// visible reports whether this row is reached at its mountpoint, including its
// parent lineage. Unknown rows are not visible; callers must preserve that
// uncertainty rather than treat those rows as verified hidden mounts.
func (t *mountTable) visible(m mount) bool {
	i, ok := t.visiblePoints[m.point]
	return ok && t.mounts[i] == m
}

// visibleIndex follows path components through the index, never scanning all
// mount rows for each absent-layer candidate.
func (t *mountTable) visibleIndex(p string) (int, bool) {
	if !filepath.IsAbs(p) {
		return 0, false
	}
	for p = filepath.Clean(p); ; p = filepath.Dir(p) {
		if _, unknown := t.uncertainPoints[p]; unknown {
			return 0, false
		}
		if i, ok := t.visiblePoints[p]; ok {
			return i, true
		}
		if p == "/" {
			return 0, false
		}
	}
}

// lookup is the only holding-mount lookup. Hidden child rows cannot supply a
// device. With the live table, statx verifies the result where the kernel supports
// mount IDs; a mismatch or inaccessible path leaves identity unknown.
func (t *mountTable) lookup(p string) (m mount, isPoint bool, ok bool) {
	i, ok := t.visibleIndex(p)
	if !ok {
		return mount{}, false, false
	}
	m = t.mounts[i]
	if t.live {
		id, supported, err := liveMountID(p)
		if err != nil || supported && id != m.id {
			return mount{}, false, false
		}
	}
	return m, filepath.Clean(p) == m.point, true
}

var statLiveMount = unix.Statx

// liveMountID preserves read failures. Only kernels lacking mount-ID support
// fall back to ancestry. Missing paths use the first existing parent, on which
// the future entry would be created.
func liveMountID(p string) (id string, supported bool, err error) {
	for probe := filepath.Clean(p); ; probe = filepath.Dir(probe) {
		var st unix.Statx_t
		err = statLiveMount(unix.AT_FDCWD, probe, unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &st)
		switch {
		case err == nil:
			return strconv.FormatUint(st.Mnt_id, 10), st.Mask&unix.STATX_MNT_ID != 0, nil
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
			return "", false, nil
		case (errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR)) && probe != "/":
			continue
		default:
			return "", false, err
		}
	}
}

// FileMount is what a mountinfo table shows of the mount holding a path and of the other names it gives the path's file
// or tree (MountTable.Of; ADR 0064 D2: the harness hook's grant holds every name of the binary to the write entries).
type FileMount struct {
	// Held says the table shows a mount holding the path. When it does not, every other field is zero and says
	// nothing: the path's place within its filesystem is unknown, so no bind the table shows can be matched to it. A
	// caller that must see every name treats such a path as one whose names it cannot list.
	Held bool
	// Aliases are the other places the table shows the path on the same filesystem instance: a bind mount of a
	// directory above it, or of its whole filesystem, elsewhere. Every row of the device counts, a hidden one or one
	// whose visibility is unknown included, except former unlinked names, which establish no path aliases.
	// No alias is dropped because its name resolves elsewhere: a security
	// caller walks and checks each one, and an alias that is not reachable only refuses more. Different instances
	// showing the same data are not recognised.
	Aliases []string
	// Beneath are the places the table shows a directory strictly beneath the path, mounted elsewhere: a bind of
	// part of the tree at p. A file has none.
	Beneath []string
	// Layers are the layer directories of the overlay holding the path, as its mount options spell them (upperdir,
	// workdir, each lowerdir, lowerdir+ and datadir+): the files whose contents the overlay shows.
	Layers []string
	// Unmapped names a stacking filesystem holding the path whose layers the table does not name (a FUSE mirror, an
	// eCryptfs, aufs or shiftfs mount, or an overlay whose options name a relative layer, a parent component, an
	// ambiguous upper or work spelling, or no lower): what the filesystem shows is another file's content by a name no
	// table lists, or a mount with an unlinked root whose former name places no backing. "" when there is none.
	Unmapped string
	// Device and Source are the holding mount's device (maj:min) and source field, unescaped: where an image or a
	// block device beneath the filesystem is found.
	Device, Source string
}

// fileMount reports the mount holding p, a clean absolute path where it resolves (lookup), and p's other names. Its
// place within the filesystem is the holding mount's root joined with its path below that mount's point. Every other
// row of the same device whose root lies at or above that place shows p below its own point (Aliases); one whose root
// lies strictly beneath it shows part of p's tree at its point (Beneath). The rows are found through the root index:
// one lookup per directory of the place, and one run of the device's sorted roots. Hard links are names no table
// shows (st_nlink counts them); unlinked roots have no usable former name, and compile checks reached regular
// roots separately by file identity. So are names a filesystem's own source gives (a loop device's backing file, a
// second superblock of one network export).
func (t *mountTable) fileMount(p string) FileMount {
	m, _, ok := t.lookup(p)
	if !ok || m.dev == "" || !filepath.IsAbs(m.root) {
		return FileMount{}
	}
	fm := FileMount{Held: true, Device: m.dev, Source: m.source}
	if m.unlinkedRoot() {
		fm.Unmapped = unlinkedRootBacking
		return fm
	}
	fm.Layers, fm.Unmapped = stackLayers(m.fstype, m.super)
	place := filepath.Join(m.root, strings.TrimPrefix(p, m.point))
	byRoot := t.roots[m.dev]
	var rows []int
	for a := place; ; a = filepath.Dir(a) {
		rows = append(rows, byRoot[a]...)
		if a == "/" || a == "." {
			break
		}
	}
	roots := t.sorted[m.dev]
	prefix := strings.TrimSuffix(place, "/") + "/"
	start, _ := slices.BinarySearch(roots, prefix)
	for i := start; i < len(roots) && strings.HasPrefix(roots[i], prefix); i++ {
		rows = append(rows, byRoot[roots[i]]...)
	}
	slices.Sort(rows)
	for _, i := range slices.Compact(rows) {
		n := t.mounts[i]
		if n.point == m.point && n.root == m.root {
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

// MountTable is a mount table read and parsed once (ReadMountSnapshot, ParseMountTableStrict) for asking many
// questions of it: the fanotify listener asks Of's question of every spelling of every deny_read entry at Prepare,
// and the built-in .env scan can write 50,000 of them. It carries the same parsed representation compile uses.
type MountTable struct {
	t mountTable
	// records retains the source order independently of lookup's ordering.
	records []MountRecord
}

// MountRecord is a mount's identity, mount point and device from a parsed mount table.
type MountRecord struct {
	ID           int
	Point        string
	Major, Minor uint32
}

// Records returns an independent copy of the table's mounts in source order.
func (mt *MountTable) Records() []MountRecord {
	return slices.Clone(mt.records)
}

// Points lists the table's mount points in source order, decoded once: what a caller deciding by mount points reads
// (the listener's submount marks, the plane's mount rows).
func (mt *MountTable) Points() []string {
	out := make([]string, len(mt.records))
	for i, r := range mt.records {
		out[i] = r.Point
	}
	return out
}

// NetworkMountWarnings reports exact repeated source strings on known network filesystems with different device
// identities. This does not establish that their content is the same: separate filesystem instances are outside
// the alias search. A warning lets the host owner inspect the two paths without refusing an unproven alias.
func (mt *MountTable) NetworkMountWarnings() []string { return mt.t.networkMountWarnings() }

func (t *mountTable) networkMountWarnings() []string {
	first := map[string]mount{}
	warned := map[string]bool{}
	var warnings []string
	for _, m := range t.mounts {
		switch m.fstype {
		case "nfs", "nfs4", "cifs", "smb3", "ceph", "afs":
		default:
			continue
		}
		if m.source == "" || m.source == "none" {
			continue
		}
		a, seen := first[m.source]
		if !seen {
			first[m.source] = m
			continue
		}
		if m.dev == a.dev || warned[m.source] {
			continue
		}
		warned[m.source] = true
		warnings = append(warnings, fmt.Sprintf("mounts %q and %q show the same network source string %q on "+
			"different filesystem instances; this alone does not establish shared content; other views on a different "+
			"filesystem instance are not recognised at any tier; if they show the same data, deny the other path too "+
			"or do not mount the same export twice where agents can read it", a.point, m.point, m.source))
	}
	return warnings
}

// MountID is the id of the mount p reaches (lookup), as statx(2)'s STATX_MNT_ID and mountinfo's first field number it.
func (mt *MountTable) MountID(p string) (int, bool) {
	m, _, ok := mt.t.lookup(p)
	if !ok {
		return 0, false
	}
	id, err := strconv.Atoi(m.id)
	return id, err == nil
}

// Device is the device (major, minor) of the filesystem p reaches, in stat(2)'s encoding as unix.Mkdev builds it.
func (mt *MountTable) Device(p string) (major, minor uint32, ok bool) {
	m, _, held := mt.t.lookup(p)
	if !held {
		return 0, 0, false
	}
	return mountDevice(m.dev)
}

// Of reports the mount holding p and p's other names (fileMount).
func (mt *MountTable) Of(p string) FileMount { return mt.t.fileMount(p) }

// TreeAliases lists the places other than p, a clean absolute path, where the same filesystem instance shows p's tree
// or a part of it, each a place whose whole subtree is p's content: Of(p)'s Aliases (a bind of p, of a directory above
// it or of its whole filesystem, elsewhere) and Beneath (a bind of a directory or of one file inside p's tree,
// elsewhere). ok is false when the table holds no mount of p it can place, or an unlinked directory or unreadable
// root on the same device could expose part of its tree. A caller that must hold p under every name fails closed
// on that uncertainty. A name the table lists twice is listed once.
//
// A filesystem mounted beneath p is not p's content where it is mounted elsewhere too: a rule on p covers it beneath
// p by path (SEMANTICS §2), and its other places are its own, as the decision plane's walk finds them (a bind of the
// root filesystem beneath p would otherwise make "/" an alias of p). A mount stacked over a part of a listed place
// hides that part, and the place still names it; a caller that refuses the places refuses that part too, which only
// refuses more. Hard links, overlay layers and FUSE mirrors are names no table lists (Of's Layers and Unmapped name
// the last two). A different filesystem instance showing the same data is not recognised.
func (mt *MountTable) TreeAliases(p string) (names []string, ok bool) {
	return mt.treeAliases(p, false)
}

// DetachedParts lists the places of TreeAliases outside p whose mount's root lies strictly inside p's tree: a bind of
// a directory or of one file inside p, elsewhere. A walk up from a file there that crosses mounts, as the decision
// plane's does (ADR 0025), meets that mount's root and then its mount point, and never p itself. A place whose mount
// root is p or lies above it (a bind of p, of its parent, of its whole filesystem) is not one, since the walk from a
// file beneath it passes p's own directory, and neither is a place beneath p, whose mount point the walk climbs
// through p from. ok is false as for TreeAliases.
func (mt *MountTable) DetachedParts(p string) (points []string, ok bool) {
	return mt.treeAliases(p, true)
}

// AliasDetails reports known tree aliases and detached parts of p, together with
// the reason those lists may be incomplete. The reason names the affected path or
// mount point, from the same query. An empty reason establishes certainty only for
// this query. Diagnostics can retain known aliases while reporting uncertainty;
// enforcement callers use TreeAliases or DetachedParts and their certainty result.
func (mt *MountTable) AliasDetails(p string) (names, parts []string, uncertainty string) {
	own := mt.Of(p)
	return aliasPlaces(own, p, false), aliasPlaces(own, p, true), mt.aliasUncertainty(own, p)
}

func (mt *MountTable) aliasUncertainty(own FileMount, p string) string {
	if !own.Held {
		return fmt.Sprintf("the mount holding folder %q cannot be placed", p)
	}
	for _, m := range mt.t.mounts {
		if m.dev != own.Device || !m.unlinkedRoot() {
			continue
		}
		// An unlinked regular file retains the single-file rule. A directory
		// or unreadable root can expose an unknown part of this device's tree.
		switch unlinkedMountType(m) {
		case unix.S_IFREG:
			continue
		case unix.S_IFDIR:
			return fmt.Sprintf("mount %q has an unlinked directory root", m.point)
		default:
			return fmt.Sprintf("mount %q has an unlinked root whose type cannot be established", m.point)
		}
	}
	return ""
}

// treeAliases is TreeAliases, or DetachedParts when detached.
func (mt *MountTable) treeAliases(p string, detached bool) (names []string, ok bool) {
	own := mt.Of(p)
	if mt.aliasUncertainty(own, p) != "" {
		return nil, false
	}
	return aliasPlaces(own, p, detached), true
}

func aliasPlaces(own FileMount, p string, detached bool) (names []string) {
	places := slices.Concat(own.Aliases, own.Beneath)
	if detached {
		places = own.Beneath
	}
	for _, n := range places {
		if n != p && !slices.Contains(names, n) && (!detached || !isAncestorOrSelf(p, n)) {
			names = append(names, n)
		}
	}
	return names
}

// mountDevice reads a canonical "major:minor" device field.
func mountDevice(device string) (major, minor uint32, ok bool) {
	ma, mi, cut := strings.Cut(device, ":")
	a, errA := strconv.ParseUint(ma, 10, 32)
	b, errB := strconv.ParseUint(mi, 10, 32)
	if !cut || errA != nil || errB != nil || strconv.FormatUint(a, 10) != ma || strconv.FormatUint(b, 10) != mi {
		return 0, 0, false
	}
	return uint32(a), uint32(b), true
}

// Only these backing classes are stated limits. Malformed overlay spellings
// remain uncertainty refusals, including malformed options after a relative layer.
const unlinkedRootBacking = "a mount with an unlinked root"

func (m mount) unlinkedRoot() bool { return strings.HasSuffix(m.root, "//deleted") }

// unlinkedAt distinguishes a known holding mount with an unplaced backing name
// from a missing mount identity. It permits landing on the mount, not an alias
// inference from its former name.
func (t *mountTable) unlinkedAt(p string) bool {
	m, _, ok := t.lookup(p)
	return ok && m.unlinkedRoot()
}

const relativeOverlayLayers = "overlay (layers named relative to a folder the mount table does not record)"

func isFuseType(fstype string) bool {
	return fstype == "fuse" || fstype == "fuseblk" || strings.HasPrefix(fstype, "fuse.")
}

func unplacedBacking(unmapped string) string {
	if unmapped == unlinkedRootBacking {
		return "the mount has an unlinked root whose backing name cannot be placed"
	}
	if unmapped == relativeOverlayLayers {
		return "the layers are named relative to a folder the mount table does not record"
	}
	if isFuseType(unmapped) ||
		unmapped == "ecryptfs" || unmapped == "aufs" || unmapped == "shiftfs" {
		return unmapped + " does not establish which folder holds the files it shows"
	}
	return ""
}

// stackLayers is the layer directories of a stacking filesystem of type fstype with super options super, or the reason
// its layers cannot be named. An overlay names its layers in its options, each escaped as seq_show_option escapes a
// value (octal for ',', '=', space, tab, newline and backslash): lowerdir is a ':' list ("\:" a literal colon, "::"
// before data-only layers), lowerdir+ and datadir+ one layer each (Linux 6.7 on). Relative paths, parent
// components and upper/work backslashes whose quoting origin is unknown cannot be placed.
// Relative layers are unplaced backing; absolute layers alongside them remain usable.
// FUSE, eCryptfs, aufs and shiftfs show another tree's files by names their options do not give.
func stackLayers(fstype, super string) (layers []string, unmapped string) {
	switch {
	case isFuseType(fstype) ||
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
			// Legacy string options quote with backslash, while FD options
			// display literal paths. Mountinfo does not distinguish their origin.
			if strings.ContainsRune(dirs[0], '\\') {
				return nil, "overlay (a layer " + strconv.Quote(dirs[0]) + " has ambiguous overlay quoting)"
			}
		}
		for _, d := range dirs {
			if d == "" {
				return nil, "overlay (an empty layer path)"
			}
			// Cleaning before the path walk could remove a symlink followed by
			// '..' and substitute a different existing layer. Refuse that inference.
			if slices.Contains(strings.Split(d, "/"), "..") {
				return nil, "overlay (a layer " + strconv.Quote(d) + " has a parent path component it cannot place)"
			}
			if !filepath.IsAbs(d) {
				unmapped = relativeOverlayLayers
				continue
			}
			layers = append(layers, filepath.Clean(d))
		}
	}
	if lowers == 0 {
		return nil, "overlay (no lower layer named in its options)"
	}
	return layers, unmapped
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

// unescapeMount decodes the \040-style octal escapes mountinfo uses, once: a decoded backslash is never read as the
// start of another escape.
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

// bindExposed reports whether the table shows a directory at or beneath scope (a clean absolute path) mounted at a
// point outside it (ADR 0043 D6 (f)): a file there is reached without passing scope, so the kernel's climb from it
// never meets the scope's row. The scope's place within its filesystem is its mount's root joined with its path
// below the mount point; another row of that device whose root lies at or beneath that place, mounted outside
// scope, exposes it, a hidden row included. A row of that device whose visibility is unknown exposes it too. A
// probed table that holds no mount of the scope (one that could not be read, or whose lookup fails) cannot place it,
// so it cannot show that nothing exposes it: the scope counts as exposed, which keeps its rows. A disabled probe
// exposes nothing.
func (t *mountTable) bindExposed(scope string) bool {
	if t == nil || !t.probed {
		return false
	}
	m, _, ok := t.lookup(scope)
	if !ok || m.dev == "" || !filepath.IsAbs(m.root) || m.unlinkedRoot() {
		return true
	}
	place := filepath.Join(m.root, strings.TrimPrefix(scope, m.point))
	for _, n := range t.mounts {
		if n.dev != m.dev {
			continue
		}
		if n.unlinkedRoot() {
			return true // no former name places this file or directory outside the scope
		}
		if t.uncertaintyAt(n.point) != "" {
			return true
		}
		if (n.point == m.point && n.root == m.root) || isAncestorOrSelf(scope, n.point) {
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

// controlFS is where a write grant at p (a clean absolute path) reaches a kernel control filesystem: the mount
// holding p is one, or one is mounted at or beneath p (a grant covers the mounts beneath it). "" when it reaches none,
// and when the probe is off or the table could not be read (its caller refuses then).
func (t *mountTable) controlFS(p string) string {
	if !t.probed || t.err != nil {
		return ""
	}
	if m, _, ok := t.lookup(p); ok && writeRefusedMount(m) {
		return fmt.Sprintf("the %s filesystem mounted at %s", m.fstype, m.point)
	}
	for _, m := range t.mounts {
		if t.visible(m) && writeRefusedMount(m) && isAncestorOrSelf(p, m.point) {
			return fmt.Sprintf("the %s filesystem mounted at %s", m.fstype, m.point)
		}
	}
	return ""
}

// The terminal layer withholds recursive access beneath /dev/pts, while it
// grants ordinary directories such as /work recursively. Devpts at another
// path, including a bind of a slave alone, cannot use that canonical exemption.
func writeRefusedMount(m mount) bool {
	return writeRefusedType(m.fstype) || m.fstype == "devpts" && m.point != "/dev/pts"
}

// placeOf is where p (a clean absolute path) lies by file identity: the device of the mount holding it and its place
// within that filesystem (the mount's root joined with p's path below the mount point). ok is false when the probe is
// off, the table could not be read, no mount holds p, or its root name was unlinked.
func (t *mountTable) placeOf(p string) (dev, place string, ok bool) {
	if !t.probed || t.err != nil {
		return "", "", false
	}
	m, _, held := t.lookup(p)
	if !held || m.dev == "" || !filepath.IsAbs(m.root) || m.unlinkedRoot() {
		return "", "", false
	}
	rel := strings.TrimPrefix(p, m.point)
	if m.point == "/" {
		rel = p
	}
	return m.dev, filepath.Join(m.root, rel), true
}

// reaches is how a write grant at entry reaches protected, both clean absolute paths, by file identity rather than by
// spelling: over when the grant covers protected (the entry's place is at or above it on the same filesystem, or a
// mount beneath the entry shows it or a directory above it), inside when the grant lies strictly inside it (the entry's
// place is beneath it on the same filesystem, or a mount beneath the entry shows part of its tree). A bind mount, a
// second mount of the filesystem or a mount of a subtree is the same file under another name, and Landlock grants a
// write through every visible mount beneath a granted directory. Callers must
// refuse unknown identities before using these comparisons (requireProtectedIdentity).
func (t *mountTable) reaches(entry, protected string) (over, inside bool) {
	devP, placeP, ok := t.placeOf(protected)
	if !ok {
		return false, false
	}
	if devE, placeE, ok := t.placeOf(entry); ok && devE == devP {
		over = isAncestorOrSelf(placeE, placeP)
		inside = !over && isAncestorOrSelf(placeP, placeE)
	}
	for _, m := range t.mounts {
		if m.unlinkedRoot() || !t.visible(m) || m.dev != devP || m.point == entry || !isAncestorOrSelf(entry, m.point) {
			continue
		}
		switch {
		case isAncestorOrSelf(m.root, placeP):
			over = true
		case isAncestorOrSelf(placeP, m.root):
			inside = true
		}
	}
	return over, inside
}

// mountTable is the compile's mount table, read and parsed once (loadMountTable) and shared by every check that
// reads it; err is the read's error each time, so each caller says what it says about an unread table.
func (k *compiler) mountTable() (*mountTable, error) {
	if k.mt == nil {
		k.mt, _ = loadMountTable(k.o.mountInfo)
	}
	return k.mt, k.mt.err
}
