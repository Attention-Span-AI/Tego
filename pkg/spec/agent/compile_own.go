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
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The names tego goes by on a machine: the launcher and the dashboard's binary beside it.
const (
	binaryTego    = "tego"
	binaryControl = "tego-control"
)

// pathShadow is a directory on the launcher's PATH searched before the one holding binary (at): anything named binary
// there runs in its place the next time a person types the name.
type pathShadow struct {
	declared, resolved string
	binary, at         string
}

// defaultInstallDirs are the places a tego is installed to beside the one running and the one PATH finds: the
// installer's default prefix under the compile's home (scripts/install.sh, TEGO_PREFIX), the usual system prefixes a
// package or a person puts it in, and /opt/tego/bin. A systemd unit's ExecStart, or a second shell's PATH, names one of
// these far more often than any other place (docs/user/run-as-a-service.md).
func defaultInstallDirs(home string) []string {
	dirs := []string{"/usr/local/bin", "/usr/bin", "/opt/tego/bin"}
	if home != "" {
		dirs = append([]string{filepath.Join(home, ".local", "bin")}, dirs...)
	}
	return dirs
}

// ownFile is a file of tego's that ownBinaries found, as the kernel names it: where its walk lands, what it is
// called in diagnostics, its device and link count, and the mount points of every mount of its filesystem.
type ownFile struct {
	name, path string
	dev        uint64
	nlink      uint64
	// points are the mount points of every mount of the file's device, where the mount table could be read: an entry
	// at or above one of them reaches the filesystem the file's other hard links are on.
	points []string
}

// backingLimit keeps each unplaced backing tied to its own holding filesystem.
// Another discovered binary's device may itself expose this filesystem's backing.
type backingLimit struct{ reason, device string }

// ownNames is what ownBinaries knows of tego's files beyond R10's targets: the files with more than one link, whose
// other names no table lists (refusedFS refuses a write entry that reaches their filesystem), the directories beneath
// the filesystems holding them whose content those filesystems show (an overlay's layers: an entry at, over or inside
// one is refused), and why compile cannot see every name of one at all ("" when it can).
type ownNames struct {
	linked []ownFile
	layers []struct{ name, path string }
	unseen string
	// absent layers have no path here; their host spellings do not establish mount identity.
	absent         []string
	unplaced       []backingLimit // no backing path is guessed
	overlayDevices []string
	files          []writeTarget // regular R10 files on absent or unplaced backing
}

// ownBinaries is what WithOwnBinaries adds to R10: the targets for the running tego and for the tego and tego-control
// the launcher's PATH finds, each beside the tego-control a tego there would hand off to, and the PATH directories
// searched before those. Each of those binaries runs outside any contract the next time a person starts it, or as root
// under sudo "$(command -v tego)", so an agent that can replace one has left its own run. The os.Executable name alone
// would miss what a person types: a link on PATH to the real file, which R10's walk follows from the name found here.
//
// A PATH directory is the launcher's, k.o.path, never the agent's env.set: the one the person's next `tego` is looked up
// on. A tego that is not on PATH is not found through it, so it shadows nothing, and a running file that cannot be named
// (WithOwnBinaries(""), a tego-control's sealed copy) leaves the search of PATH.
//
// Beyond those names, tego's files are found by what the kernel knows them by (ADR 0059, amendment 2026-11-11): a
// tego installed in one of the usual places (defaultInstallDirs), which a systemd unit or a second shell runs though
// this compile neither runs from it nor finds it on PATH; every other place the mount table shows each file (a bind
// mount of it or of a directory above it, MountOf's Aliases), each a target of its own; the layers of an overlay
// holding one; and a file with more than one hard link, whose other names no table lists (ownNames.linked).
func (k *compiler) ownBinaries(mt *mountTable) ([]writeTarget, []pathShadow, ownNames) {
	if !k.o.ownBinaries {
		return nil, nil, ownNames{}
	}
	const fix = "name the folders the agent needs instead: an agent that can write here can replace tego, and the next run would run its code"
	var unknown string
	executable := func(p string) bool {
		ok, err := isExecutableFile(p)
		if err != nil && unknown == "" {
			unknown = fmt.Sprintf("binary discovery cannot examine %s (%v)", p, err)
		}
		return ok
	}
	var targets []writeTarget
	add := func(name, p string) {
		for _, t := range targets {
			if t.declared == p {
				return
			}
		}
		targets = append(targets, k.r10Target(name, p, fix))
	}
	// tego hands off to the tego-control beside its own file and nowhere else, so a name still free there is one too.
	addControl := func(dir string) {
		p := filepath.Join(dir, binaryControl)
		if executable(p) {
			add("the tego-control binary", p)
		} else {
			add("the place beside tego for tego-control,", p)
		}
	}
	if exe := k.o.ownExe; executable(exe) {
		add("the tego binary", exe)
		addControl(filepath.Dir(exe))
	}
	dirs := pathDirs(k.o.path, k.o.cwd)
	var shadows []pathShadow
	for _, binary := range []string{binaryTego, binaryControl} {
		for i, d := range dirs {
			p := filepath.Join(d, binary)
			if !executable(p) {
				continue
			}
			add("the "+binary+" binary on PATH", p)
			if binary == binaryTego {
				if r := k.resolve(p); r != "" {
					addControl(filepath.Dir(r))
				}
			}
			for _, before := range dirs[:i] {
				if r := k.resolve(before); r != "" {
					shadows = append(shadows, pathShadow{declared: before, resolved: r, binary: binary, at: p})
				}
			}
			break
		}
	}
	installDirs := k.o.installDirs
	if !k.o.installDirsSet {
		installDirs = defaultInstallDirs(k.o.home)
	}
	for _, d := range installDirs {
		for _, binary := range []string{binaryTego, binaryControl} {
			p := filepath.Join(d, binary)
			if !executable(p) {
				continue
			}
			add("the "+binary+" binary installed at", p)
			if binary == binaryTego {
				if r := k.resolve(p); r != "" {
					addControl(filepath.Dir(r))
				}
			}
		}
	}
	names := k.otherNames(mt, targets)
	if unknown != "" {
		names.unseen = unknown
	}
	return targets, shadows, names
}

// otherNames is what the mount table and the link counts show of tego's binaries beyond their names: the layers of a
// stacking filesystem holding one, closed over (layerClosure); the files with more than one hard link, whose other
// names no table lists; and why compile cannot see every name of one: the table cannot be read whole, shows no mount
// holding the file, or malformed layer options. Absent or unplaced binary backing
// stays a stated limit, with a warning for grants reaching another storage mount. With the probe off
// (WithMountInfo("")) only the links are counted. The mount aliases of every R10 target, these included, are
// aliasTargets'.
func (k *compiler) otherNames(mt *mountTable, targets []writeTarget) ownNames {
	var names ownNames
	see := func(why string) {
		if names.unseen == "" {
			names.unseen = why
		}
	}
	if mt.probed && mt.err != nil {
		see(fmt.Sprintf("the mount table %s cannot be read whole (%v), so the names a mount gives tego's binaries are unknown", k.o.mountInfo, mt.err))
	}
	var layers []string
	seen := map[[2]uint64]bool{}
	for _, t := range targets {
		if t.path == "" || !t.placed {
			continue
		}
		var st unix.Stat_t
		statErr := statOwnFile(t.path, &st)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) && !errors.Is(statErr, unix.ENOTDIR) {
			see(fmt.Sprintf("cannot read the file identity of %s (%v)", t.path, statErr))
		}
		file := statErr == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
		if mt.probed && mt.err == nil {
			fm := mt.fileMount(t.path)
			switch {
			case !fm.Held && (file || existingDir(t.path)):
				see(fmt.Sprintf("the mount table %s shows no mount holding %s, so the names a mount gives it are unknown", k.o.mountInfo, t.path))
			case unplacedBacking(fm.Unmapped) != "":
				why := backingLimit{unplacedBacking(fm.Unmapped), fm.Device}
				if !slices.Contains(names.unplaced, why) {
					names.unplaced = append(names.unplaced, why)
				}
			case fm.Unmapped != "":
				see(fmt.Sprintf("%s lies on %s, which shows another tree's files by names the mount table does not give", t.path, fm.Unmapped))
			}
			layers = append(layers, fm.Layers...)
			if m, _, ok := mt.lookup(t.path); ok && m.fstype == "overlay" && !slices.Contains(names.overlayDevices, m.dev) {
				names.overlayDevices = append(names.overlayDevices, m.dev)
			}
		}
		if !file || seen[[2]uint64{st.Dev, st.Ino}] {
			continue
		}
		seen[[2]uint64{st.Dev, st.Ino}] = true
		// A file only root may write has no name the agent can write through, whatever its grant, while the agent is
		// not root and cannot become root (no setuid: true): a grant does not override the file's mode. A package's or a
		// Nix store's hard links are such files.
		if st.Nlink > 1 && (st.Uid != 0 || st.Mode&0o022 != 0 || k.agentMayBeRoot()) {
			f := ownFile{name: strings.TrimSuffix(t.name, ","), path: t.path, dev: st.Dev, nlink: uint64(st.Nlink)}
			if mt.probed && mt.err == nil {
				f.points = mt.pointsOf(t.path)
			}
			names.linked = append(names.linked, f)
		}
	}
	if len(layers) > 0 {
		var why string
		var unplaced []backingLimit
		names.layers, names.absent, why, unplaced = layerClosure(mt, layers)
		for _, reason := range unplaced {
			if !slices.Contains(names.unplaced, reason) {
				names.unplaced = append(names.unplaced, reason)
			}
		}
		if why != "" {
			see(why)
		}
	}
	return names
}

// backingFiles includes every regular R10 target on the affected filesystem,
// including non-executable policy files. A source spelling can only add protected
// places: FUSE's fsname is chosen by its mounter, and even eCryptfs inode numbers
// cannot establish that a source path still names its original lower directory.
func (k *compiler) backingFiles(mt *mountTable, own *ownNames, targets []writeTarget) {
	if !mt.probed || mt.err != nil {
		return
	}
	var sources []string
	for _, t := range targets {
		if !t.placed || t.path == "" {
			continue
		}
		// Every directory the protected path walk reads matters too. Crossing
		// an unlinked root places its visible name but not its backing name.
		walk := []string{t.path}
		for _, h := range t.held {
			walk = append(walk, h.dir)
		}
		for _, p := range walk {
			fm := mt.fileMount(p)
			if fm.Unmapped == unlinkedRootBacking {
				b := backingLimit{unplacedBacking(fm.Unmapped), fm.Device}
				if !slices.Contains(own.unplaced, b) {
					own.unplaced = append(own.unplaced, b)
				}
			}
		}
		fi, err := os.Lstat(t.path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		fm := mt.fileMount(t.path)
		if isFuseType(fm.Unmapped) || fm.Unmapped == "ecryptfs" {
			b := backingLimit{unplacedBacking(fm.Unmapped), fm.Device}
			if !slices.Contains(own.unplaced, b) {
				own.unplaced = append(own.unplaced, b)
			}
			if source := backingSource(fm); source != "" && !slices.Contains(sources, source) {
				sources = append(sources, source)
			}
		}
	}
	if len(sources) > 0 {
		layers, absent, unseen, unplaced := layerClosure(mt, sources)
		for _, l := range layers {
			l.name = "a protected backing folder or another place showing it,"
			if !slices.ContainsFunc(own.layers, func(p struct{ name, path string }) bool { return p.path == l.path }) {
				own.layers = append(own.layers, l)
			}
		}
		own.absent = append(own.absent, absent...)
		for _, b := range unplaced {
			if !slices.Contains(own.unplaced, b) {
				own.unplaced = append(own.unplaced, b)
			}
		}
		if own.unseen == "" {
			own.unseen = unseen
			if len(own.layers) > maxLayerPlaces {
				own.unseen = fmt.Sprintf("the backing folders beneath protected files reach past %d places", maxLayerPlaces)
			}
		}
	}
	for _, t := range targets {
		if !t.placed || t.path == "" {
			continue
		}
		fm := mt.fileMount(t.path)
		// A binary overlay can have visible layers on unplaced backing. Its
		// regular targets still need comparison even with no absent layer.
		if (len(own.absent) > 0 || len(own.unplaced) > 0) && slices.Contains(own.overlayDevices, fm.Device) ||
			slices.ContainsFunc(own.unplaced, func(b backingLimit) bool { return b.device == fm.Device }) {
			// Retain failed metadata reads too: they cannot prove a file bind
			// differs from this protected target, so the warning must stay.
			fi, err := os.Lstat(t.path)
			if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOTDIR) || err == nil && fi.Mode().IsRegular() {
				own.files = append(own.files, t)
			}
		}
	}
}

// backingSource never trusts source text to remove uncertainty. Resolve its
// actual walk before closure cleaning, so a symlink followed by '..' cannot
// substitute a different existing folder.
func backingSource(fm FileMount) string {
	if !(isFuseType(fm.Unmapped) || fm.Unmapped == "ecryptfs") || !filepath.IsAbs(fm.Source) {
		return ""
	}
	p, err := filepath.EvalSymlinks(fm.Source)
	if err != nil {
		return ""
	}
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return p
	}
	return ""
}

// The bounds of layerClosure: how many places it holds, and how many filesystems deep it follows one beneath another.
const (
	maxLayerPlaces = 64
	maxLayerDepth  = 4
)

// layerClosure is every place whose content a stacking filesystem holding one of tego's binaries shows: each layer
// directory its options name, every other place the mount table shows a layer's tree (a bind mount of it or of a
// directory above it) or part of it (a directory beneath it mounted elsewhere), and the layers of a stacking
// filesystem holding a layer, followed at most maxLayerDepth deep and maxLayerPlaces in all. An entry at, over or
// inside any of them can rewrite what tego runs. A layer no path of this mount namespace reaches (ENOENT, ENOTDIR: a
// container's, named in its host's terms) is returned in absent as a stated limit. Visible mounts whose roots match
// that spelling are still followed conservatively. Relative layers and unnamed
// FUSE/eCryptfs/aufs/shiftfs backing return their own device and reason in unplaced.
// Any other place that cannot be examined, a place the table
// shows no mount holding, malformed layer options, or a closure past
// its bounds is why compile cannot see every name, and refuses every write grant.
func layerClosure(mt *mountTable, layers []string) (places []struct{ name, path string }, absent []string, unseen string, unplaced []backingLimit) {
	type item struct {
		path, of string
		depth    int
	}
	var queue []item
	for _, l := range layers {
		queue = append(queue, item{filepath.Clean(l), filepath.Clean(l), 0})
	}
	visited := map[string]bool{}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if visited[it.path] {
			continue
		}
		visited[it.path] = true
		if len(places) >= maxLayerPlaces || it.depth > maxLayerDepth {
			return places, absent, fmt.Sprintf("the layers beneath the filesystem holding tego's binaries reach past %d places or %d filesystems deep", maxLayerPlaces, maxLayerDepth), unplaced
		}
		var st unix.Stat_t
		if err := unix.Stat(it.path, &st); err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				absent = append(absent, it.path)
				// The absent host spelling has no device here. A visible mount whose root
				// matches it can still expose all or part of the layer; protect that place
				// conservatively without pretending the merged root supplies its identity.
				for _, a := range mt.layerCandidates(it.path) {
					queue = append(queue, item{a, it.of, it.depth})
				}
				continue
			}
			return places, absent, fmt.Sprintf("%s, a layer beneath the filesystem holding tego's binaries, cannot be examined (%v)", it.path, err), unplaced
		}
		name := "a layer of the overlay holding tego's binaries"
		if it.path != it.of {
			name = "another place showing " + it.of + ", a layer of the overlay holding tego's binaries,"
		}
		places = append(places, struct{ name, path string }{name, it.path})
		if !mt.probed {
			continue
		}
		fm := mt.fileMount(it.path)
		switch {
		case !fm.Held:
			return places, absent, fmt.Sprintf("the mount table shows no mount holding %s, a layer beneath the filesystem holding tego's binaries", it.path), unplaced
		case unplacedBacking(fm.Unmapped) != "":
			reason := backingLimit{unplacedBacking(fm.Unmapped), fm.Device}
			if !slices.Contains(unplaced, reason) {
				unplaced = append(unplaced, reason)
			}
		case fm.Unmapped != "":
			return places, absent, fmt.Sprintf("%s, a layer beneath the filesystem holding tego's binaries, lies on %s, whose layers the mount table does not name", it.path, fm.Unmapped), unplaced
		}
		for _, a := range slices.Concat(fm.Aliases, fm.Beneath) {
			queue = append(queue, item{a, it.of, it.depth})
		}
		for _, l := range fm.Layers {
			queue = append(queue, item{filepath.Clean(l), filepath.Clean(l), it.depth + 1})
		}
		if source := backingSource(fm); source != "" {
			queue = append(queue, item{source, source, it.depth + 1})
		}
	}
	return places, absent, "", unplaced
}

// aliasTargets adds to targets every other place the mount table shows each of them: a bind mount of the target, or
// of a directory above it, on the same device (MountOf's Aliases), each walked as R10 walks a target. Every R10
// target gets them, not only tego's binaries: a write entry over a bind alias of the ledger root, a policy file or
// tego's binary reaches the same file (ADR 0059, amendment 2026-11-11).
func (k *compiler) aliasTargets(mt *mountTable, targets []writeTarget) []writeTarget {
	if !mt.probed || mt.err != nil {
		return targets
	}
	out := slices.Clone(targets)
	for _, t := range targets {
		if t.path == "" || !t.placed {
			continue
		}
		for _, a := range mt.fileMount(t.path).Aliases {
			if !slices.ContainsFunc(out, func(o writeTarget) bool { return o.declared == a }) {
				out = append(out, k.r10Target(strings.TrimSuffix(t.name, ",")+" (mounted again at another place, "+t.path+")", a, t.fix))
			}
		}
	}
	return out
}

// existingDir reports whether p names a directory: a place beside tego for tego-control is one, whose own name
// is not there yet.
func existingDir(p string) bool {
	fi, err := os.Stat(filepath.Dir(p))
	return err == nil && fi.IsDir()
}

// pointsOf is the mount point of every mount the table shows of the device holding p: the places its filesystem, and
// so every hard link of a file on it, can be reached from.
func (t *mountTable) pointsOf(p string) []string {
	fm := t.fileMount(p)
	if !fm.Held {
		return nil
	}
	var points []string
	for _, m := range t.mounts {
		if t.visible(m) && m.dev == fm.Device && !slices.Contains(points, m.point) {
			points = append(points, m.point)
		}
	}
	return points
}

// refusedFS is why a write entry at resolved reaches the filesystem holding one of tego's files with more than one
// hard link, whose other names compile cannot list: the entry lies on that device, or a mount of it lies at or beneath
// the entry. A write through any of those names rewrites tego. "" when it reaches none.
func refusedFS(linked []ownFile, resolved string) string {
	if len(linked) == 0 {
		return ""
	}
	probe := resolved
	var st unix.Stat_t
	for {
		err := statOwnFile(probe, &st)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOTDIR) {
			return fmt.Sprintf("cannot read the filesystem holding %s (%v), so the grant cannot be shown to stay off tego's other hard links", resolved, err)
		}
		if probe == "/" {
			return fmt.Sprintf("cannot read the filesystem holding %s (%v), so the grant cannot be shown to stay off tego's other hard links", resolved, err)
		}
		probe = filepath.Dir(probe) // a missing entry is made in the first directory above it that is there
	}
	for _, f := range linked {
		reaches := st.Dev == f.dev
		for _, p := range f.points {
			reaches = reaches || isAncestorOrSelf(resolved, p)
		}
		if reaches {
			return fmt.Sprintf("%s %s has %d hard links, whose other names compile cannot list, and the entry reaches the filesystem holding it", f.name, f.path, f.nlink)
		}
	}
	return ""
}

// statOwnFile is the identity read for discovered binaries and hard-link grant
// filesystems. Tests use it to preserve a failed read between discovery and comparison.
var statOwnFile = unix.Stat

// pathDirs is path's directories as a lookup walks them, absolute and once each: an empty element is the current
// directory, and a relative one lies under it (execvp), the compile's cwd here as in searchPath.
func pathDirs(path, cwd string) []string {
	var dirs []string
	for _, d := range filepath.SplitList(path) {
		if !filepath.IsAbs(d) {
			d = filepath.Join(cwd, d)
		}
		if d = filepath.Clean(d); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// isExecutableFile reports whether p names a regular file with an execute bit. An
// inaccessible candidate is unknown, not absent: the owner may restore directory
// search permission inside a write grant and then replace an undiscovered binary.
func isExecutableFile(p string) (bool, error) {
	if p == "" {
		return false, nil
	}
	fi, err := os.Stat(p)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return fi.Mode().IsRegular() && fi.Mode()&0o111 != 0, nil
}

// warnPathShadow warns once for a write entry over a PATH directory searched before tego: the agent could put its own
// tego there, and the next one typed in this shell would run it. A warning where R10 refuses, because the directory
// holds nothing of tego's, and the common case is a project's own: an activated .venv/bin or node_modules/.bin under
// a project the contract rightly lets the agent write.
func warnPathShadow(k *compiler, pos Pos, raw, p, resolved string, shadows []pathShadow) {
	for _, s := range shadows {
		if isAncestorOrSelf(resolved, s.resolved) {
			k.ds.warnf(pos, CodePathShadow, "fs.write %q%s lets the agent write %s, which this PATH searches before %s: a %s it puts there would run in place of tego's, outside the contract, the next time you type %s",
				raw, resolvedNote(p, resolved), s.declared, s.at, s.binary, s.binary).
				fix("put %s first on your PATH, or start tego by its full path", filepath.Dir(s.at))
			return
		}
	}
}

// agentMayBeRoot reports whether the run's agent may hold root's ids: the uid it is dropped to is root's (a root
// launcher with no sudo user), or the contract lets a setuid binary inside the run gain its ids (setuid: true).
func (k *compiler) agentMayBeRoot() bool {
	uid, _ := config.InvokingUID()
	return uid == 0 || k.c.Setuid
}

// layerCandidates maps an absent host layer spelling through visible mount roots.
// A matching root is a candidate, not proof of a shared device: the absent path
// supplies no device. Different filesystem-relative spellings remain a limit.
func (t *mountTable) layerCandidates(layer string) []string {
	if !t.probed || t.err != nil {
		return nil
	}
	var paths []string
	for _, m := range t.mounts {
		if m.unlinkedRoot() || !filepath.IsAbs(m.root) || !filepath.IsAbs(m.point) {
			continue
		}
		var p, expected string
		switch {
		case isAncestorOrSelf(m.root, layer):
			p = filepath.Join(m.point, strings.TrimPrefix(layer, m.root))
			expected = layer
		case isAncestorOrSelf(layer, m.root):
			p, expected = m.point, m.root
		default:
			continue
		}
		if !t.visible(m) && t.uncertaintyAt(m.point) == "" {
			continue
		}

		// Missing candidates place nothing. Other errors must reach the closure's
		// refusal, just as unreadable metadata at a directly named layer does.
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			continue
		}
		// A submount may cover the mapped candidate even when this row remains
		// visible at its own mountpoint. A verified different device/place covers it.
		// A failed identity read establishes no covering mount: retain that
		// uncertainty for the closure's ordinary error path.
		if holding, _, ok := t.lookup(p); ok && (holding.dev != m.dev || filepath.Join(holding.root, strings.TrimPrefix(p, holding.point)) != expected) {
			continue
		}
		if !slices.Contains(paths, p) {
			paths = append(paths, p)
			// One past the closure's bound suffices to make it refuse.
			if len(paths) > maxLayerPlaces {
				return paths
			}
		}
	}
	return paths
}

// warnOverlayBacking warns once per write or ask entry reaching another storage
// filesystem when protected-file backing is absent or unplaced. Multiple mounts still get one warning.
func (k *compiler) warnOverlayBacking(mt *mountTable, own ownNames, pos Pos, raw, resolved string) {
	if len(own.absent) == 0 && len(own.unplaced) == 0 || !mt.probed || mt.err != nil {
		return
	}
	// A character device such as /dev/null cannot expose a backing folder or
	// regular binary file. Its memory-backed /dev mount is not a storage grant.
	if fi, err := os.Stat(resolved); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return
	}
	// Unlike unnamed stacking backing, an unlinked file can retain a writable
	// hard link on a memory filesystem too. Never silently drop that warning.
	unlinked := slices.ContainsFunc(own.unplaced, func(b backingLimit) bool { return b.reason == unplacedBacking(unlinkedRootBacking) })
	checked := map[string]bool{}
	external := func(m mount) bool {
		if checked[m.id] {
			return false
		}
		checked[m.id] = true
		alias, different, regular := mt.backingFile(m, own.files)
		if alias != "" {
			d := k.ds.errorf(pos, CodeContradiction, "fs.write %q reaches mount %s, a byte-identical alias of %s on absent or unplaced backing; a write here can replace a protected file (R10)", raw, m.point, alias)
			d.fix("keep mount %s and its ancestors out of every write or ask grant", m.point)
			d.overlap = true
			return false
		} else if different && !slices.ContainsFunc(own.unplaced, func(b backingLimit) bool {
			return b.reason != unplacedBacking(relativeOverlayLayers)
		}) {
			// Only overlay layers store the visible bytes unchanged. A FUSE
			// or eCryptfs backing file may instead hold ciphertext.
			return false
		}
		// C65's memory-directory limit remains for absent and unnamed stacking
		// backing. Unlinked protected files keep the warning on memory too;
		// regular-file binds may also warn there, including an empty file.
		return (!kernelOrMemoryType(m.fstype) || (regular || unlinked) && slices.Contains(memoryFilesystemTypes, m.fstype)) && (len(own.absent) > 0 && !slices.Contains(own.overlayDevices, m.dev) ||
			slices.ContainsFunc(own.unplaced, func(b backingLimit) bool {
				return b.device != m.dev || b.reason == unplacedBacking(unlinkedRootBacking)
			}))
	}
	var at string
	if m, _, ok := mt.lookup(resolved); ok && external(m) {
		at = m.point
	}
	for _, m := range mt.mounts {
		if isAncestorOrSelf(resolved, m.point) && mt.visible(m) {
			warn := external(m) // inspect aliases even after another mount warned
			if at == "" && warn {
				at = m.point
			}
		}
	}
	if at == "" {
		return
	}
	reason := ""
	advice := "do not mount the runtime's storage or the whole host filesystem at a place a contract may write"
	if len(own.unplaced) > 0 {
		var reasons []string
		for _, b := range own.unplaced {
			switch b.reason {
			case unplacedBacking(relativeOverlayLayers):
			case unplacedBacking(unlinkedRootBacking):
				advice = "keep surviving names of unlinked protected files out of every write or ask grant"
			default:
				advice = "keep the folder that stores the encrypted or mirrored files out of every write grant"
			}
			if !slices.Contains(reasons, b.reason) {
				reasons = append(reasons, b.reason)
			}
		}
		reason = ", because " + strings.Join(reasons, "; ")
	}
	var affected []string
	for _, t := range own.files {
		fm := mt.fileMount(t.path)
		if fm.Unmapped != "" && fm.Unmapped != relativeOverlayLayers {
			text := fmt.Sprintf("%s %s lies on %s", strings.TrimSuffix(t.name, ","), t.path, fm.Unmapped)
			if !slices.Contains(affected, text) {
				affected = append(affected, text)
			}
		}
	}
	detail := ""
	if len(affected) > 0 {
		detail = "; protected files: " + strings.Join(affected, "; ")
	}
	k.ds.warnf(pos, CodeOverlayBackingUnknown, "fs.write %q reaches mount %s and Tego cannot tell whether that mount shows the folders holding its protected files%s; %s%s", raw, at, reason, advice, detail)
}

// statBackingFile is a seam for a mountpoint replaced after the snapshot.
var statBackingFile = unix.Statx

// unlinkedMountType classifies a root only under the snapshot mount ID.
// Directory type never establishes what content an unlinked root exposes.
func unlinkedMountType(m mount) uint16 {
	var st unix.Statx_t
	const mask = unix.STATX_TYPE | unix.STATX_MNT_ID
	if err := statBackingFile(unix.AT_FDCWD, m.point, unix.AT_SYMLINK_NOFOLLOW, mask, &st); err != nil ||
		st.Mask&mask != mask || strconv.FormatUint(st.Mnt_id, 10) != m.id {
		return 0
	}
	return st.Mode & unix.S_IFMT
}

// checkUnlinkedMounts never interprets the former name as a tree. A regular
// root may still be a protected file through a surviving hard link. Unknown
// root content, including a directory, refuses only grants reaching it, as
// unknown mount visibility does; its content cannot be placed from the old name.
func (k *compiler) checkUnlinkedMounts(mt *mountTable, targets []writeTarget, pos Pos, raw, resolved string) {
	for _, m := range mt.mounts {
		if !m.unlinkedRoot() || !mt.visible(m) || !(isAncestorOrSelf(resolved, m.point) || isAncestorOrSelf(m.point, resolved)) {
			continue
		}
		var st unix.Statx_t
		const mask = unix.STATX_MNT_ID | unix.STATX_TYPE | unix.STATX_INO
		err := statBackingFile(unix.AT_FDCWD, m.point, unix.AT_SYMLINK_NOFOLLOW, mask, &st)
		known := err == nil && st.Mask&(unix.STATX_MNT_ID|unix.STATX_TYPE) == unix.STATX_MNT_ID|unix.STATX_TYPE && strconv.FormatUint(st.Mnt_id, 10) == m.id
		if !known || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mask&unix.STATX_INO == 0 {
			k.ds.errorf(pos, CodeContradiction, "fs.write %q: compile cannot classify the unlinked-root mount at %s under its snapshot mount id, so the grant cannot be shown to stay off protected files (R10)", raw, m.point).
				fix("restore a linked directory root or an inspectable regular file on the named mount, then compile again, or remove the write or ask grant")
			continue
		}
		for _, p := range targets {
			if !p.placed || p.path == "" {
				continue
			}
			unknown := func() {
				k.ds.errorf(pos, CodeContradiction, "fs.write %q reaches unlinked file mount %s, but compile cannot establish the protected file identity of %s %s under its snapshot mount id (R10)", raw, m.point, strings.TrimSuffix(p.name, ","), p.path).
					fix("restore inspectable protected files on their snapshot mounts, then compile again, or remove the write or ask grant")
			}
			pm, _, held := mt.lookup(p.path)
			if !held {
				unknown()
				continue
			}
			if pm.dev != m.dev {
				continue
			}
			var ps unix.Statx_t
			err := statBackingFile(unix.AT_FDCWD, p.path, unix.AT_SYMLINK_NOFOLLOW, mask, &ps)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				continue // established absence needs no regular-file comparison
			}
			if err != nil || ps.Mask&(unix.STATX_MNT_ID|unix.STATX_TYPE) != unix.STATX_MNT_ID|unix.STATX_TYPE || strconv.FormatUint(ps.Mnt_id, 10) != pm.id {
				unknown()
				continue
			}
			if ps.Mode&unix.S_IFMT != unix.S_IFREG {
				continue
			}
			if ps.Mask&unix.STATX_INO == 0 {
				unknown()
				continue
			}
			if ps.Dev_major == st.Dev_major && ps.Dev_minor == st.Dev_minor && ps.Ino == st.Ino {
				d := k.ds.errorf(pos, CodeContradiction, "fs.write %q reaches mount %s, an alias of %s %s with the same device and inode; a write here can replace a protected file (R10)", raw, m.point, strings.TrimSuffix(p.name, ","), p.path)
				d.fix("keep mount %s and its ancestors out of every write or ask grant", m.point)
				d.overlap = true
			}
		}
	}
}

// openBackingMountID is statx(2) of an open file's mount id. The number is lent only through RawConn.Control for the
// one call (ADR 0023); it is a seam so tests can replay a snapshot's mount ids by the opened path.
var openBackingMountID = func(f *os.File, st *unix.Statx_t) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.Statx(int(fd), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, st)
	}); err != nil {
		return err
	}
	return serr
}

// backingFile compares a verified regular mount root with affected protected
// files. A nonempty match is a conservative R10 alias, regardless of execute
// bits. Only overlay backing may use a difference as an exemption. Empty pairs
// and read/type/identity uncertainty prove neither identity nor difference.
func (t *mountTable) backingFile(m mount, protected []writeTarget) (alias string, different, regular bool) {
	var st unix.Statx_t
	const mask = unix.STATX_MNT_ID | unix.STATX_TYPE | unix.STATX_SIZE
	if err := statBackingFile(unix.AT_FDCWD, m.point, unix.AT_SYMLINK_NOFOLLOW, mask, &st); err != nil ||
		st.Mask&mask != mask || st.Mode&unix.S_IFMT != unix.S_IFREG || strconv.FormatUint(st.Mnt_id, 10) != m.id || st.Size > uint64(^uint64(0)>>1) {
		return "", false, false
	}
	size := int64(st.Size)
	known := true
	for _, p := range protected {
		var st unix.Stat_t
		if err := unix.Lstat(p.path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			known = false
			continue
		}
		if st.Size != size {
			continue
		}
		if size == 0 {
			known = false // equal empty files carry no identity evidence
			continue
		}
		equal, read := t.sameBackingFile(m, p.path, size)
		if equal {
			return strings.TrimSuffix(p.name, ",") + " " + p.path, false, true
		}
		known = known && read
	}
	return "", known, true
}

// sameBackingFile opens both ends without following a last symlink or blocking
// on a substituted FIFO. Fixed buffers bound memory; reads never exceed the
// protected file's size. Live fd identity closes the gap after the path statx.
func (t *mountTable) sameBackingFile(m mount, protected string, size int64) (equal, known bool) {
	open := func(p string) *os.File {
		f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) // os adds O_CLOEXEC
		if err != nil {
			return nil
		}
		return f
	}
	a := open(m.point)
	if a == nil {
		return false, false
	}
	defer func() { _ = a.Close() }()
	b := open(protected)
	if b == nil {
		return false, false
	}
	defer func() { _ = b.Close() }()
	for _, f := range []*os.File{a, b} {
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() != size {
			return false, false
		}
	}
	{
		var st unix.Statx_t
		if err := openBackingMountID(a, &st); err != nil ||
			st.Mask&unix.STATX_MNT_ID == 0 || strconv.FormatUint(st.Mnt_id, 10) != m.id {
			return false, false
		}
	}
	var ab, bb [32 * 1024]byte
	for left := size; left > 0; {
		n := min(left, int64(len(ab)))
		if _, err := io.ReadFull(a, ab[:n]); err != nil {
			return false, false
		}
		if _, err := io.ReadFull(b, bb[:n]); err != nil {
			return false, false
		}
		if !bytes.Equal(ab[:n], bb[:n]) {
			return false, true
		}
		left -= n
	}
	return true, true
}
