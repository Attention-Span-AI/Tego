// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

type unitObservation struct {
	Name, Path string
	Trigger    string
	Enablement *bool
	Exec       unitExec
	UID        *uint32
	System     bool
}
type unitSnapshot struct {
	Items   []unitObservation
	Sources []processSource
}
type unitRoot struct {
	path   string
	fd     *sys.FD
	before unix.Stat_t
	names  []string
	listed map[string]bool
}
type unitLocation struct {
	root int
	name string
}

func unitDirectory(ctx context.Context, root *sys.FD, name string, uid uint32, entriesLeft *int, perDirectory int) ([]string, error) {
	pin, e := projectPath(root, name)
	if e != nil {
		return nil, e
	}
	defer func() { _ = pin.Close() }()
	var st unix.Stat_t
	if e = pin.Fstat(&st); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, unix.ELOOP
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errType
	}
	if e = checkPinnedMode(ctx, pin, st, uid); e != nil {
		return nil, e
	}
	fd, e := pin.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f, e := fd.Release("scan-unit-directory")
	if e != nil {
		_ = fd.Close()
		return nil, e
	}
	defer func() { _ = f.Close() }()
	names, e := unitDirectoryNamesLimit(ctx, openCatalogDirectory{f}, entriesLeft, perDirectory)
	if e != nil {
		return nil, e
	}
	current, e := projectPath(root, name)
	if e != nil {
		return nil, errChanged
	}
	defer func() { _ = current.Close() }()
	var after unix.Stat_t
	if e = current.Fstat(&after); e != nil {
		return nil, e
	}
	if !sameInode(st, after) {
		return nil, errChanged
	}
	return names, nil
}

// dropinDirectories goes from specific to general; first same-name file wins.
// Different filenames are subsequently merged in lexical order across roots.
func dropinDirectories(unit string) []string {
	ext := filepath.Ext(unit)
	stem := strings.TrimSuffix(unit, ext)
	out := []string{unit + ".d"}
	if i := strings.IndexByte(stem, '@'); i >= 0 {
		out = append(out, stem[:i+1]+ext+".d")
		stem = stem[:i]
	}
	for {
		i := strings.LastIndexByte(stem, '-')
		if i < 0 {
			break
		}
		out = append(out, stem[:i+1]+ext+".d")
		stem = stem[:i]
	}
	return append(out, strings.TrimPrefix(ext, ".")+".d")
}
func collectUnits(ctx context.Context, paths []string, uid uint32, budget *contentBudget) unitSnapshot {
	out := unitSnapshot{}
	sourceBytes, itemBytes := 0, 0
	sourcesLimited, itemsLimited := false, false
	seenSources := map[string]bool{}
	countedFailures := map[string]bool{}
	addExactSource := func(v processSource) {
		if sourcesLimited {
			return
		}
		key := v.Path + "\x00" + v.State + "\x00" + v.Reason
		if seenSources[key] {
			return
		}
		seenSources[key] = true
		if v.NotRead > 0 {
			if countedFailures[v.Path] {
				v.NotRead = 0
			} else {
				countedFailures[v.Path] = true
			}
		}
		b, _ := json.Marshal(v)
		if len(out.Sources) >= 1800 || sourceBytes+len(b) > 400<<10 {
			out.Sources = append(out.Sources, projectSource("", errLimit))
			sourcesLimited = true
			return
		}
		sourceBytes += len(b)
		out.Sources = append(out.Sources, v)
	}
	addSource := func(v processSource) {
		if budget.unitCache != nil {
			v = budget.unitCache.source(v)
		}
		addExactSource(v)
	}
	addItem := func(v unitObservation) bool {
		if itemsLimited || sourcesLimited {
			return false
		}
		b, _ := json.Marshal(v)
		if len(out.Items) >= 512 || itemBytes+len(b) > 450<<10 {
			addSource(projectSource("", errLimit))
			itemsLimited = true
			return false
		}
		itemBytes += len(b)
		if budget.unitCache != nil {
			addExactSource(projectSource(v.Path, nil))
			if sourcesLimited {
				return false
			}
		}
		out.Items = append(out.Items, v)
		return true
	}

	roots := []unitRoot{}
	all := map[string]unitLocation{}
	badRoot := false
	timers := []unitObservation{}
	enabled := map[string]bool{}
	type cachedUnit struct {
		doc  unitDocument
		err  error
		root *sys.FD
		name string
	}
	cache := map[string]cachedUnit{}

	type cachedDirectory struct {
		names  []string
		err    error
		root   *sys.FD
		name   string
		before unix.Stat_t
	}
	directories := map[string]cachedDirectory{}
	work := budget.units
	if work == nil {
		work = &unitWorkBudget{entries: unitTotalEntries, perDirectory: unitDirectoryEntries, maxDirectories: unitDirectoryCount}
	}
	readDirectory := func(fd *sys.FD, path, name string) ([]string, error) {
		key := filepath.Join(path, name)
		if v, ok := directories[key]; ok {
			return v.names, v.err
		}
		v := cachedDirectory{root: fd, name: name}
		pin, e := projectPath(fd, name)
		if e == nil {
			e = pin.Fstat(&v.before)
			_ = pin.Close()
			if e == nil && v.before.Uid != unitReadOwner(path, uid, budget) && v.before.Uid != 0 {
				e = errOwner
			}
		}
		if e == nil {
			cache := budget.unitCache
			switch {
			case cache != nil && cache.roots[path]:
				if previous, ok := cache.directories[key]; ok {
					if !sameInode(previous.before, v.before) {
						cache.changed = true
						e = errChanged
					} else {
						v.names, e = previous.names, previous.err
					}
				} else if work.directories >= work.maxDirectories || work.entries <= 0 {
					e = errLimit
				} else {
					work.directories++
					v.names, e = unitDirectory(ctx, fd, name, unitReadOwner(path, uid, budget), &work.entries, work.perDirectory)
					cache.directories[key] = checkedUnitDirectory{names: v.names, err: e, before: v.before}
				}
			case work.directories >= work.maxDirectories || work.entries <= 0:
				e = errLimit
			default:
				work.directories++
				v.names, e = unitDirectory(ctx, fd, name, unitReadOwner(path, uid, budget), &work.entries, work.perDirectory)
			}
		}
		if e != nil && budget.unitCache != nil {
			if _, ok := budget.unitCache.directories[key]; ok && !errors.Is(e, budget.unitCache.directories[key].err) {
				budget.unitCache.changed = true
				e = errChanged
			}
		}
		if errors.Is(e, unix.ENOENT) {
			return nil, e
		}
		v.err = e
		directories[key] = v
		return v.names, e
	}

	for _, path := range paths {
		if sourcesLimited {
			break
		}
		fd, _, e := metadataPath(ctx, path, false)
		if e != nil {
			if budget.unitCache != nil {
				if _, ok := budget.unitCache.directories[path]; ok {
					budget.unitCache.changed = true
					e = errChanged
				}
			}
			addSource(projectSource(path, e))
			if !errors.Is(e, unix.ENOENT) {
				badRoot = true
			}
			continue
		}
		root := unitRoot{path: path, fd: fd}
		e = fd.Fstat(&root.before)
		if e == nil && (root.before.Uid != unitReadOwner(path, uid, budget) && root.before.Uid != 0) {
			e = errOwner
		}
		if e == nil {
			e = checkPinnedMode(ctx, fd, root.before, unitReadOwner(path, uid, budget))
		}
		validatedRoot := e == nil
		if validatedRoot {
			root.names, e = readDirectory(fd, path, ".")
		}
		if e != nil {
			// readDirectory owns listing identity/error checks. A cached, stable
			// limit refusal is not a root validation change.
			if !validatedRoot && budget.unitCache != nil {
				if _, ok := budget.unitCache.directories[path]; ok {
					budget.unitCache.changed = true
					e = errChanged
				}
			}
			_ = fd.Close()
			addSource(projectSource(path, e))
			badRoot = true
			continue
		}
		root.listed = make(map[string]bool, len(root.names))
		for _, name := range root.names {
			root.listed[name] = true
		}
		roots = append(roots, root)
		addSource(processSource{Path: path, State: "read", Reason: "none"})
		for _, dir := range root.names {
			if sourcesLimited {
				break
			}
			if !strings.HasSuffix(dir, ".wants") {
				continue
			}
			entries, x := readDirectory(fd, path, dir)
			if x != nil {
				addSource(projectSource(filepath.Join(path, dir), x))
				continue
			}
			for _, name := range entries {
				if !plainUnit(name) {
					continue
				}
				pin, x := projectPath(fd, filepath.Join(dir, name))
				if x != nil {
					addSource(projectSource(filepath.Join(path, dir, name), x))
					continue
				}
				var st unix.Stat_t
				x = pin.Fstat(&st)
				_ = pin.Close()
				if x == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
					enabled[name] = true
				}
			}
		}
		for _, name := range root.names {
			if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".timer") {
				if !configuredUnitName(name) {
					addSource(projectSource(filepath.Join(path, name), errUnsupported))
					continue
				}
				if _, ok := all[name]; !ok {
					all[name] = unitLocation{len(roots) - 1, name}
				}
			}
		}
	}
	defer func() {
		for _, r := range roots {
			_ = r.fd.Close()
		}
	}()
	// An enabled instance can have no main file of its own. Resolve its
	// template by name within the already selected roots, never by link target.
	for name := range enabled {
		if _, ok := all[name]; ok {
			continue
		}
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		at := strings.IndexByte(stem, '@')
		if at > 0 && at < len(stem)-1 {
			if loc, ok := all[stem[:at+1]+ext]; ok {
				all[name] = loc
			}
		}
	}

	// Alias destinations inside the selected load path identify a name, not a
	// file to follow. Reapply load-path precedence to that name (systemd.unit).
	resolved := map[string]unitLocation{}
	canonical := map[string]string{}
	aliases := map[string][]string{}
	aliasPins := map[string]unitAliasPin{}
	aliasNames := make([]string, 0, len(all))
	for name := range all {
		aliasNames = append(aliasNames, name)
	}
	sort.Strings(aliasNames)
	for _, name := range aliasNames {
		loc, target, pins, e := resolveUnitAlias(ctx, roots, all, name, uid, budget)
		pinPaths := make([]string, 0, len(pins))
		for path := range pins {
			pinPaths = append(pinPaths, path)
		}
		sort.Strings(pinPaths)
		for _, path := range pinPaths {
			aliasPins[path] = pins[path]
			addSource(projectSource(path, e))
		}
		if e != nil {
			loc := all[name]
			addSource(projectSource(filepath.Join(roots[loc.root].path, loc.name), e))
			continue
		}
		resolved[target] = loc
		canonical[name] = target
		if name != target {
			aliases[target] = append(aliases[target], name)
		}
	}
	names := make([]string, 0, len(resolved))
	for name := range resolved {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if sourcesLimited || itemsLimited {
			break
		}
		loc := resolved[name]
		chain := []unitLocation{loc}
		dropins := map[string]unitLocation{}
		bad := badRoot
		// systemd searches each root's exact/template/dash-prefix directories
		// before the next root; type.d follows all names and all roots.
		unitNames := append([]string{name}, aliases[name]...)
		sort.Strings(unitNames[1:])
		for _, unitName := range unitNames {
			dirs := dropinDirectories(unitName)
			for i, root := range roots {
				for _, dir := range dirs[:len(dirs)-1] {
					if !root.listed[dir] {
						continue
					}
					entries, e := readDirectory(root.fd, root.path, dir)
					if e != nil {
						addSource(projectSource(filepath.Join(root.path, dir), e))
						bad = true
						continue
					}
					for _, file := range entries {
						if strings.HasSuffix(file, ".conf") {
							if _, ok := dropins[file]; !ok {
								dropins[file] = unitLocation{i, filepath.Join(dir, file)}
							}
						}
					}
				}
			}
		}
		typeDir := strings.TrimPrefix(filepath.Ext(name), ".") + ".d"
		for i, root := range roots {
			if !root.listed[typeDir] {
				continue
			}
			entries, e := readDirectory(root.fd, root.path, typeDir)
			if e != nil {
				addSource(projectSource(filepath.Join(root.path, typeDir), e))
				bad = true
				continue
			}
			for _, file := range entries {
				if strings.HasSuffix(file, ".conf") {
					if _, ok := dropins[file]; !ok {
						dropins[file] = unitLocation{i, filepath.Join(typeDir, file)}
					}
				}
			}
		}
		sorted := make([]string, 0, len(dropins))
		for file := range dropins {
			sorted = append(sorted, file)
		}
		sort.Strings(sorted)
		for _, file := range sorted {
			chain = append(chain, dropins[file])
		}
		effective := []unitExec{}
		serviceType := "simple"
		trigger := strings.TrimSuffix(name, ".timer") + ".service"
		timerPath := ""
		for _, src := range chain {
			if sourcesLimited || itemsLimited {
				bad = true
				break
			}
			root := roots[src.root]
			path := filepath.Join(root.path, src.name)
			cached, ok := cache[path]
			if !ok {
				cached.root, cached.name = root.fd, src.name
				cached.doc, cached.err = readUnitDocument(ctx, root.fd, root.path, src.name, uid, budget)
				cache[path] = cached
				addSource(projectSource(path, cached.err))
			}
			doc, e := cached.doc, cached.err
			if doc.ServiceType != nil {
				serviceType = *doc.ServiceType
			}
			if e != nil {
				bad = true
				continue
			}
			if strings.HasSuffix(name, ".timer") {
				timerPath = path
				if doc.Trigger != "" {
					trigger = doc.Trigger
				}
			}
			if doc.Reset {
				effective = []unitExec{}
			}
			for _, x := range doc.Exec {
				x.Path = path
				effective = append(effective, x)
			}
			if len(effective) > 128 {
				addSource(projectSource(path, errLimit))
				bad = true
				break
			}
		}
		if len(effective) > 1 && serviceType != "oneshot" {
			addSource(projectSource(filepath.Join(roots[loc.root].path, loc.name), errUnsupported))
			bad = true
		}
		if !bad {
			if strings.HasSuffix(name, ".timer") {
				timers = append(timers, unitObservation{Name: name, Path: timerPath, Trigger: trigger})
			}
			for _, x := range effective {
				if !strings.HasSuffix(name, ".service") {
					continue
				}
				if x.Program != "" {
					if !addItem(unitObservation{Name: name, Path: x.Path, Exec: x}) {
						break
					}
				}
			}
		}
	}
	for _, timer := range timers {
		for _, service := range out.Items {
			if service.Name == canonical[timer.Trigger] {
				timer.Exec.Program = service.Exec.Program
				if !addItem(timer) {
					break
				}
				break
			}
		}
	}
	for i := range out.Items {
		isEnabled := enabled[out.Items[i].Name]
		for _, alias := range aliases[out.Items[i].Name] {
			isEnabled = isEnabled || enabled[alias]
		}
		if isEnabled {
			v := true
			out.Items[i].Enablement = &v
		}
	}

	for path, alias := range aliasPins {
		pin, e := projectPath(roots[alias.location.root].fd, alias.location.name)
		var after unix.Stat_t
		if e == nil {
			e = pin.Fstat(&after)
			_ = pin.Close()
		}
		if e == nil && alias.parentRoot >= 0 {
			e = unitAliasParent(roots[alias.parentRoot].fd, alias.parentName)
		}
		if e != nil || !sameInode(alias.before, after) {
			if budget.unitCache != nil && budget.unitCache.roots[roots[alias.location.root].path] {
				budget.unitCache.changed = true
			}
			addSource(projectSource(path, errChanged))
			out.Items = nil
		}
	}

	// Cached documents are checked again after the account's merge, so an
	// in-place edit cannot preserve an old parsed command under a stable root.
	if budget.unitCache != nil {
		for path, doc := range cache {
			previous, ok := budget.unitCache.documents[path]
			if !ok {
				continue
			}
			after, err := unitIdentity(doc.root, doc.name)
			if err != nil || !sameInode(previous.before, after) {
				budget.unitCache.changed = true
				addSource(projectSource(path, errChanged))
				out.Items = nil
			}
		}
	}

	for path, dir := range directories {
		if dir.err != nil {
			continue
		}
		pin, e := projectPath(dir.root, dir.name)
		var after unix.Stat_t
		if e == nil {
			e = pin.Fstat(&after)
			_ = pin.Close()
		}
		if e != nil || !sameInode(dir.before, after) {
			if budget.unitCache != nil {
				if _, ok := budget.unitCache.directories[path]; ok {
					budget.unitCache.changed = true
				}
			}
			addSource(projectSource(path, errChanged))
			out.Items = nil
		}
	}

	// A changed directory or root path may have hidden precedence information.
	// Discard all unit evidence rather than accepting stale merge decisions.
	for _, root := range roots {
		var after unix.Stat_t
		e := root.fd.Fstat(&after)
		if e == nil && !sameInode(root.before, after) {
			e = errChanged
		}
		current, _, x := metadataPath(ctx, root.path, false)
		if x != nil {
			e = errChanged
		} else {
			if x = current.Fstat(&after); x != nil || !sameInode(root.before, after) {
				e = errChanged
			}
			_ = current.Close()
		}
		if e != nil {
			if budget.unitCache != nil && budget.unitCache.roots[root.path] {
				budget.unitCache.changed = true
			}
			addSource(projectSource(root.path, e))
			out.Items = nil
		}
	}
	return out
}

func configuredUnitName(name string) bool {
	return plainUnit(name) && (alphaNum(name[0]) || name[0] == '_')
}

type unitAliasPin struct {
	location   unitLocation
	before     unix.Stat_t
	parentRoot int
	parentName string
}

func aliasNamesCompatible(source, target string) bool {
	if !configuredUnitName(target) || filepath.Ext(source) != filepath.Ext(target) {
		return false
	}
	instance := func(name string) (string, bool) {
		stem := strings.TrimSuffix(name, filepath.Ext(name))
		i := strings.IndexByte(stem, '@')
		if i < 0 {
			return "", false
		}
		return stem[i+1:], true
	}
	src, st := instance(source)
	dst, dt := instance(target)
	if st != dt {
		return false
	}
	return !st || src == dst || (src != "" && dst == "")
}

func resolveUnitAlias(ctx context.Context, roots []unitRoot, all map[string]unitLocation, name string, uid uint32, budget *contentBudget) (unitLocation, string, map[string]unitAliasPin, error) {
	pins := map[string]unitAliasPin{}
	seen := map[string]bool{}
	for hops := 0; ; hops++ {
		if e := ctx.Err(); e != nil {
			return unitLocation{}, "", pins, e
		}
		if seen[name] {
			return unitLocation{}, "", pins, errUnsupported
		}
		seen[name] = true
		loc, ok := all[name]
		if !ok {
			stem := strings.TrimSuffix(name, filepath.Ext(name))
			if at := strings.IndexByte(stem, '@'); at > 0 && at < len(stem)-1 {
				loc, ok = all[stem[:at+1]+filepath.Ext(name)]
			}
			if !ok {
				return unitLocation{}, "", pins, errUnsupported
			}
		}
		root := roots[loc.root]
		pin, e := projectPath(root.fd, loc.name)
		if e != nil {
			return unitLocation{}, "", pins, e
		}
		var before unix.Stat_t
		e = pin.Fstat(&before)
		if e != nil {
			_ = pin.Close()
			return unitLocation{}, "", pins, e
		}
		if before.Mode&unix.S_IFMT != unix.S_IFLNK {
			_ = pin.Close()
			return loc, name, pins, nil
		}
		path := filepath.Join(root.path, loc.name)
		pins[path] = unitAliasPin{location: loc, before: before, parentRoot: -1}
		// systemd unit_ids_map_get permits eight lookups, including the final
		// regular unit. The resource allowance is separate from this semantic rule.
		if hops >= 7 {
			_ = pin.Close()
			return unitLocation{}, "", pins, errUnsupported
		}
		if hops == unitAliasHops {
			_ = pin.Close()
			return unitLocation{}, "", pins, errLimit
		}
		// A failed owner check must still invalidate earlier account merges
		// that used this cached alias under its prior trusted identity.
		if budget.unitCache != nil {
			if previous, ok := budget.unitCache.aliases[path]; ok && !sameInode(previous.before, before) {
				budget.unitCache.changed = true
				_ = pin.Close()
				return unitLocation{}, "", pins, errChanged
			}
		}
		if before.Uid != unitReadOwner(root.path, uid, budget) && before.Uid != 0 {
			_ = pin.Close()
			return unitLocation{}, "", pins, errOwner
		}
		target, e := readUnitAlias(pin, before, root.path, path, budget)
		_ = pin.Close()
		if e != nil {
			return unitLocation{}, "", pins, e
		}
		if target == "" || !plainPath("/"+strings.TrimPrefix(target, "/")) {
			return unitLocation{}, "", pins, errUnsupported
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(root.path, target)
		}
		target = filepath.Clean(target)
		inside := -1
		for i, r := range roots {
			if strings.HasPrefix(target, r.path+string(filepath.Separator)) && (inside < 0 || len(r.path) > len(roots[inside].path)) {
				inside = i
			}
		}
		if inside < 0 {
			return unitLocation{}, "", pins, unix.ELOOP
		}
		parent, e := filepath.Rel(roots[inside].path, filepath.Dir(target))
		if e != nil {
			return unitLocation{}, "", pins, errUnsupported
		}
		v := pins[path]
		v.parentRoot = inside
		v.parentName = parent
		pins[path] = v
		if e = unitAliasParent(roots[inside].fd, parent); e != nil {
			return unitLocation{}, "", pins, e
		}
		next := filepath.Base(target)
		if !aliasNamesCompatible(name, next) {
			return unitLocation{}, "", pins, errUnsupported
		}
		// An instance alias may name a template; propagate its instance exactly
		// as systemd does without reading or expanding arbitrary file values.
		ext := filepath.Ext(next)
		if strings.HasSuffix(strings.TrimSuffix(next, ext), "@") {
			stem := strings.TrimSuffix(name, filepath.Ext(name))
			if at := strings.IndexByte(stem, '@'); at >= 0 && at < len(stem)-1 {
				next = strings.TrimSuffix(next, ext) + stem[at+1:] + ext
			}
		}
		name = next
	}
}

// Alias destination paths are not data sources. Inspect existing parents only
// to refuse a path that would escape through a directory symlink. Missing
// parents are allowed because systemd aliases can have dangling targets.
func unitAliasParent(root *sys.FD, name string) error {
	pin, e := projectPath(root, name)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	defer func() { _ = pin.Close() }()
	var st unix.Stat_t
	if e = pin.Fstat(&st); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.ELOOP
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errType
	}
	return nil
}
