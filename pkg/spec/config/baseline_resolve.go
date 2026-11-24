// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// BaselineOwner is the agent owner's compile context, including during another user's adoption.
// Home must come from that owner's passwd/WithHome context, never the caller's environment.
type BaselineOwner struct {
	UID  int
	Home string
}

// ResolvedBaselineEntry retains the declared spelling and the expanded kernel-walk spelling.
// An absent system entry is a candidate ancestor/name guard, not permission to launch: the later
// materializer must prove the selected mechanism can hold it, including surrounding grant checks.
type ResolvedBaselineEntry struct {
	BaselineEntry
	Expanded string
	State    LayerState // present for non-path entries too; absent only for system-only missing paths
	Target   string     // resolved existing target; empty when absent
	Ancestor string     // nearest existing directory for an absent row
	Missing  string     // remaining names below Ancestor; never lexically cleaned
	Device   uint64
	Inode    uint64
}

// ResolvedBaseline is a detached owner-specific resolution result. It asserts no tier coverage.
type ResolvedBaseline struct {
	Owner   BaselineOwner
	Entries []ResolvedBaselineEntry
}

// Resolve expands paths only against owner.Home, then resolves target metadata and supported absence.
// It checks no ownership or write authority and creates nothing. Compile supplies the governed owner context.
// A missing target is retained only if every source is the system layer; all other errors stop
// resolution with its source and owner context. No resolved home means no absolute ~/ target.
func (b Baseline) Resolve(owner BaselineOwner) (ResolvedBaseline, error) {
	if b.unknown {
		return ResolvedBaseline{}, fmt.Errorf("machine baseline is UNKNOWN: repair unreadable or untrusted config layers before resolving rules")
	}
	r := ResolvedBaseline{Owner: owner}
	for _, entry := range b.Entries() {
		e := ResolvedBaselineEntry{BaselineEntry: entry, Expanded: entry.Value, State: LayerPresent}
		if entry.Key != BaselineDenyRead && entry.Key != BaselineDenyWrite {
			r.Entries = append(r.Entries, e)
			continue
		}
		fail := func(err error) (ResolvedBaseline, error) {
			return ResolvedBaseline{}, fmt.Errorf("%s layer %s: baseline.%s %q (owner uid %d, home %q, sources %v): %w; use an absolute existing target, or remove this baseline entry",
				entry.Sources[0].Layer, entry.Sources[0], entry.Key, entry.Value, owner.UID, owner.Home, entry.Sources, err)
		}
		if strings.HasPrefix(e.Expanded, "~/") {
			if owner.Home == "" || !filepath.IsAbs(owner.Home) {
				return ResolvedBaseline{}, fmt.Errorf("%s layer %s: baseline.%s %q: no resolved absolute agent-owner home for owner uid %d; give the entry an absolute path, or run as a user with a passwd entry",
					entry.Sources[0].Layer, entry.Sources[0], entry.Key, entry.Value, owner.UID)
			}
			// Join/Clean would change a symlink followed by '..'.
			e.Expanded = strings.TrimSuffix(owner.Home, "/") + "/" + e.Expanded[2:]
		}
		if via, proc := ThroughProc(e.Expanded); proc {
			return fail(fmt.Errorf("target reaches process-relative procfs at %s", via))
		}
		target, ancestor, missing, st, err := resolveBaselinePath(e.Expanded)
		if err != nil {
			return fail(err)
		}
		if missing != "" {
			for _, source := range entry.Sources {
				if source.Layer != LayerEtc {
					return fail(fmt.Errorf("target is absent in %s layer: %w", source.Layer, fs.ErrNotExist))
				}
			}
			e.State, e.Ancestor, e.Missing = LayerAbsent, ancestor, missing
		} else {
			e.Target = target
		}
		e.Device, e.Inode = uint64(st.Dev), st.Ino
		r.Entries = append(r.Entries, e)
	}
	return r, nil
}

// resolveBaselinePath follows links before '..', as the kernel does. For absence it stops at the
// first missing component, retaining the existing ancestor and unresolved suffix. A '..' after a
// missing component cannot be walked and is refused instead of being erased into another target.
func resolveBaselinePath(path string) (target, ancestor, missing string, st *syscall.Stat_t, err error) {
	if !filepath.IsAbs(path) {
		return "", "", "", nil, fmt.Errorf("target is not absolute")
	}
	type component struct {
		name, link string
	}
	components := func(path, link string) []component {
		names := strings.Split(path, "/")
		out := make([]component, len(names))
		for i, name := range names {
			out[i] = component{name: name, link: link}
		}
		return out
	}
	pending, resolved, links := components(path, ""), "/", 0
	for len(pending) > 0 {
		next := pending[0]
		part := next.name
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		comp := strings.TrimSuffix(resolved, "/") + "/" + part
		fi, e := os.Lstat(comp)
		if e != nil {
			if !errors.Is(e, fs.ErrNotExist) {
				return "", "", "", nil, e
			}
			if next.link != "" {
				return "", "", "", nil, fmt.Errorf("%s: dangling symlink: %w", next.link, e)
			}
			parts := []string{part}
			for _, p := range pending {
				parts = append(parts, p.name)
			}
			for _, p := range parts {
				if p == ".." {
					return "", "", "", nil, fmt.Errorf("cannot place '..' beneath a missing target: %w", e)
				}
			}
			// The walk resolved this spelling already. I10 permits only no-follow
			// metadata above an absent layer's containing folder.
			fi, e = os.Lstat(resolved)
			if e != nil {
				return "", "", "", nil, e
			}
			if !fi.IsDir() {
				return "", "", "", nil, fmt.Errorf("absent target has no directory ancestor")
			}
			return "", resolved, strings.Join(parts, "/"), fi.Sys().(*syscall.Stat_t), nil
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			links++
			if links > maxProcHops {
				return "", "", "", nil, syscall.ELOOP
			}
			t, e := os.Readlink(comp)
			if e != nil {
				return "", "", "", nil, e
			}
			if filepath.IsAbs(t) {
				resolved = "/"
			}
			pending = append(components(t, comp), pending...)
			continue
		}
		if len(pending) > 0 && !fi.IsDir() {
			return "", "", "", nil, fmt.Errorf("%s: %w", comp, syscall.ENOTDIR)
		}
		if part == ".." {
			resolved = filepath.Dir(resolved)
		} else {
			resolved = filepath.Join(resolved, part)
		}
	}
	fi, e := os.Stat(resolved)
	if e != nil {
		return "", "", "", nil, e
	}
	return resolved, "", "", fi.Sys().(*syscall.Stat_t), nil
}
