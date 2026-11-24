// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

type checkedUnitDirectory struct {
	err    error
	names  []string
	before unix.Stat_t
}

type checkedUnitDocument struct {
	doc    unitDocument
	err    error
	before unix.Stat_t
}

type checkedUnitAlias struct {
	target string
	err    error
	before unix.Stat_t
}

// Machine input is shared, but precedence is recalculated for each account.
// Cached data never owns descriptors. Every reuse compares the current pinned
// identity, and collectUnits rechecks directories and roots after the merge.
type unitReadCache struct {
	changed     bool
	roots       map[string]bool
	uid         uint32
	directories map[string]checkedUnitDirectory
	documents   map[string]checkedUnitDocument
	aliases     map[string]checkedUnitAlias
	read        map[string]map[string]bool
}

func newUnitReadCache(roots []string, uid uint32) *unitReadCache {
	c := &unitReadCache{roots: map[string]bool{}, uid: uid, directories: map[string]checkedUnitDirectory{}, documents: map[string]checkedUnitDocument{}, aliases: map[string]checkedUnitAlias{}, read: map[string]map[string]bool{}}
	for _, root := range roots {
		c.roots[root] = true
	}
	return c
}

func unitReadOwner(path string, uid uint32, budget *contentBudget) uint32 {
	if budget.unitCache != nil && budget.unitCache.roots[path] {
		return budget.unitCache.uid
	}
	return uid
}

func unitIdentity(root *sys.FD, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	pin, err := projectPath(root, name)
	if err != nil {
		return st, err
	}
	defer func() { _ = pin.Close() }()
	err = pin.Fstat(&st)
	return st, err
}

func readUnitDocument(ctx context.Context, root *sys.FD, path, name string, uid uint32, budget *contentBudget) (unitDocument, error) {
	cache := budget.unitCache
	key := filepath.Join(path, name)
	if cache == nil || !cache.roots[path] {
		var doc unitDocument
		err := readContent(ctx, root, name, uid, budget, func(r io.Reader) error { var err error; doc, err = parseUnit(ctx, r); return err })
		return doc, err
	}
	before, err := unitIdentity(root, name)
	if err != nil {
		if _, ok := cache.documents[key]; ok {
			cache.changed = true
			return unitDocument{}, errChanged
		}
		return unitDocument{}, err
	}
	if v, ok := cache.documents[key]; ok {
		if !sameInode(before, v.before) {
			cache.changed = true
			return unitDocument{}, errChanged
		}
		return v.doc, v.err
	}
	v := checkedUnitDocument{before: before}
	v.err = readContent(ctx, root, name, cache.uid, budget, func(r io.Reader) error { var err error; v.doc, err = parseUnit(ctx, r); return err })
	after, err := unitIdentity(root, name)
	if err != nil || !sameInode(before, after) {
		cache.changed = true
		v.doc, v.err = unitDocument{}, errChanged
	}
	cache.documents[key] = v
	return v.doc, v.err
}

func (c *unitReadCache) source(v processSource) processSource {
	if v.State != "read" {
		return v
	}
	for root := range c.roots {
		if v.Path != root && !strings.HasPrefix(v.Path, root+string(filepath.Separator)) {
			continue
		}
		if c.read[root] == nil {
			c.read[root] = map[string]bool{}
		}
		if v.Read > 0 {
			c.read[root][v.Path] = true
		}
		v.Path, v.Read = root, 0
		return v
	}
	return v
}

func (c *unitReadCache) summarize(users, system *unitSnapshot) {
	exact := map[string]bool{}
	for _, sources := range [][]processSource{users.Sources, system.Sources} {
		for _, src := range sources {
			if src.State == "read" && !c.roots[src.Path] {
				exact[src.Path] = true
			}
		}
	}
	for _, snapshot := range []*unitSnapshot{users, system} {
		for i := range snapshot.Sources {
			src := &snapshot.Sources[i]
			if src.State != "read" || !c.roots[src.Path] {
				continue
			}
			for path := range c.read[src.Path] {
				if !exact[path] {
					src.Read++
				}
			}
		}
	}
}

// Reuse link text only after checking the pinned alias inode. The target name
// still goes through the current account's load-path and parent checks.
func readUnitAlias(pin *sys.FD, before unix.Stat_t, root, path string, budget *contentBudget) (string, error) {
	cache := budget.unitCache
	if cache != nil && cache.roots[root] {
		if v, ok := cache.aliases[path]; ok {
			if !sameInode(before, v.before) {
				cache.changed = true
				return "", errChanged
			}
			return v.target, v.err
		}
	}
	if budget.remaining <= 0 {
		return "", errLimit
	}
	// Reserve the complete limit-plus-one buffer on the first read, including
	// failures. Account-specific alias reads always spend their own allowance.
	allowance := min(4097, budget.remaining)
	buf := make([]byte, allowance)
	budget.remaining -= allowance
	var n int
	err := pin.Borrow(func(raw int) error { var err error; n, err = unix.Readlinkat(raw, "", buf); return err })
	if err == nil && n == len(buf) {
		err = errSize
		if allowance < 4097 {
			err = errLimit
		}
	}
	target := ""
	if err == nil {
		target = string(buf[:n])
	}
	if cache != nil && cache.roots[root] {
		cache.aliases[path] = checkedUnitAlias{target: target, err: err, before: before}
	}
	return target, err
}

func (c *unitReadCache) finish(users, system *unitSnapshot) {
	c.summarize(users, system)
	if c.changed {
		// Every account merge used shared machine precedence. A later change
		// invalidates earlier dependent observations as well as the current one.
		users.Items, system.Items = nil, nil
	}
}
