// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// MaxCatalogEntries bounds one registry listing. A cut is reported, never hidden.
const MaxCatalogEntries = 4096

// MaxCatalogBytes bounds source bytes retained by one catalog listing.
const MaxCatalogBytes = 32 << 20

// ErrCatalogBound identifies a cut in catalog discovery or retained source bytes.
var ErrCatalogBound = errors.New("catalog resource bound")

// CatalogRoot is a place the registry looked, including absent and unreadable places.
type CatalogRoot struct {
	Path, Kind, State string
	Err               error
}

// CatalogEntry is a file found in a registry, including a file that cannot be loaded.
// Data is read through the registry's checked descriptor, as Resolve reads it.
type CatalogEntry struct {
	Entry
	Cwd string
	Err error
}

// FileIdentity names the checked descriptor across a read-only helper reply.
// It never stats or reopens a path; absent identity must never alias an entry.
func (e Entry) FileIdentity() (dev, ino uint64, ok bool) {
	if e.file == nil {
		return 0, 0, false
	}
	st, ok := e.file.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), st.Ino, true
}

// CatalogContext lists the same places Resolve consults, without resolving names against
// each other. This preserves ambiguous names and broken entries for read-only views.
// It never searches below a project or outside a registry's agents directory.
func (p Places) CatalogContext(ctx context.Context) ([]CatalogEntry, []CatalogRoot) {
	return p.catalogContext(ctx, Places.placed)
}

func (p Places) catalogContext(ctx context.Context, place func(Places) (Places, *Error)) ([]CatalogEntry, []CatalogRoot) {
	if err := ctx.Err(); err != nil {
		return nil, []CatalogRoot{{Path: p.Dir, Kind: "registry", State: "unreadable", Err: err}}
	}
	placed, err := place(p)
	if err := ctx.Err(); err != nil {
		return nil, []CatalogRoot{{Path: p.Dir, Kind: "registry", State: "unreadable", Err: err}}
	}
	if err != nil {
		return nil, []CatalogRoot{{Path: err.Path, Kind: "registry", State: "unreadable", Err: err}}
	}
	p = placed
	var entries []CatalogEntry
	var roots []CatalogRoot
	bytes := 0
	appendEntry := func(e CatalogEntry) {
		if bytes+len(e.Data) > MaxCatalogBytes {
			e.Data = nil
			e.Err = fmt.Errorf("%w: registry sources exceed %d bytes; this contract was not checked", ErrCatalogBound, MaxCatalogBytes)
		} else {
			bytes += len(e.Data)
		}
		entries = append(entries, e)
	}
	if p.Dir != "" {
		path := filepath.Join(p.Dir, ProjectFile)
		e := p.catalogEntry(ctx, p.Dir, ProjectFile, path, "", Project)
		state := catalogState(e.Err)
		roots = append(roots, CatalogRoot{Path: path, Kind: Project, State: state, Err: e.Err})
		if state != "absent" {
			appendEntry(e)
		}
	}
	for _, loc := range []struct{ root, kind string }{{projectRoot(p.Dir), Project}, {p.User, User}} {
		if loc.root == "" {
			continue
		}
		path := filepath.Join(loc.root, AgentsDir)
		if err := ctx.Err(); err != nil {
			roots = append(roots, CatalogRoot{Path: path, Kind: loc.kind, State: "unreadable", Err: err})
			return entries, roots
		}
		names, err := p.catalogNames(ctx, loc.root, path)
		if len(names) > MaxCatalogEntries {
			err = fmt.Errorf("%w: registry listing exceeds %d entries; some contracts are missing", ErrCatalogBound, MaxCatalogEntries)
			names = names[:MaxCatalogEntries]
		}
		// A missing directory is ordinary for a registry not used yet.
		if errors.Is(err, syscall.ENOENT) {
			roots = append(roots, CatalogRoot{Path: path, Kind: loc.kind, State: "absent", Err: err})
			continue
		}
		roots = append(roots, CatalogRoot{Path: path, Kind: loc.kind, State: catalogState(err), Err: err})
		slices.SortFunc(names, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		for _, n := range names {
			if err := ctx.Err(); err != nil {
				roots = append(roots, CatalogRoot{Path: path, Kind: loc.kind, State: "unreadable", Err: err})
				return entries, roots
			}
			name, ok := strings.CutSuffix(n.Name(), ".yaml")
			if !ok {
				continue
			}
			appendEntry(p.catalogEntry(ctx, loc.root, filepath.Join(AgentsDir, n.Name()),
				filepath.Join(path, n.Name()), name, loc.kind))
		}
	}
	return entries, roots
}

func (p Places) catalogNames(ctx context.Context, root, path string) ([]os.DirEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := r.OpenFile(AgentsDir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.CheckTrusted(d, path, p.UID); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	df, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = df.Close() }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.CheckTrusted(df, root, p.UID); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names, err := d.ReadDir(MaxCatalogEntries + 1)
	if ctx.Err() != nil {
		return names, ctx.Err()
	}
	// ReadDir(n) returns EOF for an empty or short final batch.
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return names, err
}

func projectRoot(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, ProjectDir)
}

func catalogState(err error) string {
	if err == nil {
		return "present"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "absent"
	}
	return "unreadable"
}

func (p Places) catalogEntry(ctx context.Context, root, rel, path, name, kind string) CatalogEntry {
	e := CatalogEntry{Entry: Entry{Name: name, Registry: kind, Path: path}, Cwd: p.Dir}
	if e.Err = ctx.Err(); e.Err != nil {
		return e
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		e.Err = err
		return e
	}
	defer func() { _ = r.Close() }()
	ar := r
	if name != "" {
		if e.Err = ctx.Err(); e.Err != nil {
			return e
		}
		ar, err = r.OpenRoot(AgentsDir)
		if err != nil {
			e.Err = err
			return e
		}
		defer func() { _ = ar.Close() }()
		rel = filepath.Base(rel)
	}
	if e.Err = ctx.Err(); e.Err != nil {
		return e
	}
	f, fi, data, err := readEntry(ar, rel, path, root)
	if err != nil {
		e.Err = err
		return e
	}
	defer func() { _ = f.Close() }()
	if e.Err = ctx.Err(); e.Err != nil {
		return e
	}
	if err = config.CheckTrusted(f, path, p.UID); err == nil && name != "" {
		for _, d := range []*os.Root{r, ar} {
			if err = ctx.Err(); err != nil {
				break
			}
			df, derr := d.Open(".")
			if derr != nil {
				err = derr
				break
			}
			if err = ctx.Err(); err == nil {
				err = config.CheckTrusted(df, root, p.UID)
			}
			_ = df.Close()
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		if err = ctx.Err(); err == nil {
			_, err = p.notOwn(&Entry{Path: path})
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	e.Err = err
	if err == nil {
		e.Data, e.file = data, fi
		if name == "" {
			e.Name, _ = nameOf(data)
		} // bad YAML stays in Data for the full loader's diagnostic
	}
	return e
}
