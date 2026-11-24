// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
)

type metadataBudgetKey struct{}
type metadataBudget struct{ remaining int }

// metadataPath pins each component. Only B may resolve links, with eight hops
// across the whole path. O_PATH never opens program or settings contents.
func metadataPath(ctx context.Context, path string, links bool) (*sys.FD, string, error) {
	if !plainPath(path) || filepath.Clean(path) != path {
		return nil, "", errSyntax
	}
	root, err := sys.Own(unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, "", err
	}
	stack := []*sys.FD{root}
	names := []string{}
	defer func() {
		for _, d := range stack {
			_ = d.Close()
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	hops, steps := 0, 0
	for len(parts) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		steps++
		if steps > 512 {
			return nil, "", errLimit
		}
		name := parts[0]
		parts = parts[1:]
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			if len(stack) > 1 {
				_ = stack[len(stack)-1].Close()
				stack = stack[:len(stack)-1]
				names = names[:len(names)-1]
			}
			continue
		}
		fd, err := stack[len(stack)-1].Openat(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, "", err
		}
		var st unix.Stat_t
		if err := fd.Fstat(&st); err != nil {
			_ = fd.Close()
			return nil, "", err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			if !links {
				_ = fd.Close()
				return nil, "", unix.ELOOP
			}
			hops++
			if hops > 8 {
				_ = fd.Close()
				return nil, "", errLimit
			}

			budget, _ := ctx.Value(metadataBudgetKey{}).(*metadataBudget)
			if budget != nil && budget.remaining < maxProcText+1 {
				_ = fd.Close()
				return nil, "", errLimit
			}
			buf := make([]byte, maxProcText+1)
			n := 0
			err = fd.Borrow(func(raw int) error { var e error; n, e = unix.Readlinkat(raw, "", buf); return e })
			_ = fd.Close()
			if budget != nil {
				cost := n
				if err != nil {
					cost = maxProcText + 1
				}
				budget.remaining -= cost
			}
			if err != nil {
				return nil, "", err
			}
			if n > maxProcText {
				return nil, "", errSize
			}
			target := string(buf[:n])
			if target == "" || !plainPath("/"+strings.TrimPrefix(target, "/")) {
				return nil, "", errSyntax
			}
			if strings.HasPrefix(target, "/") {
				for len(stack) > 1 {
					_ = stack[len(stack)-1].Close()
					stack = stack[:len(stack)-1]
				}
				names = nil
			}
			parts = append(strings.Split(target, "/"), parts...)
			continue
		}
		names = append(names, name)
		if len(parts) == 0 {
			target := "/" + strings.Join(names, "/")
			if !plainPath(target) {
				_ = fd.Close()
				return nil, "", errSize
			}
			return fd, target, nil
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = fd.Close()
			return nil, "", errType
		}
		stack = append(stack, fd)
	}
	// A directory such as a link to '/' is still pinned, but never executable.
	fd, err := stack[len(stack)-1].Openat(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	return fd, "/" + strings.Join(names, "/"), err
}

type fileObservation struct {
	RuleID, Name, Path, Target, FileType string
	Mtime                                time.Time
}
type metadataSnapshot struct {
	Programs, Settings []fileObservation
	Sources            []metadataSource
	Limits             []string
}
type metadataSource struct {
	processSource
	Kind string
}

// collectMetadata has no content-reading operation. Fixed catalog paths are
// expanded only one level; PATH is metadata input, never a launch command.
func collectMetadata(ctx context.Context, home, cwd, path string, uid uint32, rows []catalog.Row) metadataSnapshot {
	budget := &metadataBudget{remaining: 1 << 20}
	ctx = context.WithValue(ctx, metadataBudgetKey{}, budget)
	out := metadataSnapshot{Programs: []fileObservation{}, Settings: []fileObservation{}, Sources: []metadataSource{}, Limits: []string{}}
	seen := map[string]bool{}
	candidates := 0
	limited := map[string]bool{}
	sourceBytes, itemBytes := 0, 0
	addSource := func(kind, path string, err error) bool {
		if limited[kind] {
			return false
		}
		if path != "" && !plainPath(path) {
			path = ""
		}
		v := procSource(path, err, false)
		if errors.Is(err, os.ErrNotExist) {
			v.State = "missing"
			v.Reason = "none"
			v.NotRead = 0
		}
		next := metadataSource{v, kind}
		encoded, _ := json.Marshal(next)
		if len(out.Sources) >= 1900 || sourceBytes+len(encoded) > 400<<10 {
			out.Sources = append(out.Sources, metadataSource{procSource("", errLimit, false), kind})
			out.Limits = append(out.Limits, "source-limit")
			limited[kind] = true
			return false
		}
		sourceBytes += len(encoded)
		out.Sources = append(out.Sources, next)
		return true
	}
	limit := func(kind, path, code string) {
		if !limited[kind] {
			addSource(kind, path, errLimit)
			out.Limits = append(out.Limits, code)
			limited[kind] = true
		}
	}
	inspect := func(kind, path string, r catalog.Row) {
		key := kind + ":" + path
		if seen[key] || limited[kind] {
			return
		}
		seen[key] = true
		if ctx.Err() != nil {
			addSource(kind, path, ctx.Err())
			limited[kind] = true
			out.Limits = append(out.Limits, "deadline")
			return
		}
		candidates++
		if candidates > 2048 {
			limit(kind, path, "file-limit")
			return
		}
		if len(out.Programs)+len(out.Settings) >= 512 || len(out.Sources) >= 1900 {
			limit(kind, path, "item-limit")
			return
		}
		fd, target, err := metadataPath(ctx, path, kind == "B")
		if err != nil {
			addSource(kind, path, err)
			return
		}
		defer func() { _ = fd.Close() }()
		var st unix.Stat_t
		if err = fd.Fstat(&st); err != nil {
			addSource(kind, path, err)
			return
		}
		typ := st.Mode & unix.S_IFMT
		fileType := "executable"
		if kind == "B" {
			if typ != unix.S_IFREG || st.Mode&0111 == 0 {
				addSource(kind, path, errType)
				return
			}
		} else {
			if st.Uid != uid {
				addSource(kind, path, errOwner)
				return
			}
			switch typ {
			case unix.S_IFREG:
				fileType = "file"
			case unix.S_IFDIR:
				fileType = "directory"
			default:
				addSource(kind, path, errType)
				return
			}
		}
		var after unix.Stat_t
		if err = fd.Fstat(&after); err != nil {
			addSource(kind, path, err)
			return
		}
		if !sameInode(st, after) {
			addSource(kind, path, errChanged)
			return
		}
		name, valid := catalog.ObservedName(r.ID)
		if !valid {
			addSource(kind, path, errSyntax)
			return
		}
		v := fileObservation{RuleID: r.ID, Name: name, Path: path, FileType: fileType, Mtime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC()}
		if kind == "B" && target != path {
			v.Target = target
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			addSource(kind, path, errUnsupported)
			return
		}
		if itemBytes+len(encoded) > 500<<10 {
			limit(kind, path, "item-limit")
			return
		}
		if !addSource(kind, path, nil) {
			return
		}
		itemBytes += len(encoded)
		if kind == "B" {
			out.Programs = append(out.Programs, v)
		} else {
			out.Settings = append(out.Settings, v)
		}
	}
	dirs := []string{}
	excluded := 0
	if len(path) > 64<<10 {
		addSource("B", "", errLimit)
		out.Limits = append(out.Limits, "path-limit")
		path = ""
		limited["B"] = true
	}
	for _, dir := range strings.Split(path, ":") {
		if limited["B"] {
			break
		}
		if !plainPath(dir) || filepath.Clean(dir) != dir {
			// Do not retain an unsafe or relative PATH spelling as a locator.
			excluded++
			continue
		}
		if len(dirs) == 64 {
			addSource("B", dir, errLimit)
			out.Limits = append(out.Limits, "path-limit")
			break
		}
		dirs = append(dirs, dir)
	}
	if excluded > 0 {
		out.Sources = append(out.Sources, metadataSource{processSource: processSource{State: "excluded", Reason: "scope", NotRead: excluded}, Kind: "B"})
	}
	// A bounded local virtual environment is included without accepting a relative PATH entry.
	if plainPath(cwd) {
		dirs = append(dirs, filepath.Join(cwd, ".venv/bin"))
	}
	for _, r := range rows {
		for _, dir := range dirs {
			for _, program := range r.Programs {
				inspect("B", filepath.Join(dir, program), r)
			}
		}
		for _, rel := range r.Install {
			path := filepath.Join(home, rel)
			if !strings.HasSuffix(rel, "/*") {
				inspect("B", path, r)
				continue
			}
			dir := strings.TrimSuffix(path, "/*")
			if limited["B"] {
				continue
			}
			names, err := catalogGlob(ctx, dir)
			if !addSource("B", dir, err) {
				continue
			}
			out.Sources[len(out.Sources)-1].Read = 0
			if errors.Is(err, errLimit) {
				out.Limits = append(out.Limits, "glob-limit")
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				out.Limits = append(out.Limits, "deadline")
			}
			for _, name := range names {
				inspect("B", filepath.Join(dir, name), r)
			}
		}
		for _, rel := range r.Settings {
			inspect("C", filepath.Join(home, rel), r)
		}
	}
	if budget.remaining < maxProcText+1 {
		out.Limits = appendUnique(out.Limits, "byte-limit")
	}
	return out
}

func catalogGlob(ctx context.Context, path string) ([]string, error) {
	pin, _, err := metadataPath(ctx, path, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pin.Close() }()
	fd, err := pin.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f, err := fd.Release("scan-catalog-directory")
	if err != nil {
		_ = fd.Close()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return catalogNames(ctx, openCatalogDirectory{f})
}

type catalogDirectory interface {
	names(int) ([]string, error)
	stat() (unix.Stat_t, error)
}
type openCatalogDirectory struct{ file *os.File }

func (d openCatalogDirectory) names(n int) ([]string, error) { return d.file.Readdirnames(n) }
func (d openCatalogDirectory) stat() (unix.Stat_t, error) {
	var st unix.Stat_t
	err := sys.FstatFile(d.file, &st)
	return st, err
}

func catalogNames(ctx context.Context, dir catalogDirectory) ([]string, error) {
	return catalogNamesLimit(ctx, dir, 256)
}

func catalogNamesLimit(ctx context.Context, dir catalogDirectory, limit int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, e := dir.stat()
	if e != nil {
		return nil, e
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errType
	}
	names, err := dir.names(limit + 1)
	after, e := dir.stat()
	if e != nil {
		return nil, e
	}
	if !sameInode(before, after) {
		return nil, errChanged
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}

	if errors.Is(err, os.ErrNotExist) {
		return nil, errChanged
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > limit {
		names = names[:limit]
		err = errLimit
	} else {
		err = nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if !plainPath("/" + name) {
			return nil, errSyntax
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, err
}
