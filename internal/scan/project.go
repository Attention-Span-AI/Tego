// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"io"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"golang.org/x/sys/unix"
)

type projectObservation struct {
	ID, Name, Path string
	Dependency     *string
}
type projectSnapshot struct {
	Items   []projectObservation
	Sources []processSource
	Limits  []string
}

var errProjectMode = errors.New("project file mode")

var projectMarkers = []struct{ path, id, name string }{{"langgraph.json", "marker-langgraph", "langgraph"}, {"crew.jsonc", "marker-crew", "crewai"}, {"config/agents.yaml", "marker-agents", "agents"}}

// projectPath cannot cross a mount (including bind mounts) or any link beneath
// the explicitly selected root. No directory enumeration is needed for F.
func projectPath(root *sys.FD, name string) (*sys.FD, error) {
	return openProjectPath(root, name, (*sys.FD).Openat2)
}

// openProjectPath opens name beneath root through open, (*sys.FD).Openat2 outside tests, so the number is owned at
// birth (ADR 0023).
func openProjectPath(root *sys.FD, name string, open func(*sys.FD, string, *unix.OpenHow) (*sys.FD, error)) (*sys.FD, error) {
	return open(root, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
}
func collectProject(ctx context.Context, cwd string, uid, gid uint32) projectSnapshot {
	out := projectSnapshot{Items: []projectObservation{}, Sources: []processSource{}, Limits: []string{}}
	root, _, err := metadataPath(ctx, cwd, false)
	if err != nil {
		out.Sources = append(out.Sources, projectSource(cwd, err))
		return out
	}
	defer func() { _ = root.Close() }()
	var st unix.Stat_t
	if err = root.Fstat(&st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err == nil {
			err = errType
		}
		out.Sources = append(out.Sources, projectSource(cwd, err))
		return out
	}
	for _, name := range []string{"package.json", "requirements.txt", "langgraph.json", "crew.jsonc", "config/agents.yaml"} {
		path := filepath.Join(cwd, name)
		if err = ctx.Err(); err != nil {
			out.Sources = append(out.Sources, projectSource(path, err))
			out.Limits = appendUnique(out.Limits, "deadline")
			break
		}
		pin, e := projectPath(root, name)
		if e != nil {
			out.Sources = append(out.Sources, projectSource(path, e))
			continue
		}
		items, e := readProjectPath(ctx, root, pin, name, path, uid, gid)
		_ = pin.Close()
		out.Sources = append(out.Sources, projectSource(path, e))
		if e == nil {
			out.Items = append(out.Items, items...)
		}
		if errors.Is(e, errLimit) {
			out.Limits = appendUnique(out.Limits, "parse-limit")
		}
		if errors.Is(e, errSize) {
			out.Limits = appendUnique(out.Limits, "byte-limit")
		}
	}
	return out
}
func projectSource(path string, err error) processSource {
	s := procSource(path, err, false)
	if errors.Is(err, errProjectMode) {
		s.Reason = "mode"
	}
	if errors.Is(err, unix.ENOENT) {
		s.State = "missing"
		s.Reason = "none"
		s.Read = 0
		s.NotRead = 0
	}
	if errors.Is(err, unix.EXDEV) {
		s.Reason = "mount"
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
		s.Reason = "unsupported"
	}
	return s
}
func readProjectPath(ctx context.Context, root, pin *sys.FD, name, path string, uid, gid uint32) ([]projectObservation, error) {
	parser := parseJSONDependencies
	if name == "requirements.txt" {
		parser = parseRequirements
	}
	return readProjectPathWith(ctx, root, pin, name, path, uid, gid, parser)
}

func readProjectPathWith(ctx context.Context, root, pin *sys.FD, name, path string, uid, gid uint32, parser func(context.Context, io.Reader) ([]catalog.Dependency, error)) ([]projectObservation, error) {
	var before unix.Stat_t
	if err := pin.Fstat(&before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, unix.ELOOP
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return nil, errType
	}
	if before.Uid != uid && before.Uid != 0 {
		return nil, errOwner
	}
	if err := checkPinnedMode(ctx, pin, before, uid); err != nil {
		return nil, err
	}
	recheckParents, err := contentParents(ctx, root, name, uid)
	if err != nil {
		return nil, err
	}
	var out []projectObservation
	if name == "package.json" || name == "requirements.txt" {
		if before.Size < 0 || before.Size > manifestBytes {
			return nil, errSize
		}
		var fd *sys.FD
		err := pin.ProcPath(func(path string) error {
			var e error
			fd, e = sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
			return e
		})
		if err != nil {
			return nil, err
		}
		f, err := fd.Release("scan-manifest")
		if err != nil {
			_ = fd.Close()
			return nil, err
		}
		defer func() { _ = f.Close() }()
		var opened unix.Stat_t
		if err = sys.FstatFile(f, &opened); err != nil {
			return nil, err
		}
		if !sameInode(before, opened) {
			return nil, errChanged
		}
		var deps []catalog.Dependency
		r := io.LimitReader(f, manifestBytes+1)
		deps, err = parser(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, d := range deps {
			id := d.ID
			out = append(out, projectObservation{ID: id, Name: d.Name, Path: path, Dependency: &id})
		}
		if err = sys.FstatFile(f, &opened); err != nil {
			return nil, err
		}
		if !sameInode(before, opened) {
			return nil, errChanged
		}
	} else {
		for _, m := range projectMarkers {
			if name == m.path {
				out = append(out, projectObservation{ID: m.id, Name: m.name, Path: path})
			}
		}
	}
	current, err := projectPath(root, name)
	if err != nil {
		return nil, errChanged
	}
	defer func() { _ = current.Close() }()
	var after unix.Stat_t
	if err = current.Fstat(&after); err != nil {
		return nil, err
	}
	if !sameInode(before, after) {
		return nil, errChanged
	}
	return out, recheckParents()
}
