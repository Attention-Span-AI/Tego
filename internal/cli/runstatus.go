// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

// runStatusWriter holds the private directory across both atomic replacements.
// It never opens the destination for writing, including a planted link.
type runStatusWriter struct {
	dir          *sys.FD
	parent, name string
	previous     *unix.Stat_t
}

func openRunStatusWriter(path string, rt *agent.RuleTable) (*runStatusWriter, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("--status-file requires an absolute clean file path")
	}
	parent := filepath.Dir(path)
	if err := statusOutsideWrites(parent, rt); err != nil {
		return nil, err
	}
	dir, err := openDirectoryNoLinks(parent)
	if err != nil {
		return nil, err
	}
	w := &runStatusWriter{dir: dir, parent: parent, name: filepath.Base(path)}
	if err := w.checkParent(); err != nil {
		_ = dir.Close()
		return nil, err
	} // cleanup of unopened output
	var st unix.Stat_t
	if err := dir.Fstatat(w.name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		_ = dir.Close() // cleanup of unopened output
		if err == nil {
			return nil, errors.New("--status-file destination already exists; use a fresh private directory")
		}
		return nil, fmt.Errorf("--status-file destination: %w", err)
	}
	return w, nil
}

// openDirectoryNoLinks walks an absolute directory without following any component link. The ancestors are
// opened O_PATH, which needs search permission on them and never read, as a whole-path open does; only the
// directory itself, which is synced, is opened for reading.
func openDirectoryNoLinks(path string) (*sys.FD, error) {
	var parts []string
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	const ancestor, destination = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if len(parts) == 0 {
		dir, err := sys.Strict(sys.Own(unix.Open("/", destination, 0)))
		if err != nil {
			return nil, fmt.Errorf("directory root: %w", err)
		}
		return dir, nil
	}
	dir, err := sys.Strict(sys.Own(unix.Open("/", ancestor, 0)))
	if err != nil {
		return nil, fmt.Errorf("directory root: %w", err)
	}
	for i, part := range parts {
		flags := ancestor
		if i == len(parts)-1 {
			flags = destination
		}
		next, err := sys.Strict(dir.Openat(part, flags, 0))
		cerr := dir.Close()
		if err != nil {
			return nil, fmt.Errorf("directory (links are refused): %w", err)
		}
		if cerr != nil {
			_ = next.Close()
			return nil, cerr
		} // release the newly opened directory on error
		dir = next
	}
	return dir, nil
}

func (w *runStatusWriter) checkParent() error {
	var st unix.Stat_t
	if err := w.dir.Fstat(&st); err != nil {
		return fmt.Errorf("--status-file parent: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o777 != 0o700 || int(st.Uid) != os.Geteuid() {
		return errors.New("--status-file parent must be a private 0700 directory owned by the launcher")
	}
	var named unix.Stat_t
	if err := unix.Lstat(w.parent, &named); err != nil {
		return fmt.Errorf("--status-file parent path: %w", err)
	}
	if st.Ino != named.Ino || st.Dev != named.Dev {
		return errors.New("--status-file parent was replaced")
	}
	return nil
}

func statusOutsideWrites(parent string, rt *agent.RuleTable) error {
	if rt == nil {
		return errors.New("--status-file requires the run's compiled rules")
	}
	for _, rules := range [][]agent.FSRule{rt.FS, rt.FSAsk} {
		for _, rule := range rules {
			if rule.Kind != agent.FSWrite && rule.Kind != agent.FSAsk {
				continue
			}
			for _, path := range []string{rule.Path, rule.Resolved} {
				if path == "" {
					continue
				}
				if resolved, err := filepath.EvalSymlinks(path); err == nil {
					path = resolved
				}
				if agent.Covers(path, parent) || agent.Covers(parent, path) {
					return fmt.Errorf("--status-file directory overlaps fs.%s %s", rule.Kind, rule.Path)
				}
				// Inode comparisons also refuse a mounted alias of an ancestor directory.
				grant, err := os.Stat(path)
				if err != nil {
					continue
				} // lexical and compiled resolved names were checked above
				for p := parent; ; p = filepath.Dir(p) {
					info, err := os.Stat(p)
					if err != nil {
						return fmt.Errorf("--status-file directory: %w", err)
					}
					if os.SameFile(grant, info) {
						return fmt.Errorf("--status-file directory aliases fs.%s %s", rule.Kind, rule.Path)
					}
					if p == "/" {
						break
					}
				}
			}
		}
	}
	return nil
}

func (w *runStatusWriter) Write(status runstatus.Status) error {
	data, err := runstatus.Encode(status)
	if err != nil {
		return err
	}
	if err := w.checkParent(); err != nil {
		return err
	}
	if w.previous != nil {
		var named unix.Stat_t
		if err := w.dir.Fstatat(w.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("run status replaced: %w", err)
		}
		if named.Dev != w.previous.Dev || named.Ino != w.previous.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG || named.Nlink != 1 || named.Mode&0o777 != 0o600 || int(named.Uid) != os.Geteuid() {
			return errors.New("run status destination was replaced or changed")
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("run status temporary name: %w", err)
	}
	tmp := ".tego-run-status-" + hex.EncodeToString(random[:])
	fd, err := w.dir.Openat(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("run status temporary file: %w", err)
	}
	defer func() { _ = w.dir.Borrow(func(n int) error { return unix.Unlinkat(n, tmp, 0) }) }() // remove an unpublished temporary file
	if err := fd.Borrow(func(n int) error { return unix.Fchmod(n, 0o600) }); err != nil {
		_ = fd.Close()
		return err
	} // release on preparation error
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return err
	} // release on preparation error
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		_ = fd.Close()
		return errors.New("run status temporary file is not regular and singly linked")
	}
	f, err := fd.Release(filepath.Join(w.parent, tmp))
	if err != nil {
		_ = fd.Close()
		return err
	} // release on ownership-transfer error
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("run status write: %w", err)
	}
	err = w.dir.Borrow(func(n int) error {
		if w.previous == nil {
			return unix.Renameat2(n, tmp, n, w.name, unix.RENAME_NOREPLACE)
		}
		return unix.Renameat(n, tmp, n, w.name)
	})
	if err != nil {
		return fmt.Errorf("run status atomic rename: %w", err)
	}
	w.previous = &st
	// A closure, not unix.Fsync itself: fdcheck follows a lender's callback only when its body is in the module.
	if err := w.dir.Borrow(func(n int) error { return unix.Fsync(n) }); err != nil { //nolint:gocritic // see above

		return fmt.Errorf("run status directory sync: %w", err)
	}
	return nil
}

func (w *runStatusWriter) Close() error { return w.dir.Close() }
