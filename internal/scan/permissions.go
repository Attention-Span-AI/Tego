// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/internal/grouptrust"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

type modePolicyKey struct{ uid uint32 }
type collectionPolicyKey struct{}

// discoveryPolicy loads once, only when a group-writable inode needs evidence.
type discoveryPolicy struct {
	once   sync.Once
	policy grouptrust.Policy
	load   func() grouptrust.Policy
}

func modePolicy(ctx context.Context, uid uint32) grouptrust.Policy {
	switch p := ctx.Value(modePolicyKey{uid}).(type) {
	case grouptrust.Policy:
		return p
	case *discoveryPolicy:
		p.once.Do(func() { p.policy = p.load() })
		return p.policy.ForUID(uid)
	}
	if p, ok := ctx.Value(collectionPolicyKey{}).(*discoveryPolicy); ok {
		p.once.Do(func() { p.policy = p.load() })
		return p.policy.ForUID(uid)
	}
	return grouptrust.System(int(uid))
}
func checkMode(ctx context.Context, st unix.Stat_t, uid uint32) error {
	if st.Uid != 0 && st.Uid != uid {
		return grouptrust.ErrOwner
	}
	if st.Mode&0002 != 0 {
		return &grouptrust.ModeError{}
	}
	if st.Mode&0020 == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return modePolicy(ctx, uid).Check(st.Mode, st.Uid, st.Gid)
}

// parentError keeps the failing parent relative to the reported leaf's folder.
type parentError struct {
	relative string
	err      error
}

func (e *parentError) Error() string { return e.err.Error() }
func (e *parentError) Unwrap() error { return e.err }

// Check every selected parent before content is opened and again after parsing.
// An unchanged leaf alone cannot detect replacement through a writable parent.
func contentParents(ctx context.Context, root *sys.FD, name string, uid uint32) (func() error, error) {
	return contentParentsWithRootMode(ctx, root, name, uid, nil)
}

// rootMode is used only for an already selected cron spool root.
func contentParentsWithRootMode(ctx context.Context, root *sys.FD, name string, uid uint32, rootMode func(unix.Stat_t) error) (func() error, error) {
	names := []string{"."}
	dir := filepath.Dir(name)
	if dir != "." {
		parts := strings.Split(dir, "/")
		for i := range parts {
			names = append(names, filepath.Join(parts[:i+1]...))
		}
	}
	before := make([]unix.Stat_t, len(names))
	stat := func(name string, st *unix.Stat_t) error {
		pin, e := projectPath(root, name)
		if e != nil {
			return e
		}
		defer func() { _ = pin.Close() }()
		if e = pin.Fstat(st); e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errType
		}
		if name == "." && rootMode != nil {
			return rootMode(*st)
		}
		return checkPinnedMode(ctx, pin, *st, uid)
	}
	parentFailure := func(n string, err error) error {
		relative, e := filepath.Rel(filepath.Dir(name), n)
		if e != nil {
			return e
		}
		return &parentError{relative: relative, err: err}
	}
	for i, n := range names {
		if e := stat(n, &before[i]); e != nil {
			return nil, parentFailure(n, e)
		}
	}
	return func() error {
		for i, n := range names {
			var after unix.Stat_t
			if e := stat(n, &after); e != nil {
				return parentFailure(n, e)
			}
			if !sameInode(before[i], after) {
				return parentFailure(n, errChanged)
			}
		}
		return ctx.Err()
	}, nil
}

func checkPinnedMode(ctx context.Context, pin *sys.FD, st unix.Stat_t, uid uint32) error {
	if e := checkMode(ctx, st, uid); e != nil {
		return e
	}
	if st.Mode&0020 != 0 {
		return pin.ProcPath(func(path string) error {
			_, aclErr := unix.Getxattr(path, "system.posix_acl_access", nil)
			if !grouptrust.AccessACLAbsent(aclErr) {
				return modePolicy(ctx, uid).Refusal(st.Gid, "access-acl")
			}
			return nil
		})
	}
	return nil
}
