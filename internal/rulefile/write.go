// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/attention-span-ai/tego/internal/registry"
)

// replace writes text over the pinned file, which held cur when it was read under the contract's lock: the old text
// goes to <name>.bak and the new text to a temporary file renamed over the name, each fsync'ed, then the directory.
// Just before the rename the file is read again through the guards, so an edit made meanwhile by something that does
// not take the lock (an editor) is refused rather than lost. A reader sees the old file or the new one, never part.
func (p *pinned) replace(ctx context.Context, cur *File, text []byte) (bak string, err error) {
	if err := step("bak"); err != nil {
		return "", err
	}
	if err := p.put(ctx, p.name+".bak", cur.Text, cur.Mode, nil); err != nil {
		return "", fmt.Errorf("keep %s.bak: %w", p.path, err)
	}
	if err := p.put(ctx, p.name, text, cur.Mode, &cur.Identity); err != nil {
		return "", err
	}
	return p.path + ".bak", nil
}

// put delegates publication to the registry leaf writer. Existing contracts are
// checked by both the service guards and the old file's identity and digest.
func (p *pinned) put(ctx context.Context, name string, b []byte, mode os.FileMode, expected *registry.FileIdentity) error {
	before := func() error { return nil }
	if expected != nil {
		before = func() error {
			if err := step("temp"); err != nil {
				return err
			}
			if err := p.holds(expected.SHA256); err != nil {
				return err
			}
			if err := step("rename"); err != nil {
				return err
			}
			if p.beforePublish != nil {
				return p.beforePublish()
			}
			return nil
		}
	} else {
		// A backup is also published atomically. Refuse a linked or concurrently
		// replaced backup rather than overwriting a file we did not inspect.
		old, err := registry.ReadIdentityAt(p.dir, name)
		if err == nil {
			expected = &old
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("backup-recheck: %w", err)
		}
	}
	err := registry.WriteFileAt(p.dir, name, b, registry.WriteOptions{Context: ctx, Mode: mode, Expected: expected, BeforePublish: before})
	if errors.Is(err, registry.ErrFileChanged) {
		return fmt.Errorf("%w: %v", ErrStale, err)
	}
	return err
}

// holds reads the file again just before it is replaced: one that no longer passes the guards, or holds something
// other than base, is refused.
func (p *pinned) holds(base string) error {
	now, err := p.read()
	if err != nil {
		return err
	}
	if now.SHA256 != base {
		return fmt.Errorf("%w: %s was changed while the new text was being written; nothing was written", ErrStale, p.path)
	}
	return nil
}
