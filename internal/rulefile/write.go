// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// replace writes text over the pinned file, which held cur when it was read under the contract's lock: the old text
// goes to <name>.bak and the new text to a temporary file renamed over the name, each fsync'ed, then the directory.
// Just before the rename the file is read again through the guards, so an edit made meanwhile by something that does
// not take the lock (an editor) is refused rather than lost. A reader sees the old file or the new one, never part.
func (p *pinned) replace(cur *File, text []byte) (bak string, err error) {
	if err := step("bak"); err != nil {
		return "", err
	}
	if err := p.put(p.name+".bak", cur.Text, cur.Mode, ""); err != nil {
		return "", fmt.Errorf("keep %s.bak: %w", p.path, err)
	}
	if err := p.put(p.name, text, cur.Mode, cur.SHA256); err != nil {
		return "", err
	}
	return p.path + ".bak", nil
}

// put writes b to a new file in the pinned directory and renames it to name. With base set (the contract itself,
// not its .bak) it first reads the file again and refuses, ErrStale, when it no longer holds base.
func (p *pinned) put(name string, b []byte, mode os.FileMode, base string) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := "." + p.name + ".tego-rule-" + hex.EncodeToString(rnd[:])
	fd, err := p.dir.Openat(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f, err := fd.Release(tmp)
	if err != nil {
		_ = fd.Close() // Release failed, so the owner still holds the number; its error is the one to report
		p.unlink(tmp)
		return err
	}
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Chmod(mode)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil && base != "" {
		werr = step("temp")
		if werr == nil {
			werr = p.holds(base)
		}
		if werr == nil {
			werr = step("rename")
		}
	}
	if werr == nil {
		werr = p.dir.Borrow(func(n int) error { return unix.Renameat(n, tmp, n, name) })
	}
	if werr != nil {
		p.unlink(tmp)
		return werr
	}
	if err := p.dir.Fsync(); err != nil {
		return fmt.Errorf("%s is written, but its folder could not be synced: %w", p.path, err)
	}
	return nil
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

// unlink removes a temporary file this package made; a failure leaves a dot-file behind and is not the error to
// report.
func (p *pinned) unlink(name string) {
	_ = p.dir.Borrow(func(n int) error { return unix.Unlinkat(n, name, 0) })
}
