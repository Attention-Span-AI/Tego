// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// What this file exports, only this package's tests call.

// HandOverRun hands a finished run directory, and everything the writer created in it, to the owner of
// the ledger root holding it under the hand-over rule (handOverDir). It does nothing unless this process
// is root and the ledger root is another uid's. Writer.Close does the same through the descriptor it
// held for the whole run; this is the by-name form, whose walk refuses a link the user left in their own
// ledger root.
func HandOverRun(runDir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	runDir = filepath.Clean(runDir)
	root := filepath.Dir(runDir)
	rd, err := openDir(root, false)
	if err != nil {
		return err
	}
	defer func() { _ = rd.Close() }()
	o, ok, err := ownerOf(rd, root)
	if err != nil || !ok {
		return err
	}
	d, err := rd.Openat(filepath.Base(runDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: runDir, Err: err}
	}
	defer func() { _ = d.Close() }()
	return handOverDir(d, runDir, o)
}

// PlaceNewFile is placeNewFileAt (whose doc is the contract) on dir reached by the §3 walk (openDir), refusing a
// name that is not one file name.
func PlaceNewFile(dir, name string, b []byte) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("ledger: place %q in %s: not a file name", name, dir)
	}
	path := filepath.Join(dir, name)
	dfd, err := openDir(dir, false)
	if err != nil {
		return fmt.Errorf("ledger: place %s: %w", path, err)
	}
	defer func() { _ = dfd.Close() }()
	return placeNewFileAt(dfd, dir, name, b, nil)
}

// WithWriterOptions passes options to the Writers the sweep opens (clock, anchor, logger).
func WithWriterOptions(opts ...Option) GCOption {
	return func(o *gcOptions) { o.writer = append(o.writer, opts...) }
}
