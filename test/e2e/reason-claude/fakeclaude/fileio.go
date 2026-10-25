// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// maxScriptBytes bounds a --script file, as MaxSettingsBytes bounds --settings.
const maxScriptBytes = 2 << 20

var (
	errNotRegular = errors.New("not a regular file")
	errTooBig     = errors.New("too big")
)

// openFile opens a file; a variable so that a test can put a FIFO where the name was between the caller's decision to
// read it and the open itself (the race readRegular is written to survive).
var openFile = os.OpenFile

// readRegular reads a file of at most max bytes. The file is opened without blocking and judged from the descriptor,
// not from an earlier stat of its name: a name that is swapped for a FIFO between a stat and an open would block the
// open for ever, and a device such as /dev/zero would never end. A file that is not regular is errNotRegular and one
// over max is errTooBig (also when it grew after the size was read, as one byte past max is read to see).
func readRegular(path string, max int64) ([]byte, error) {
	f, err := openFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%w: %d bytes, over the %d byte limit", errTooBig, fi.Size(), max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: over the %d byte limit", errTooBig, max)
	}
	return data, nil
}
