// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"sync"
)

// outputWriter keeps the first failed command-output write. Some branches report a
// result with fmt instead of returning its error; mainWith must still refuse success
// when that result never reached the caller. Existing nonzero exit codes are retained.
type outputWriter struct {
	mu  sync.Mutex
	dst io.Writer
	err error
}

func (w *outputWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.dst.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func (w *outputWriter) failure() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}
