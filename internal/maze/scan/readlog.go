// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"errors"
	"sync"
)

// ReadNote is one file the look around opened, or meant to open and didn't, and why not.
type ReadNote struct {
	// Path is the file, absolute.
	Path string `json:"path"`
	// Opened is true when Maze read (part of) the file.
	Opened bool `json:"opened"`
	// Skipped says why it wasn't opened: "only in iCloud", "a link", "time limit".
	Skipped string `json:"skipped,omitempty"`
}

// errBudget marks a file left unopened because the time for reading contents ran out.
var errBudget = errors.New("time limit")

var (
	logMu  sync.Mutex
	logFor func(ReadNote)
)

// Record sends every file the scans open (or skip) to note until the returned function is called, so a person
// can be shown exactly what was read. One recording at a time.
func Record(note func(ReadNote)) (stop func()) {
	logMu.Lock()
	logFor = note
	logMu.Unlock()
	return func() {
		logMu.Lock()
		logFor = nil
		logMu.Unlock()
	}
}

// noted records path as opened (err nil) or skipped (err says why); a missing file isn't worth a line.
func noted(path string, err error) {
	logMu.Lock()
	f := logFor
	logMu.Unlock()
	if f == nil {
		return
	}
	switch {
	case err == nil:
		f(ReadNote{Path: path, Opened: true})
	case errors.Is(err, ErrOnlyInCloud):
		f(ReadNote{Path: path, Skipped: "only in iCloud"})
	case errors.Is(err, errNotRegular):
		f(ReadNote{Path: path, Skipped: "a link, not followed"})
	case errors.Is(err, errBudget):
		f(ReadNote{Path: path, Skipped: "time limit reached"})
	}
}
