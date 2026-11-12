// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// maxRuns is how many run folders, newest first, a guide reads: each costs one open, the last line and the first.
// A ledger root with more says so in NotKnown.
const maxRuns = 2000

// run is what the guide reads of one run folder: its run_start and whether it ended.
type run struct {
	id, dir string
	start   record.RunStartPayload
	// state is ledger.Reader.State: ended, running, lost or empty.
	state ledger.RunState
}

// observe reports whether the run enforced nothing (tego watch, --observe): run_start's tier is observe.
func (r *run) observe() bool { return r.start.Tier == string(backend.TierObserve) }

// runs is what the guide read of a ledger root.
type runs struct {
	// all is every run with a readable run_start, newest first.
	all []*run
	// ids is every run id under the root, for the short ids a hint names.
	ids []string
	// unreadable counts run folders whose record could not be read; missing is true when the root does not exist.
	unreadable int
	missing    bool
	// more is how many run folders past maxRuns were not read.
	more int
}

// readRuns reads every run folder under root, newest first (ledger.CompareRunIDs), up to maxRuns. A folder with no
// events.jsonl recorded nothing and is left out; one whose record cannot be read is counted. The error is the root's
// own: it exists and cannot be listed.
func readRuns(root string) (*runs, error) {
	out := &runs{}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			out.missing = true
			return out, nil
		}
		return nil, fmt.Errorf("read the ledger root %s: %w", root, err)
	}
	for _, e := range entries {
		if e.IsDir() && ledger.IsRunID(e.Name()) {
			out.ids = append(out.ids, e.Name())
		}
	}
	slices.SortFunc(out.ids, func(a, b string) int { return ledger.CompareRunIDs(b, a) })
	for i, id := range out.ids {
		if i == maxRuns {
			out.more = len(out.ids) - maxRuns
			break
		}
		r, err := readRun(filepath.Join(root, id), id)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			out.unreadable++
		case r != nil:
			out.all = append(out.all, r)
		}
	}
	return out, nil
}

// readRun reads one run folder: its state from the lock and the last line, and its first line, which must be
// run_start. A run with no complete line yet is nil.
func readRun(dir, id string) (*run, error) {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rd.Close() }()
	rd.SkipNewerVersions()
	st, err := rd.State()
	if err != nil {
		return nil, err
	}
	if st == ledger.StateEmpty {
		return nil, nil
	}
	r := &run{id: id, dir: dir, state: st}
	for e, err := range rd.Iter() {
		if err != nil {
			return nil, err
		}
		if e.Kind != record.KindRunStart {
			return nil, fmt.Errorf("%s: the first line is %s, not run_start", dir, e.Kind)
		}
		if err := e.DecodePayload(&r.start); err != nil {
			return nil, fmt.Errorf("%s: run_start: %w", dir, err)
		}
		return r, nil
	}
	return nil, nil
}

// newest is the newest run that keep accepts, nil for none.
func (rs *runs) newest(keep func(*run) bool) *run {
	for _, r := range rs.all {
		if keep(r) {
			return r
		}
	}
	return nil
}

// short is how a next step names run id: its last part, which every command takes for the run, when no other run
// under the root ends the same way; else the whole id. Only an id ledger.IsRunID accepts is ever written.
func (rs *runs) short(id string) string {
	i := strings.LastIndexByte(id, '-')
	if i < 0 || i == len(id)-1 {
		return id
	}
	suffix := id[i:]
	for _, other := range rs.ids {
		if other != id && strings.HasSuffix(other, suffix) {
			return id
		}
	}
	return id[i+1:]
}

// commandWords is a recorded command as a fact shows it: each word as a shell reads it (shellword.Quote), every
// character that does not print written as an escape (record.Printable), and at most maxWords words and maxRunes
// characters. It is a fact, never a command a next step names: the agent's own words could be anything.
func commandWords(argv []string) string {
	const maxWords, maxRunes = 6, 72
	words := make([]string, 0, min(len(argv), maxWords))
	for i, w := range argv {
		if i == maxWords {
			words = append(words, "...")
			break
		}
		words = append(words, shellword.Quote(w))
	}
	s := []rune(record.Printable(strings.Join(words, " ")))
	if len(s) > maxRunes {
		return string(s[:maxRunes-3]) + "..."
	}
	return string(s)
}
