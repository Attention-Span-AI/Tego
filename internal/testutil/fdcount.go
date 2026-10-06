// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// noFDLeakEnv is what NoFDLeak sets through t.Setenv, which is what makes it refuse a parallel test.
const noFDLeakEnv = "TEGO_TESTUTIL_NOFDLEAK"

// fdDir is the descriptor table NoFDLeak lists; its own test points it elsewhere.
var fdDir = "/proc/self/fd"

// NoFDLeak snapshots this process's descriptor table and, at the test's Cleanup, fails the test when the
// table has grown, naming each new number and what it names (ADR 0023 A8's table check, which every package
// migration adds to its unwind tests). The Go runtime's poller (its eventpoll and eventfd, opened lazily by
// the first pollable file) is ignored.
//
// It calls t.Setenv, so it panics in a test that already called t.Parallel and forbids a later one: in a
// parallel test another test's descriptors would make the delta meaningless.
func NoFDLeak(t *testing.T) {
	t.Helper()
	t.Setenv(noFDLeakEnv, t.Name())
	before, err := openFDs()
	if err != nil {
		t.Fatalf("testutil.NoFDLeak: %v", err)
	}
	t.Cleanup(func() {
		after, err := openFDs()
		if err != nil {
			t.Errorf("testutil.NoFDLeak: %v", err)
			return
		}
		if grown := fdGrowth(before, after); grown != "" {
			t.Errorf("testutil.NoFDLeak: the test leaked descriptors: %s", grown)
		}
	})
}

// openFDs maps each open descriptor to what it names, without the runtime's poller and the listing's own.
func openFDs() (map[int]string, error) {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", fdDir, err)
	}
	fds := map[int]string{}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue // the listing's own descriptor, closed by now
		}
		if link == "anon_inode:[eventpoll]" || link == "anon_inode:[eventfd]" {
			continue
		}
		fds[n] = link
	}
	return fds, nil
}

// fdGrowth names what after holds beyond before, or "" when it holds no more descriptors. A number that was
// closed and reopened on something else counts as neither growth nor a leak.
func fdGrowth(before, after map[int]string) string {
	if len(after) <= len(before) {
		return ""
	}
	var added []string
	for n, link := range after {
		if was, ok := before[n]; !ok || was != link {
			added = append(added, fmt.Sprintf("%d -> %s", n, link))
		}
	}
	slices.Sort(added)
	return fmt.Sprintf("%d open before, %d after; new: %s", len(before), len(after), strings.Join(added, ", "))
}
