// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestARuntimeGrantLandsOnlyOnTheDirectoryTheRunMade: the runtime checks its CODEX_HOME's identity
// when it grants it, but Prepare opens the path again, following links, so a link swapped in for the directory (or
// for one above it) between the two moved the grant where it pointed. writeEntry compares the held descriptor with
// the identity the grant carries and refuses another directory; the directory itself is granted, and an entry with
// no identity is not compared.
func TestARuntimeGrantLandsOnlyOnTheDirectoryTheRunMade(t *testing.T) {
	root := tempDir(t)
	home := filepath.Join(root, "tego", "r-1", "codex")
	elsewhere := filepath.Join(root, "elsewhere")
	for _, d := range []string{home, elsewhere} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(home, &st); err != nil {
		t.Fatal(err)
	}
	grant := agent.FSRule{Path: home, Kind: agent.FSWrite, Access: agent.AccessWriteSet, Runtime: agent.CodexHomeGrant,
		RuntimeDev: uint64(st.Dev), RuntimeIno: st.Ino}
	h, _ := prepare(t, 7, &agent.RuleTable{FS: []agent.FSRule{grant}})
	if e, ok := h.entry(home); !ok || e.Access == 0 {
		t.Fatalf("the run's own directory was not granted: %+v (held %v)", e, ok)
	}

	if err := os.Rename(home, home+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, home); err != nil {
		t.Fatal(err)
	}
	err := prepareErr(t, 7, &agent.RuleTable{FS: []agent.FSRule{grant}}, nil)
	if !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), "no longer the directory the run made") {
		t.Fatalf("a link swapped in for the directory: Prepare = %v, want a refusal", err)
	}
	// A directory above it swapped for a link moves it too.
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(home+".moved", home); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(root, "tego", "r-1")
	if err := os.Rename(run, run+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(elsewhere, "codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, run); err != nil {
		t.Fatal(err)
	}
	err = prepareErr(t, 7, &agent.RuleTable{FS: []agent.FSRule{grant}}, nil)
	if !errors.Is(err, ErrRulesetBuild) {
		t.Fatalf("a link swapped in above the directory: Prepare = %v, want a refusal", err)
	}
	// An entry with no identity, a contract's own write entry, is held where its path leads.
	plain := fsRule(agent.FSWrite, home)
	if h, _ := prepare(t, 7, &agent.RuleTable{FS: []agent.FSRule{plain}}); h == nil {
		t.Fatal("no handle")
	}
}
