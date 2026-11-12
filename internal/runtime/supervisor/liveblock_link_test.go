// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// linkLayout is a multi-call program on disk: one file box under the names ls and sleep (hard links, as uutils' applets
// are on Ubuntu 25.10 and 26.04), a symbolic link xls to ls, and a folder w the agent writes in. os.Link makes the
// links, so a host whose own coreutils are GNU tests it too.
type linkLayout struct{ box, ls, sleep, xls, w string }

func newLinkLayout(t *testing.T) linkLayout {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := linkLayout{box: filepath.Join(dir, "box"), ls: filepath.Join(dir, "ls"), sleep: filepath.Join(dir, "sleep"),
		xls: filepath.Join(dir, "xls"), w: filepath.Join(dir, "w")}
	if err := os.WriteFile(m.box, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	for _, n := range []string{m.ls, m.sleep} {
		if err := os.Link(m.box, n); err != nil {
			t.Skipf("hard link: %v", err)
		}
	}
	if err := os.Symlink(m.ls, m.xls); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(m.w, 0o755); err != nil {
		t.Fatal(err)
	}
	return m
}

// linkSet is the Set the launcher compiles for the overlay o, with each absolute exec block's identity as it
// resolves it (stat(2), links followed).
func linkSet(t *testing.T, o *liveblock.Overlay) *liveblock.Set {
	t.Helper()
	res := liveblock.Resolved{Files: map[string]liveblock.FileID{}}
	for _, e := range o.Blocks {
		var st unix.Stat_t
		if unix.Stat(e.Value, &st) == nil {
			res.Files[e.Value] = liveblock.FileID{Dev: st.Dev, Ino: st.Ino}
		}
	}
	return liveblock.Compile(o, res)
}

// TestLiveLinkBlockRefusesWhatTheNewContractRefuses: under exec.allow [ls, sleep], where ls and sleep are one file,
// the block "Also apply now" places when ls is removed (a link block) refuses exactly what exec.allow [sleep] refuses:
// ls by its name, through a symbolic link the agent made, and through /proc/self/fd/N of a descriptor opened by that
// name; sleep, the same file under the name the new contract keeps, by its name and by its descriptor, runs. What the
// contract refuses already (a hard link the agent made, the file's dispatcher name) stays refused under the contract's
// own rule. A person's block on ls by path refuses the whole file, sleep included, as it always did. Real files, the
// real describeImage, StatID and EvalSymlinks, the loop's own decideExec and liveExec (pinDecide).
func TestLiveLinkBlockRefusesWhatTheNewContractRefuses(t *testing.T) {
	m := newLinkLayout(t)
	hard2 := filepath.Join(m.w, "hard2")
	if err := os.Link(m.box, hard2); err != nil {
		t.Fatal(err)
	}
	running, next := pinContract(m.ls, m.sleep), pinContract(m.sleep)

	link := liveblock.New("r-test")
	if _, _, err := link.AddLink(liveblock.KindExec, m.ls, "uid:1 pid:2 dashboard", time.Now()); err != nil {
		t.Fatal(err)
	}
	whole := liveblock.New("r-test")
	if _, _, err := whole.Add(liveblock.KindExec, m.ls, "uid:1 pid:2 cli", time.Now()); err != nil {
		t.Fatal(err)
	}
	linkBlocks, wholeBlocks := linkSet(t, link), linkSet(t, whole)

	decide := func(c *compiled, set *liveblock.Set, spelled, open string) execDecision {
		t.Helper()
		return pinDecide(t, c, set, spelled, open)
	}
	for _, tc := range []struct {
		name, spelled, open string
	}{
		{"ls by its name", m.ls, m.ls},
		{"a symbolic link to ls", m.xls, m.xls},
		{"/proc/self/fd/N of ls", "", m.ls},
		{"sleep by its name", m.sleep, m.sleep},
		{"/proc/self/fd/N of sleep", "", m.sleep},
		{"a hard link the agent made", hard2, hard2},
		{"the dispatcher name", m.box, m.box},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := decide(next, nil, tc.spelled, tc.open)
			got := decide(running, linkBlocks, tc.spelled, tc.open)
			if got.verdict != want.verdict {
				t.Errorf("with the link block: %s (%s); the next run's contract: %s (%s)", got.verdict, got.rule, want.verdict, want.rule)
			}
			if got.verdict == record.VerdictRefused && got.answer.cont {
				t.Error("a refused exec is answered by the loop, never continued")
			}
			// What the running contract refuses keeps its own rule; what it allows and the block refuses names the block.
			switch alone := decide(running, nil, tc.spelled, tc.open); {
			case alone.verdict == record.VerdictRefused && got.rule != alone.rule:
				t.Errorf("refused under %s, want the contract's own %s", got.rule, alone.rule)
			case alone.verdict != record.VerdictRefused && got.verdict == record.VerdictRefused && got.rule != "live.block[exec:"+m.ls+"]":
				t.Errorf("refused under %s, want the block's rule", got.rule)
			}
			if w := decide(running, wholeBlocks, tc.spelled, tc.open); w.verdict != record.VerdictRefused {
				t.Errorf("a person's block on %s by path: %s (%s), want the whole file refused", m.ls, w.verdict, w.rule)
			}
		})
	}
}
