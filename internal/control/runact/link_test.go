// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestBlockFromContractMatchesOneName: the block a rules change places on a run whose launcher reads a link block
// (liveblock.TakesLink) refuses what the run's contract grants under the removed entry only, so another hard link of
// the same file (a multi-call program's other applets) runs as the next run's contract lets it; on a run whose
// launcher predates it
// the writer places the whole-file block instead, which the old launcher reads (version 1) and which refuses more,
// never less; and a person's Block now on the same path stays the whole-file block in both.
func TestBlockFromContractMatchesOneName(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	bin, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ls, sleep := filepath.Join(bin, "ls"), filepath.Join(bin, "sleep")
	if err := os.WriteFile(ls, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	if err := os.Link(ls, sleep); err != nil {
		t.Skipf("hard link: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(ls, &st); err != nil {
		t.Fatal(err)
	}
	id := liveblock.FileID{Dev: st.Dev, Ino: st.Ino}

	// grantOf is the run's contract exec.allow [ls, sleep] on an exec of the file reached at at, as the supervisor
	// answers it (liveblock.Grant): each entry grants the file at its own path.
	grantOf := func(at string) liveblock.Grant {
		return func(v string) (bool, bool) { return v == ls || v == sleep, v == at }
	}
	// sleepRefused compiles the run's overlay as its launcher does and asks whether an exec of sleep is refused.
	sleepRefused := func(t *testing.T, dir string) (*liveblock.Overlay, bool) {
		t.Helper()
		o, err := liveblock.Read(dir, liveRun)
		if err != nil {
			t.Fatal(err)
		}
		s := liveblock.Compile(o, liveblock.Resolved{Files: map[string]liveblock.FileID{ls: id}})
		if _, ok := s.MatchExec([]string{ls}, id, true, grantOf(ls)); !ok {
			t.Fatal("ls, the removed name, is not refused")
		}
		_, refused := s.MatchExec([]string{sleep}, id, true, grantOf(sleep))
		return o, refused
	}

	for _, tc := range []struct {
		name       string
		marked     bool
		wantV      int
		sleepBlock bool
	}{
		{"a launcher that reads a link block", true, liveblock.VersionLink, false},
		{"an older launcher", false, liveblock.Version, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":26`)
			holdRunLock(t, dir)
			if tc.marked {
				if err := liveblock.MarkLink(dir); err != nil {
					t.Fatal(err)
				}
			}
			b, err := BlockFromContract(ctx, root, liveRun, "exec", ls)
			if err != nil || b.Word != "blocked" || b.Rule != "live.block[exec:"+ls+"]" {
				t.Fatalf("BlockFromContract: %+v, %v", b, err)
			}
			o, refused := sleepRefused(t, dir)
			if o.V != tc.wantV || refused != tc.sleepBlock {
				t.Fatalf("overlay version %d, sleep refused %v; want %d and %v", o.V, refused, tc.wantV, tc.sleepBlock)
			}
			// A person's Block now on the same path refuses the whole file, whatever the launcher reads.
			if _, err := BlockUntil(ctx, root, liveRun, "exec", ls, true, time.Time{}, "dashboard"); err != nil {
				t.Fatal(err)
			}
			if o, refused := sleepRefused(t, dir); !refused || o.V != liveblock.Version {
				t.Fatalf("after a person's block: sleep refused %v at version %d; want the whole file at version %d", refused, o.V, liveblock.Version)
			}
		})
	}

	// A bare name or a folder has no link form: it is Block's block on every run.
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":26`)
	holdRunLock(t, dir)
	if err := liveblock.MarkLink(dir); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"ls", bin + "/"} {
		if _, err := BlockFromContract(ctx, root, liveRun, "exec", v); err != nil {
			t.Fatal(err)
		}
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil || o.V != liveblock.Version {
		t.Fatalf("a bare name and a folder: %+v, %v; want version %d", o, err, liveblock.Version)
	}
}
