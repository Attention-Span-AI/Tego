// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestBlockResolvesALinkedFolder: the dashboard's Block now on a path, read or write block
// through a linked folder writes where the link leads as the block's Real and reports it; an exec block is not
// resolved (its identity match covers a link already).
func TestBlockResolvesALinkedFolder(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":26,"fs_reads":{"reads":"held","why":"contract"}`)
	holdRunLock(t, dir)
	if err := liveblock.MarkReal(dir); err != nil { // the run's launcher reads a real path
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "data", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "data"), link); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"path", "read", "write"} {
		value := filepath.Join(link, kind+".txt")
		b, err := BlockUntil(ctx, root, liveRun, kind, value, true, time.Time{}, "dashboard")
		want := filepath.Join(base, "data", kind+".txt")
		if err != nil || b.Word != "blocked" || b.Real != want {
			t.Fatalf("%s through a link: %+v, %v; want Real %q", kind, b, err, want)
		}
	}
	if b, err := BlockUntil(ctx, root, liveRun, "exec", filepath.Join(link, "bin")+"/", true, time.Time{}, "dashboard"); err != nil || b.Real != "" {
		t.Fatalf("exec block: %+v, %v; want no Real", b, err)
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil {
		t.Fatal(err)
	}
	s := liveblock.Compile(o, liveblock.Resolved{})
	if e, ok := s.MatchPath(filepath.Join(base, "data", "read.txt"), liveblock.AccessRead); !ok || e.Value != filepath.Join(link, "read.txt") {
		t.Fatalf("the real path of a read block: %+v %v, want refused under the value written", e, ok)
	}
}

// TestBlockThroughALinkOnAnOlderLauncher: on a run whose launcher made no real-path mark, Block now
// through a link stores the value alone and reports the path it does not cover.
func TestBlockThroughALinkOnAnOlderLauncher(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":26,"fs_reads":{"reads":"held","why":"contract"}`)
	holdRunLock(t, dir)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "data"), link); err != nil {
		t.Fatal(err)
	}
	b, err := BlockUntil(ctx, root, liveRun, "path", filepath.Join(link, "x"), true, time.Time{}, "dashboard")
	if err != nil || b.Word != "blocked" || b.Real != "" || b.Uncovered != filepath.Join(base, "data", "x") {
		t.Fatalf("Block now through a link on an older launcher: %+v, %v; want Uncovered and no Real", b, err)
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil || o.V > liveblock.VersionModes || o.Blocks[0].Real != "" {
		t.Fatalf("overlay %+v, %v; want the value alone at a version an older launcher reads", o, err)
	}
}
