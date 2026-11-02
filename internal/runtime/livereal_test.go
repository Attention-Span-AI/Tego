// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestLauncherReadsARealPath: the launcher makes the run directory's real-path mark, so writers
// store a block's real path for its run, and it reads a version 4 overlay holding one and refuses beneath both
// spellings under the value's rule.
func TestLauncherReadsARealPath(t *testing.T) {
	r := pauseRunner(t)
	if liveblock.TakesReal(r.dir) {
		t.Fatal("a run directory has the mark before its launcher made it")
	}
	r.markRealReader()
	if !liveblock.TakesReal(r.dir) {
		t.Fatal("the launcher made no real-path mark")
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, _, err := o.Add(liveblock.KindPath, "/home/u/link/secret", "uid:1 pid:3 cli", time.Now()); err != nil {
			return err
		}
		o.SetReal(liveblock.KindPath, "/home/u/link/secret", "/data/secret")
		return nil
	})
	b := &liveBlocks{}
	r.pollLiveBlocks(context.Background(), b)
	if b.last == nil || b.last.V != liveblock.VersionReal {
		t.Fatalf("overlay read %+v: want the version %d file read", b.last, liveblock.VersionReal)
	}
	for _, p := range []string{"/home/u/link/secret/k", "/data/secret/k"} {
		e, ok := b.Load().MatchPath(p, liveblock.AccessRead)
		if !ok || e.Rule() != "live.block[path:/home/u/link/secret]" {
			t.Fatalf("MatchPath(%q) = %+v %v, want refused under the value's rule", p, e, ok)
		}
	}
}
