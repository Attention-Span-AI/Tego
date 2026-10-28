// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestBlockThroughALinkedFolder: `tego block <run> path <link>/secret` writes the path the link
// leads to as the block's Real, says so, and keeps the value as written for the rule and for `tego unblock`; a path
// with no link in it gets no Real.
func TestBlockThroughALinkedFolder(t *testing.T) {
	dir, id, _ := liveRun(t)
	if err := liveblock.MarkReal(dir); err != nil { // the run's launcher reads a real path
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "data", "secret")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "data"), link); err != nil {
		t.Fatal(err)
	}
	value := filepath.Join(link, "secret")
	code, out, errs := run(t, "block", id, "path", value)
	if code != identity.ExitOK || !strings.HasPrefix(out, id+": blocked live.block[path:"+value+"]\n") ||
		!strings.Contains(out, value+" leads to "+target+" through a link; the block refuses both.") {
		t.Fatalf("block through a link: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := liveblock.Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := o.Find(liveblock.KindPath, value); !ok || e.Real != target {
		t.Fatalf("overlay holds %+v %v, want the value with Real %q", e, ok, target)
	}
	if _, ok := liveblock.Compile(o, liveblock.Resolved{}).MatchPath(filepath.Join(target, "k.pem"), liveblock.AccessRead); !ok {
		t.Fatal("the target path is not refused")
	}
	code, out, errs = run(t, "block", id, "path", target)
	if code != identity.ExitOK || strings.Contains(out, "through a link") {
		t.Fatalf("block of a target path: exit %d stdout %q stderr %q", code, out, errs)
	}
	if o, err = liveblock.Read(dir, id); err != nil {
		t.Fatal(err)
	}
	if e, _ := o.Find(liveblock.KindPath, target); e.Real != "" {
		t.Fatalf("a path with no link got Real %q", e.Real)
	}
	if code, out, errs := run(t, "unblock", id, "path", value); code != identity.ExitOK || !strings.Contains(out, "block removed") {
		t.Fatalf("unblock by the spelling written: exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestBlockThroughALinkOnAnOlderLauncher: a run whose launcher made no real-path mark (an older
// tego) gets the block with its value alone, at the overlay version that launcher reads, and the CLI says the path the
// link leads to is not covered and how to block it, never "refuses both".
func TestBlockThroughALinkOnAnOlderLauncher(t *testing.T) {
	dir, id, _ := liveRun(t)
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
	value, target := filepath.Join(link, "secret"), filepath.Join(base, "data", "secret")
	code, out, errs := run(t, "block", id, "path", value)
	if code != identity.ExitOK || strings.Contains(out, "refuses both") ||
		!strings.Contains(out, value+" leads to "+target+" through a link, but "+id+" was started by an older tego") ||
		!strings.Contains(out, "tego block "+id+" path "+target) {
		t.Fatalf("block through a link on an older launcher: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := liveblock.Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := o.Find(liveblock.KindPath, value); !ok || e.Real != "" || o.V > liveblock.VersionModes {
		t.Fatalf("overlay v%d holds %+v %v; want the value alone at a version an older launcher reads", o.V, e, ok)
	}
}
