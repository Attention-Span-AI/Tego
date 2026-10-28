// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestBlockReadWriteKinds: both kinds are refused on a run an older launcher runs; `tego block <run> read <path>` is
// refused on a run whose reads are not seen (it would refuse
// nothing there), and placed once the run holds its reads; `write` says it refuses changes and leaves reads alone; both
// read a relative path against the working directory, as path does.
func TestBlockReadWriteKinds(t *testing.T) {
	dir, id, _ := liveRun(t)
	wd := t.TempDir()
	t.Chdir(wd)
	// A run whose launcher predates read and write blocks (no record_minor here, below 24 in an r6 run) would fail to
	// read its overlay and ignore every later change, so both kinds are refused there and a path block still works.
	for _, kind := range []string{"read", "write"} {
		code, out, errs := run(t, "block", id, kind, "./tmp/")
		if code != identity.ExitFinding || !strings.Contains(errs, "started by an older tego that has no "+kind+" blocks") ||
			!strings.Contains(errs, "launcher-too-old") || out != "" {
			t.Fatalf("%s on an older launcher's run: exit %d stdout %q stderr %q", kind, code, out, errs)
		}
	}
	if code, out, errs := run(t, "block", id, "path", "./tmp/"); code != identity.ExitOK {
		t.Fatalf("path on an older launcher's run: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, out, errs := run(t, "unblock", id, "path", "./tmp/"); code != identity.ExitOK {
		t.Fatalf("unblock path: exit %d stdout %q stderr %q", code, out, errs)
	}
	rewriteStart(t, dir, `"tier":"landlock"`, `"tier":"landlock","record_minor":24`)
	code, out, errs := run(t, "block", id, "read", "token")
	if code != identity.ExitFinding || !strings.Contains(errs, "a read block would refuse nothing") || !strings.Contains(errs, "reads-unseen") || out != "" {
		t.Fatalf("read on a run that does not see reads: exit %d stdout %q stderr %q", code, out, errs)
	}
	abs := filepath.Join(wd, "tmp")
	code, out, errs = run(t, "block", id, "write", "./tmp/")
	if code != identity.ExitOK || !strings.HasPrefix(out, id+": blocked live.block[write:"+abs+"]\n") ||
		!strings.Contains(out, "reading it still works") {
		t.Fatalf("write: exit %d stdout %q stderr %q", code, out, errs)
	}
	rewriteStart(t, dir, `"tier":"landlock"`, `"tier":"landlock","fs_reads":{"reads":"held","why":"contract"}`)
	code, out, errs = run(t, "block", id, "read", "token")
	if code != identity.ExitOK || !strings.HasPrefix(out, id+": blocked live.block[read:"+filepath.Join(wd, "token")+"]\n") {
		t.Fatalf("read on a held-reads run: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, out, _ := run(t, "unblock", id, "write", abs); code != identity.ExitOK || !strings.Contains(out, "block removed live.block[write:"+abs+"]") {
		t.Fatalf("unblock write: exit %d stdout %q", code, out)
	}
}
