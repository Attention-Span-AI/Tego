// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestBlockExecNotes: an exec block says what the launcher's identity match reaches beyond its value's own name (a
// file with other names, as a multi-call program's applets are, or a link to a file named otherwise), with the bare
// name that refuses that name alone; a bare name on no folder of the PATH says so; a lone program says nothing more.
// Blocking /bin/ls on a uutils machine refused sleep too, and nothing said so.
func TestBlockExecNotes(t *testing.T) {
	_, id, _ := liveRun(t)
	bin, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, tool := filepath.Join(bin, "coreutils"), filepath.Join(bin, "tool")
	for _, p := range []string{box, tool} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"ls", "sleep"} {
		if err := os.Link(box, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(bin, "alias")
	if err := os.Symlink(tool, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	for _, tc := range []struct {
		value string
		want  []string // nil: no note
	}{
		{filepath.Join(bin, "ls"), []string{"Note: " + filepath.Join(bin, "ls") + " is one file with 3 names here (a multi-call program",
			"so it refuses every one of those names, not ls alone.", "A bare name is matched by name only: tego block " + id + " exec ls\n"}},
		{alias, []string{"Note: " + alias + " leads to " + tool + "; the block matches that file", "not alias alone.",
			"tego block " + id + " exec alias\n"}},
		{"crul", []string{"Note: no program named crul is on this PATH; the block still refuses any program by that name"}},
		{filepath.Join(bin, "gone"), []string{"Note: " + filepath.Join(bin, "gone") + " is not a file here now"}},
		{"tool", nil},
		{tool, nil},
	} {
		code, out, errs := run(t, "block", id, "exec", tc.value)
		if code != identity.ExitOK || !strings.HasPrefix(out, id+": blocked live.block[exec:"+tc.value+"]\n") {
			t.Fatalf("block exec %s: exit %d stdout %q stderr %q", tc.value, code, out, errs)
		}
		if tc.want == nil && strings.Contains(out, "Note:") {
			t.Errorf("block exec %s says more than its name: %q", tc.value, out)
		}
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("block exec %s: stdout %q, want %q", tc.value, out, w)
			}
		}
	}
}
