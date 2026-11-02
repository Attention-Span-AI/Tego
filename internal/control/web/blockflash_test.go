// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBlockFlashNamesTheFileItMatches: Block now on an absolute program whose file has other names says the block
// refuses each of them, as `tego block` does: the launcher matches the file's identity, so a block on one applet of a
// multi-call program refuses them all. A lone program's flash says nothing more.
func TestBlockFlashNamesTheFileItMatches(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	bin, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, tool := filepath.Join(bin, "box"), filepath.Join(bin, "tool")
	for _, p := range []string{box, tool} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(box, filepath.Join(bin, "ls")); err != nil {
		t.Fatal(err)
	}
	block := func(value string) string {
		return follow(t, s, c, post(s, "/runs/"+adjRun+"/block", url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {value}}, own, "", c))
	}
	b := block(filepath.Join(bin, "ls"))
	mustContain(t, "the block's line", b, "It is refused from the next try on.",
		"It matches the program&#39;s file, which has 2 names here (a multi-call program, as coreutils and busybox are): every one of them is refused, not this name alone.")
	if b := block(tool); strings.Contains(b, "names here") || !strings.Contains(b, "It is refused from the next try on.") {
		t.Error("a lone program's flash speaks of other names")
	}
}
