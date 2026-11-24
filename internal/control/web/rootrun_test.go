// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestRootLaunchedRunIsSaidToBeSudos: a run launched with sudo keeps its folder root's, so a person's dashboard cannot read
// it (N72). Every page that meets that says what is true (the run was launched with sudo, its folder is root's until it
// ends, so this dashboard cannot show or change it live; run the command with sudo or open the dashboard as root), never
// the failed system call, and a refusal for another reason keeps its own words.
func TestRootLaunchedRunIsSaidToBeSudos(t *testing.T) {
	if testutil.RerunAsOrdinaryUser(t) { // root can open the folder: an ordinary uid, the person's dashboard, cannot
		return
	}
	root := t.TempDir()
	id := "r-aaaaaaaa-0000000000501-sudoxx"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ledgerRun(t, root, id, "sudoer", t0, "", time.Time{}, func(func(time.Time, string, string)) {})
	if err := os.Chmod(filepath.Join(root, id), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(root, id), 0o755) }) //nolint:errcheck
	s := newServer(t, root)
	c := login(t, s)
	words := ledgerview.RootLaunchedWords(id)
	pages := []string{"/", "/runs", "/approvals", "/logs", "/runs/" + id}
	t.Run("owned by root", func(t *testing.T) {
		defer ledgerview.SetRootRunSeams(func(string) (int, bool) { return 0, true }, func() int { return 1000 })()
		named := 0
		for _, p := range pages {
			body := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
			for _, bad := range []string{"permission denied", "lstat "} {
				if strings.Contains(body, bad) {
					t.Errorf("%s still says %q", p, bad)
				}
			}
			if strings.Contains(body, "launched with sudo") {
				named++
			} else {
				t.Logf("%s does not name it", p)
			}
		}
		if named < len(pages) {
			t.Errorf("only %d of %d pages say the run was launched with sudo", named, len(pages))
		}
		if body := do(s, "GET", "/", "127.0.0.1:8484", c).Body.String(); !strings.Contains(body, html.EscapeString(words)) {
			t.Errorf("the Overview lacks the words %q", words)
		}
	})
	t.Run("owned by the person", func(t *testing.T) {
		defer ledgerview.SetRootRunSeams(func(string) (int, bool) { return 1000, true }, func() int { return 1000 })()
		body := do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String()
		if strings.Contains(body, "launched with sudo") || !strings.Contains(body, "permission denied") {
			t.Errorf("a refusal of the person's own folder was called a sudo run, or lost its words")
		}
	})
}
