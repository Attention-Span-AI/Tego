// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestSessionListReadErrors(t *testing.T) {
	for _, tc := range []string{"root-not-directory", "corrupt-run", "empty", "missing"} {
		t.Run(tc, func(t *testing.T) {
			root := gcRoot(t)
			t.Chdir(t.TempDir())
			switch tc {
			case "root-not-directory":
				// ReadDir fails for root and unprivileged users alike, without a permission skip.
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(root, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-run":
				id := sessionsOf(t, root, "helper", 1)[0]
				if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte("broken\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
			}
			code, out, errs := run(t, "session", "list")
			if tc == "empty" || tc == "missing" {
				if code != identity.ExitOK || out != "No sessions yet. Start one: tego run AGENT\n" || errs != "" {
					t.Fatalf("readable empty/new ledger: exit %d stdout %q stderr %q", code, out, errs)
				}
			} else if code != identity.ExitError || out != "" || !strings.HasPrefix(errs, "tego session list: ") || !strings.HasSuffix(errs, " [io]\n") {
				t.Fatalf("read failure: exit %d stdout %q stderr %q", code, out, errs)
			}
		})
	}
}
