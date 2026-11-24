// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
)

func TestAdvancedOtherAccountsNeverReadOrRetainFolders(t *testing.T) {
	recipient := uint32(os.Getuid())
	for _, tc := range []struct {
		name, exe, argv string
		foreign, task   bool
	}{
		{"foreign native", "/bin/codex", "codex\x00", true, false},
		{"foreign matched interpreter", "/bin/node", "node\x00/lib/@openai/codex/bin/codex.js\x00", true, false},
		{"foreign surviving task", "/bin/codex", "codex\x00", true, true},
		{"recipient native", "/bin/codex", "codex\x00", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			owner := recipient
			if tc.foreign {
				owner += 5000
			}
			processFixture(t, root, 10, 1, 100, tc.exe, []byte(tc.argv), 0)
			writeProcFile(t, root, "10/status", statusFixture(owner))
			if tc.task {
				if err := os.Remove(filepath.Join(root, "10/exe")); err != nil {
					t.Fatal(err)
				}
				processFixture(t, filepath.Join(root, "10/task"), 11, 1, 101, tc.exe, []byte(tc.argv), 0)
				writeProcFile(t, root, "10/task/11/status", statusFixture(owner))
			}
			fs, err := openProc(root)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.close()
			cwdReads := 0
			spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(_ int, _ uint32, err error) (uint32, error) {
				return owner, err
			}, linkHook: func(pid int, name, value string, err error) (string, error) {
				if name == "cwd" {
					cwdReads++
					if tc.foreign {
						t.Errorf("read foreign process %d working folder", pid)
					}
					return fmt.Sprintf("/home/account-%d/%s", owner, markerSecret), nil
				}
				return value, err
			}}
			got := readProcessesMode(t.Context(), spy, root, recipient, catalog.Rows(), true)
			if got.Unknown || len(got.Processes) != 1 {
				t.Fatalf("lost match or coverage: %+v", got)
			}
			p := got.Processes[0]
			if p.Exe != tc.exe || p.UID != owner || p.Name != "codex" {
				t.Fatalf("lost process identity: %+v", p)
			}
			if tc.foreign {
				if cwdReads != 0 || p.Cwd != "" {
					t.Fatalf("foreign folder retained: reads=%d folder=%q", cwdReads, p.Cwd)
				}
				assertNoCanary(t, got)
			} else if cwdReads != 1 || p.Cwd == "" {
				t.Fatal("recipient working folder was lost")
			}
		})
	}
}
