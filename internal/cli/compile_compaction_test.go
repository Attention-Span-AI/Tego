// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompilePrintsPlaneCompaction is ADR 0043 D6 in compile's print: where a contract's project holds more .env files
// than the plane keys before compacting (agent.NameCompactAt), compile says how many per-file deny_read rows the name
// rows hold instead and how many paths the plane still keys; with a few files it says nothing of it. A contract
// pinned to tier cgroup says it too, since that tier's plane modes are filled from the same compacted rows, and one
// pinned to tier landlock, which no plane decides, says nothing. Compaction reads the casefold facts
// of ext4, f2fs and tmpfs directories only, so the test needs its temporary directory on one.
func TestCompilePrintsPlaneCompaction(t *testing.T) {
	var st unix.Statfs_t
	if err := unix.Statfs(os.TempDir(), &st); err != nil {
		t.Fatal(err)
	}
	switch st.Type {
	case unix.EXT4_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.F2FS_SUPER_MAGIC:
	default:
		t.Skipf("the temporary directory's filesystem (magic %#x) is not one compaction reads (ext4, f2fs, tmpfs)", st.Type)
	}
	for _, tc := range []struct {
		files int
		tier  string
		line  bool
	}{
		{3, "", false},
		{agent.NameCompactAt + 100, "", true},
		{agent.NameCompactAt + 100, "cgroup", true},
		{agent.NameCompactAt + 100, "landlock", false},
	} {
		files := tc.files
		t.Run(fmt.Sprint(files, tc.tier), func(t *testing.T) {
			dir := t.TempDir()
			contract := "version: 0\nname: compaction\ncommand: [\"true\"]\nfs:\n  write: [\"./work/\"]\n"
			if tc.tier != "" {
				contract += "tier: " + tc.tier + "\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
				t.Fatal(err)
			}
			for i := range files {
				sub := filepath.Join(dir, "work", fmt.Sprintf("s%d", i))
				if err := os.MkdirAll(sub, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(sub, ".env"), []byte("K=V\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
			code, out, errs := run(t, "compile", "agent.yaml")
			if code != identity.ExitOK {
				t.Fatalf("exit %d\nstderr %s", code, errs)
			}
			var line string
			for l := range strings.SplitSeq(out, "\n") {
				if strings.HasPrefix(l, "plane     ") {
					line = l
				}
			}
			if !tc.line {
				if line != "" {
					t.Errorf("%d files (tier %q): compile printed %q", files, tc.tier, line)
				}
				return
			}
			var dropped, keyed int
			if _, err := fmt.Sscanf(line, "plane     %d per-file deny_read rows held by the name rows (ADR 0043 D6); %d paths keyed",
				&dropped, &keyed); err != nil {
				t.Fatalf("%d files: no compaction line (%v):\n%s", files, err, out)
			}
			if dropped < files-agent.NameCompactAt || keyed > agent.NameCompactAt {
				t.Errorf("%d files: %d rows dropped, %d paths keyed", files, dropped, keyed)
			}
		})
	}
}
