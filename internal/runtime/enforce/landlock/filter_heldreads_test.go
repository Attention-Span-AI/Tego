// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestHeldReadsNotifyEveryOpen holds Prepare to ADR 0069 D2: a table whose run holds its reads gets the filter's
// every-open arm (the one record: full and fs.ask_read take) and the held-completion arm (no Landlock domain of the
// run's own), while fs.reads: direct keeps the write arm alone. A read-only open is notified only under held reads.
func TestHeldReadsNotifyEveryOpen(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("K=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reads string
		held  bool
	}{{"auto", true}, {"held", true}, {"direct", false}} {
		t.Run(tc.reads, func(t *testing.T) {
			contract := filepath.Join(root, "agent-"+tc.reads+".yaml")
			yaml := "version: 0\nname: held\ncommand: [\"/bin/sh\", \"-c\", \"true\"]\nfs:\n  reads: " + tc.reads + "\n  write: [\"" + work + "\"]\n" +
				"exec:\n  allow: [\"sh\"]\ntier: landlock\nrecord: summary\n"
			if err := os.WriteFile(contract, []byte(yaml), 0o644); err != nil {
				t.Fatal(err)
			}
			c, ds, err := agent.LoadBytes(contract, []byte(yaml), nil)
			if err != nil {
				t.Fatalf("Load: %v\n%v", err, ds)
			}
			m := config.Builtin()
			m.LedgerRoot.Value = filepath.Join(root, "ledger")
			rt, ds, err := agent.Compile(c, m, agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(root), agent.WithHome(root), agent.WithMountInfo(""), agent.Offline())
			if err != nil {
				t.Fatalf("Compile: %v\n%v", err, ds)
			}
			if rt.Tier != backend.TierLandlock || rt.ReadsHeld() != tc.held {
				t.Fatalf("tier %s, reads held %v", rt.Tier, rt.ReadsHeld())
			}
			h, _ := prepare(t, 7, rt)
			if h.filterOpts.askRead != tc.held || h.filterOpts.heldOpens != tc.held {
				t.Errorf("every-open arm %v, held-completion arm %v, want %v", h.filterOpts.askRead, h.filterOpts.heldOpens, tc.held)
			}
			insts, err := buildFilter(ArchX86_64, h.filterOpts)
			if err != nil {
				t.Fatal(err)
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatal(err)
			}
			ret, err := vm.Run(seccompData(ArchX86_64, 257, 3, 0, unix.O_RDONLY))
			if err != nil {
				t.Fatal(err)
			}
			if notified := uint32(ret) == retNotify; notified != tc.held {
				t.Errorf("a read-only openat notified %v, want %v", notified, tc.held)
			}
		})
	}
}

// TestUselibIsAbsent: uselib(2) opens a file by a pathname no arm sees, so every x86_64 filter answers it ENOSYS,
// whatever the record mode (ADR 0069 D2, R10's openat2 and open_by_handle_at); arm64 has no such syscall.
func TestUselibIsAbsent(t *testing.T) {
	for _, full := range []bool{false, true} {
		if got := runFilter(t, ArchX86_64, full, seccompData(ArchX86_64, 134, 0)); got != retENOSYS {
			t.Errorf("full %v: uselib answered %#x, want ENOSYS", full, got)
		}
	}
}
