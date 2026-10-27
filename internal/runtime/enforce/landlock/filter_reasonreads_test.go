// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestReasonReadsNotifyEveryOpen holds Prepare to ADR 0077: a table with reason reads at tier landlock gets the filter's
// every-open arm (the one fs.ask_read and held reads take) and nothing else of theirs (no held-completion arm), and a
// table with the default (auto, the measured default: off) or reason.reads: off gets exactly the filter a table without
// the key gets: the options are the ones Prepare built before the key existed, and the program is byte for byte the
// same.
func TestReasonReadsNotifyEveryOpen(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	compile := func(t *testing.T, extra string) *agent.RuleTable {
		t.Helper()
		contract := filepath.Join(root, "agent.yaml")
		yaml := "version: 0\nname: reason\ncommand: [\"/bin/sh\", \"-c\", \"true\"]\nfs:\n  write: [\"" + work + "\"]\n" +
			"  deny_read: [\"" + filepath.Join(root, "secrets") + "\"]\nexec:\n  allow: [\"sh\"]\ntier: landlock\nrecord: summary\n" + extra
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
		return rt
	}
	if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	var quiet [][]bpf.RawInstruction
	for _, tc := range []struct {
		name, extra string
		notified    bool
	}{
		{"on", "reason:\n  reads: on\n", true},
		{"on, harness none", "harness: none\nreason:\n  reads: on\n", true},
		{"the default", "", false},
		{"off", "reason:\n  reads: off\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := compile(t, tc.extra)
			if rt.ReasonReadsNotified() != tc.notified || rt.ReadsHeld() || rt.HoldsFSNotifications() {
				t.Fatalf("reason reads %v, held %v, holds fs notifications %v", rt.ReasonReadsNotified(), rt.ReadsHeld(), rt.HoldsFSNotifications())
			}
			h, _ := prepare(t, 7, rt)
			if h.filterOpts.askRead != tc.notified || h.filterOpts.heldOpens || h.ask {
				t.Errorf("every-open arm %v, held-completion arm %v, ask %v; want %v, false, false", h.filterOpts.askRead, h.filterOpts.heldOpens, h.ask, tc.notified)
			}
			// The arm is all reason reads change: the same options with it off are the filter a table without the
			// key is given.
			before := h.filterOpts
			before.askRead = false
			want, err := assembleFilter(NativeArch(), before)
			if err != nil {
				t.Fatal(err)
			}
			if same := slices.Equal(h.filter, want); same == tc.notified {
				t.Errorf("filter equal to the one without the every-open arm: %v, want %v", same, !tc.notified)
			}
			if !tc.notified {
				quiet = append(quiet, h.filter)
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
			if notified := uint32(ret) == retNotify; notified != tc.notified {
				t.Errorf("a read-only openat notified %v, want %v", notified, tc.notified)
			}
		})
	}
	if len(quiet) != 2 || !slices.Equal(quiet[0], quiet[1]) {
		t.Errorf("the default and reason.reads: off built different filters (%d)", len(quiet))
	}
}
