// SPDX-License-Identifier: Apache-2.0

//go:build integration

package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestIntegrationThisBox asserts the unprivileged probes against the development box: kernel >= 5.14
// with BTF, a delegated user@<uid>.service with cpu memory pids, Landlock ABI >= 2, and a seccomp
// NEW_LISTENER + ADDFD(SEND) round trip. The four probes that need privilege answer "requires root
// to test" here and are asserted in TestIntegrationAsRoot instead.
func TestIntegrationThisBox(t *testing.T) {
	root := os.Geteuid() == 0
	unprivileged := map[CheckID]bool{CheckKernel: true, CheckBTF: true, CheckCgroupV2: true,
		CheckLandlock: true, CheckSeccomp: true}
	for _, r := range Probe(context.Background(), os.Getuid()) {
		switch {
		case unprivileged[r.ID] && !r.OK:
			t.Errorf("%s: %s; fix: %s", r.ID, r.Detail, r.Fix)
		case !r.OK && !root:
			t.Logf("%s (needs privilege here): %s", r.ID, r.Detail)
		default:
			t.Logf("%s: %s", r.ID, r.Detail)
		}
	}
	abi, err := sys.LandlockABI()
	if err != nil || abi < MinLandlockABI {
		t.Fatalf("landlock abi %d %v", abi, err)
	}
}

// TestIntegrationReportAsUser is the acceptance for an ordinary user on this box: tier
// landlock, exit 0, the capability matrix rendered with this machine's values, and — because bpf is
// not an active LSM on Ubuntu — the lsm= line that would make tier 3 reachable.
func TestIntegrationReportAsUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test describes the unprivileged answer; see TestIntegrationAsRoot")
	}
	rep, err := Run(context.Background(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tier != backend.TierLandlock {
		t.Fatalf("tier %q, want landlock", rep.Tier)
	}
	if rep.ExitCode() != identity.ExitOK {
		t.Errorf("exit %d", rep.ExitCode())
	}
	if err := rep.WriteText(os.Stderr); err != nil {
		t.Fatal(err)
	}
	if !rep.LSM.BPFActive && rep.Fix == "" {
		t.Error("no fix line although tier 3 is out of reach")
	}
	require := &Report{Tier: rep.Tier, Require: backend.TierCgroup}
	if require.ExitCode() != identity.ExitRequire {
		t.Errorf("--require cgroup here exits %d, want %d", require.ExitCode(), identity.ExitRequire)
	}
}

// TestIntegrationAsRoot exercises the halves that need privilege: D7's program loads and links,
// D8's fanotify permission round trip and its FAN_DENY refusal, and D6's functional BPF LSM check. It skips cleanly as an ordinary user, which is how it behaves on this development box
// (no passwordless sudo); the kernel matrix in test/vm is where it actually runs.
func TestIntegrationAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("D6's functional probe, D7's program loads and D8's fanotify round trip need root (CAP_BPF, CAP_SYS_ADMIN)")
	}
	_, _, kernel := probeKernelVersion()
	progs, hookResults := probePrograms(true, os.Getuid(), kernel)
	t.Logf("programs: %s", progs.Detail)
	for _, h := range hookResults {
		if !h.OK() {
			t.Logf("hook %s (%s): btf=%v loaded=%v attached=%v %s", h.Hook, h.Tier, h.BTF, h.Loaded, h.Attached, h.Detail)
		}
	}
	// Every attach point this kernel's BTF declares is reported as declared: the pre-load check once
	// read a nil btf.Type and called all of them absent, on this very kernel.
	if spec, err := btf.LoadKernelSpec(); err == nil {
		for i, h := range hooks {
			// A hook held back by a version guard (Absent) never looked at the BTF: a vendor kernel may carry the
			// function (RHEL 9's 5.14 has security_file_truncate) below the version the tier's program needs.
			if h.btfName != "" && hookInBTF(spec, h) == nil && i < len(hookResults) && !hookResults[i].BTF && !hookResults[i].Absent {
				t.Errorf("%s: %s is in this kernel's BTF but D7 reported btf=false: %s", h.Name, h.btfName,
					hookResults[i].Detail)
			}
		}
	}
	for _, h := range hookResults {
		if h.Tier != backend.TierCgroup {
			continue
		}
		// An optional hook this kernel predates is absent, not failed: the tier runs without it (§5 R7), and
		// nothing was loaded for it, stand-in or not.
		if h.Absent {
			if kernel.AtLeast(Version{6, 7, 0}) {
				t.Errorf("tier-2 hook %s is reported absent on %s, which has it: %s", h.Hook, kernel, h.Detail)
			}
			t.Logf("tier-2 hook %s absent on %s: %s", h.Hook, kernel, h.Detail)
			continue
		}
		// With the objects D7 loads the program a run loads; without them it can only stand in for
		// it, and must say so.
		if h.StandIn == bpfobj.Available() {
			t.Errorf("tier-2 hook %s: stand_in=%v in a build whose objects are available=%v", h.Hook, h.StandIn,
				bpfobj.Available())
		}
		if !h.OK() {
			t.Errorf("tier-2 hook %s (stand_in=%v) does not load and attach on this kernel: %s", h.Hook,
				h.StandIn, h.Detail)
		}
	}

	// Capture's rows (R27 D7): every uprobe_ssl program loads, as the program capture loads wherever
	// this build carries it, and attaches wherever this machine has a system libssl. None of them has
	// a tier, so none can reach a tier's missing list.
	_, sslErr := bpfobj.Load(bpfobj.ObjectUprobeSSL)
	lib := systemLibSSL(libsslDirs())
	t.Logf("uprobe_ssl in this build: %v; system libssl: %+v", sslErr == nil, lib)
	captured := 0
	for _, h := range hookResults {
		if !h.Capture {
			continue
		}
		captured++
		t.Logf("capture row %s: loaded=%v attached=%v load_only=%v stand_in=%v %s", h.Hook, h.Loaded,
			h.Attached, h.LoadOnly, h.StandIn, h.Detail)
		if h.Tier != "" || h.StandIn != (sslErr != nil) || !h.Loaded {
			t.Errorf("capture row %s: tier %q stand_in=%v loaded=%v; uprobe_ssl loads=%v", h.Hook, h.Tier,
				h.StandIn, h.Loaded, sslErr == nil)
		}
		if lib.err == nil && !h.Attached && !(h.LoadOnly && h.Target != "") {
			t.Errorf("capture row %s did not attach at %s: %s", h.Hook, lib.path, h.Detail)
		}
	}
	if captured != len(captureHooks) {
		t.Errorf("%d capture rows, want %d", captured, len(captureHooks))
	}

	fan, fanState := probeFanotify(true, kernel)
	t.Logf("fanotify: %s %+v", fan.Detail, fanState)
	if !fan.OK {
		t.Errorf("fanotify: %s; fix: %s", fan.Detail, fan.Fix)
	}
	if !fanState.PermissionMarks {
		t.Error("a root fanotify probe could not add permission marks")
	}
	// The probe used to mark its temporary *directory* and open a file inside it. A plain
	// FAN_MARK_INODE mark covers only the object named (fanotify_mark(2); child opens need
	// FAN_EVENT_ON_CHILD in the mask), so no permission event was ever generated and D8 never reached
	// its reply. A root run must complete the FAN_DENY round trip, and the FAN_DENY must refuse the
	// open: that refusal is what tier 2's listener sends on every kernel (enforce-cgroup-observe.md
	// §6 E2).
	if strings.Contains(fan.Detail, "could not be tested") {
		t.Errorf("D8 did not reach its FAN_DENY reply at all: %s", fan.Detail)
	}
	if !fanState.Refuses {
		t.Errorf("a FAN_DENY did not refuse D8's own open: %s", fan.Detail)
	}
	// The EACCES reply comes from a FAN_CLASS_CONTENT group, which no kernel accepts it from
	// (FAN_DENY_ERRNO, 6.14, is FAN_CLASS_PRE_CONTENT only, and never EACCES). A kernel that did
	// would make DenyErrno true, and the listener's bare FAN_DENY would then be a choice rather than
	// the only option; log it so a kernel matrix run shows the day it changes.
	t.Logf("kernel %s: FAN_DENY_ERRNO from a FAN_CLASS_CONTENT group = %v", kernel, fanState.DenyErrno)

	lsm, lsmState := probeLSM(true)
	t.Logf("lsm: %s %+v", lsm.Detail, lsmState)
	if lsmState.BPFActive && lsmState.Functional == "" {
		t.Error("bpf is active but the functional probe did not run")
	}

	rep, err := Run(context.Background(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.WriteText(os.Stderr); err != nil {
		t.Fatal(err)
	}
	if bpfobj.Available() && (rep.Tier == "" || rep.Tier == backend.TierLandlock) {
		t.Errorf("tier %q as root; sudo should reach at least cgroup on this kernel", rep.Tier)
	}
	// A kernel that passes every tier-2 probe still gives a binary without the objects nothing to
	// load, so the derivation must not offer the tier (enforce.Buildable).
	if !bpfobj.Available() && rep.Tiers[backend.TierCgroup] {
		t.Errorf("a build without the BPF objects offers tier cgroup: %+v", rep.Tiers)
	}
	for tier, reasons := range rep.Missing {
		for _, r := range reasons {
			if strings.Contains(r, "SSL_") {
				t.Errorf("tier %s lists a capture row: %s", tier, r)
			}
		}
	}
	// I7: doctor leaves no bpffs entry of its own behind.
	if entries, err := os.ReadDir("/sys/fs/bpf"); err == nil {
		for _, e := range entries {
			if len(e.Name()) > 6 && e.Name()[:6] == "doctor" {
				t.Errorf("doctor left %s behind on bpffs", e.Name())
			}
		}
	}
}
