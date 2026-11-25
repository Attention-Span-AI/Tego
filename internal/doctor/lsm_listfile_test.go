// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/lsmlist"
)

// dockerDefaults stands in for Debian 12 or 13 under Docker's default profile: the call answers ENOSYS, securityfs is not
// mounted, and the kernel log is not readable. list is what the machine config's list file gives (nil: none is named).
func dockerDefaults(t *testing.T, listPath string, list func() (string, lsmlist.Kind, error)) {
	t.Helper()
	oldSys, oldFile, oldLog, oldList := lsmSyscall, lsmFile, lsmKernelLog, lsmListFile
	t.Cleanup(func() {
		lsmSyscall, lsmFile, lsmKernelLog, lsmListFile = oldSys, oldFile, oldLog, oldList
		_ = lsmlist.SetFile("")
	})
	lsmSyscall = func() ([]string, error) { return nil, fmt.Errorf("lsm_list_modules(2): %w", unix.ENOSYS) }
	lsmFile = func(string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: securityFSLSM, Err: unix.ENOENT}
	}
	lsmKernelLog = func() ([]byte, error) { return nil, unix.EACCES }
	lsmListFile = func(int, func(string) ([]byte, error)) (string, lsmlist.Kind, error) {
		if list == nil {
			return "", "", lsmlist.ErrNotConfigured
		}
		return list()
	}
	if err := lsmlist.SetFile(listPath); err != nil {
		t.Fatal(err)
	}
}

// TestHandedInListAnswersHeldOpensAndNeverTheTier: with the list file believed, the held-open reader has the list
// and doctor's row says so, skipped, since the tier is decided from the kernel's own answer only; ReadLSMState, which every
// tier decision reads, still fails.
func TestHandedInListAnswersHeldOpensAndNeverTheTier(t *testing.T) {
	dockerDefaults(t, "/run/tego-lsm/lsm-list", func() (string, lsmlist.Kind, error) {
		return "lockdown,capability,landlock,yama,apparmor,bpf", lsmlist.KindHandedIn, nil
	})
	held, err := ReadHeldOpenList()
	if err != nil || held.Source != LSMSourceListFile || strings.Join(held.Modules, ",") != "lockdown,capability,landlock,yama,apparmor,bpf" {
		t.Fatalf("ReadHeldOpenList = %+v, %v", held, err)
	}
	if st, err := ReadLSMState(); !errors.Is(err, ErrLSMList) || st.Source != LSMSourceNone || st.BPFActive {
		t.Errorf("a handed-in list reached a tier decision: %+v, %v", st, err)
	}
	if bpfLSMActive() {
		t.Error("bpfLSMActive is true from a handed-in list: tier bpflsm would be offered on a file's word")
	}
	r, st := probeLSM(false)
	if r.OK || !r.Skipped || st.Source != LSMSourceNone {
		t.Errorf("row %+v, state %+v: want skipped, not ok, with no list for the tier", r, st)
	}
	for _, w := range []string{"lockdown,capability,landlock,yama,apparmor,bpf via /run/tego-lsm/lsm-list (the list the container's entrypoint wrote as root at this boot)",
		"held file opens read this list", "tier bpflsm is not decided from it", "whether bpf is an active LSM is unknown"} {
		if !strings.Contains(r.Detail, w) {
			t.Errorf("detail %q lacks %q", r.Detail, w)
		}
	}
}

// TestListFileThatIsNotBelievedIsSaidWithItsCause: a list file that fails its checks leaves the row failing, with what is
// wrong with the file and the fix that exists, and the held-open reader without a list.
func TestListFileThatIsNotBelievedIsSaidWithItsCause(t *testing.T) {
	bad := &lsmlist.Unusable{Path: "/run/tego-lsm/lsm-list", Why: "can be written by someone other than root: /run/tego-lsm/lsm-list is writable by its group or by others (mode 0666)"}
	dockerDefaults(t, "/run/tego-lsm/lsm-list", func() (string, lsmlist.Kind, error) { return "", "", bad })
	if _, err := ReadHeldOpenList(); !errors.Is(err, ErrLSMList) {
		t.Fatalf("ReadHeldOpenList err %v", err)
	}
	r, _ := probeLSM(false)
	if r.OK || r.Skipped {
		t.Errorf("row %+v: want a failure", r)
	}
	for _, w := range []string{"cannot read the active LSM list", "lsm_list_modules(2) answered ENOSYS", "/sys/kernel/security/lsm is not there",
		"lsm.list_file /run/tego-lsm/lsm-list can be written by someone other than root", "held-label-unavailable"} {
		if !strings.Contains(r.Detail, w) {
			t.Errorf("detail %q lacks %q", r.Detail, w)
		}
	}
	if !strings.Contains(r.Fix, "make the list file /run/tego-lsm/lsm-list what the entrypoint writes at each start") || !strings.Contains(r.Fix, "mount securityfs") {
		t.Errorf("fix %q", r.Fix)
	}
}

// TestNoListFileSaysItCanBeHandedIn: with no lsm.list_file the row fails as before and now says the list can be handed in.
func TestNoListFileSaysItCanBeHandedIn(t *testing.T) {
	dockerDefaults(t, "", nil)
	r, _ := probeLSM(false)
	if r.OK || r.Skipped {
		t.Fatalf("row %+v", r)
	}
	for _, w := range []string{"hand the list in", "lsm.list_file", "bind the host's /sys/kernel/security/lsm read-only"} {
		if !strings.Contains(r.Fix, w) {
			t.Errorf("fix %q lacks %q", r.Fix, w)
		}
	}
	if strings.Contains(r.Detail, "lsm.list_file") {
		t.Errorf("detail names a file nobody set: %q", r.Detail)
	}
}

// TestKernelLogDoesNotAnswerHeldOpens: the kernel log passes doctor's tier row, but a held open never reads it, so the row
// says held opens are refused (it used to say nothing, while every held open was refused).
func TestKernelLogDoesNotAnswerHeldOpens(t *testing.T) {
	dockerDefaults(t, "", nil)
	lsmKernelLog = func() ([]byte, error) {
		return []byte("LSM: initializing lsm=lockdown,capability,landlock,yama,apparmor\n"), nil
	}
	r, st := probeLSM(false)
	if st.Source != LSMSourceKernelLog {
		t.Fatalf("state %+v", st)
	}
	for _, w := range []string{"via /dev/kmsg", "held file opens do not read the kernel log and are refused until the list can be read", "held-label-unavailable"} {
		if !strings.Contains(r.Detail, w) {
			t.Errorf("detail %q lacks %q", r.Detail, w)
		}
	}
	// With a list file believed, the same row says where held opens read it.
	dockerDefaults(t, "/run/tego-lsm/lsm-list", func() (string, lsmlist.Kind, error) { return "capability,apparmor", lsmlist.KindKernel, nil })
	lsmKernelLog = func() ([]byte, error) { return []byte("LSM: initializing lsm=capability,apparmor\n"), nil }
	if r, _ = probeLSM(false); !strings.Contains(r.Detail, "held file opens read the list from lsm.list_file /run/tego-lsm/lsm-list") {
		t.Errorf("detail %q", r.Detail)
	}
}

// TestHeldOpenListPrefersTheKernelsOwnWays: the call and the file answer before the list file is asked.
func TestHeldOpenListPrefersTheKernelsOwnWays(t *testing.T) {
	asked := false
	dockerDefaults(t, "/run/tego-lsm/lsm-list", func() (string, lsmlist.Kind, error) { asked = true; return "capability", lsmlist.KindHandedIn, nil })
	lsmSyscall = func() ([]string, error) { return []string{"capability", "yama"}, nil }
	if st, err := ReadHeldOpenList(); err != nil || st.Source != LSMSourceSyscall || asked {
		t.Errorf("syscall: %+v, %v, list file asked %v", st, err, asked)
	}
	lsmSyscall = func() ([]string, error) { return nil, unix.ENOSYS }
	lsmFile = func(string) ([]byte, error) { return []byte("capability,yama\n"), nil }
	if st, err := ReadHeldOpenList(); err != nil || st.Source != LSMSourceSecurityFS || asked {
		t.Errorf("securityfs: %+v, %v, list file asked %v", st, err, asked)
	}
}
