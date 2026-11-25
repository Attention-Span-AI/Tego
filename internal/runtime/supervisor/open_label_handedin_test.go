// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/lsmlist"
)

// Docker's default profile on a Debian 12 kernel: no syscall, no securityfs.
var (
	noSyscall = func() ([]uint64, error) { return nil, unix.ENOSYS }
	noFile    = func(string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: "/sys/kernel/security/lsm", Err: unix.ENOENT}
	}
)

func setListFile(t *testing.T, p string) {
	t.Helper()
	if err := lsmlist.SetFile(p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lsmlist.SetFile("") })
}

// labelsRead answers the AppArmor attributes of a task (123) and the open deputy (456) as the given labels, and the
// namespace depth as the root namespace's.
func labelsRead(task, opener string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		switch p {
		case "/sys/kernel/security/apparmor/.ns_level":
			return []byte("0\n"), nil
		case "/proc/123/attr/apparmor/current":
			return []byte(task), nil
		case "/proc/456/attr/apparmor/current":
			return []byte(opener), nil
		}
		return nil, os.ErrNotExist
	}
}

// TestHandedInListIsUsedOnlyWhenTheKernelsTwoWaysFail: the list file is the third way, asked only after
// lsm_list_modules(2) and /sys/kernel/security/lsm both failed and only when the machine config names one; its list then
// decides which labels are compared, exactly as the kernel's would.
func TestHandedInListIsUsedOnlyWhenTheKernelsTwoWaysFail(t *testing.T) {
	setListFile(t, "/run/tego-lsm/lsm-list")
	asked := 0
	handed := func(list string, err error) func(int) (string, error) {
		return func(tid int) (string, error) {
			asked++
			if tid != 123 {
				t.Errorf("the list was read for task %d, want the trapped task 123", tid)
			}
			return list, err
		}
	}
	apparmor := func() ([]uint64, error) { return []uint64{100, 104}, nil }

	// Debian 12 under Docker's defaults, list handed in: the open proceeds when the labels are equal, and refuses when
	// they differ: the handed-in list names apparmor, so its labels are compared.
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, labelsRead("docker-default (enforce)", "docker-default (enforce)"), noSyscall, handed("capability,landlock,yama,apparmor", nil), false); err != nil {
		t.Errorf("equal labels with a handed-in list: %v", err)
	}
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, labelsRead("tight (enforce)", "docker-default (enforce)"), noSyscall, handed("capability,landlock,yama,apparmor", nil), false); !errors.Is(err, errOpenLabelDiffers) {
		t.Errorf("different labels with a handed-in list that names apparmor: %v, want the labels refused", err)
	}
	// The dangerous direction, pinned: a list that omits a label-bearing module compares nothing for it. This is why the
	// list file is believed only when it is the kernel's bytes or root's from this boot.
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, labelsRead("tight (enforce)", "docker-default (enforce)"), noSyscall, handed("capability,landlock,yama", nil), false); err != nil {
		t.Errorf("a list without apparmor compared apparmor labels: %v", err)
	}
	// An unknown module in a handed-in list refuses, as in the kernel's.
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, noFile, noSyscall, handed("capability,newmodule", nil), false); err == nil || !strings.Contains(err.Error(), `unsupported active LSM "newmodule"`) {
		t.Errorf("an unknown module in the handed-in list: %v", err)
	}
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, noFile, noSyscall, handed("capability,smack", nil), false); err == nil {
		t.Error("smack in the handed-in list admitted a held open")
	}
	if asked == 0 {
		t.Fatal("the list file was never asked")
	}

	// The kernel's answers come first: with the syscall or the file readable, the file is not asked.
	asked = 0
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, labelsRead("a", "a"), apparmor, handed("capability", nil), false); err != nil {
		t.Errorf("syscall answered: %v", err)
	}
	fileOnly := func(p string) ([]byte, error) {
		if p == "/sys/kernel/security/lsm" {
			return []byte("capability,yama\n"), nil
		}
		return nil, os.ErrNotExist
	}
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, fileOnly, noSyscall, handed("capability,apparmor", nil), false); err != nil {
		t.Errorf("securityfs answered: %v", err)
	}
	if asked != 0 {
		t.Errorf("the list file was asked %d times although the kernel's own ways answered", asked)
	}
}

// TestHandedInListNotBelievedRefusesWithTheCause: a list file that fails a check keeps every held open refused, in words
// that name the file and what is wrong with it, and offer the fix that exists.
func TestHandedInListNotBelievedRefusesWithTheCause(t *testing.T) {
	setListFile(t, "/run/tego-lsm/lsm-list")
	bad := &lsmlist.Unusable{Path: "/run/tego-lsm/lsm-list", Why: "was written in another boot (its boot id is \"x\", this boot's is \"y\"): it is stale"}
	err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, noFile, noSyscall, func(int) (string, error) { return "", bad }, false)
	if err == nil {
		t.Fatal("a handed-in list that was not believed admitted a held open")
	}
	for _, w := range []string{"could not be read", "lsm_list_modules(2) answered ENOSYS", "is not there", "lsm.list_file /run/tego-lsm/lsm-list was written in another boot", "make the list file /run/tego-lsm/lsm-list what the entrypoint writes at each start", "compose.yaml"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q lacks %q", err, w)
		}
	}
	// No file named: no third way is tried, and the refusal says a list can be handed in.
	if err := lsmlist.SetFile(""); err != nil {
		t.Fatal(err)
	}
	called := false
	err = checkOpenLabelAuthority(123, 456, unix.O_RDONLY, noFile, noSyscall, func(int) (string, error) { called = true; return "capability", nil }, false)
	if err == nil || called {
		t.Fatalf("with no lsm.list_file: err %v, list file asked %v", err, called)
	}
	for _, w := range []string{"hand the list in", "lsm.list_file", "bind the host's /sys/kernel/security/lsm read-only"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q lacks %q", err, w)
		}
	}
	// A bad setting is a refusal, never "no file".
	if lsmlist.SetFile("relative") == nil {
		t.Fatal("a relative path was accepted")
	}
	if err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, noFile, noSyscall, handedInList, false); err == nil || !strings.Contains(err.Error(), "not a clean absolute path") {
		t.Errorf("a bad lsm.list_file: %v", err)
	}
}

// TestHandedInListFromThisProcessIsRefusedWithoutAFile: the production reader, with a file that is not there, refuses.
func TestHandedInListFromThisProcessIsRefusedWithoutAFile(t *testing.T) {
	setListFile(t, t.TempDir()+"/lsm-list")
	err := checkOpenLabelAuthority(os.Getpid(), 456, unix.O_RDONLY, noFile, noSyscall, handedInList, false)
	if err == nil || !strings.Contains(err.Error(), "is not there") {
		t.Errorf("err %v", err)
	}
}
