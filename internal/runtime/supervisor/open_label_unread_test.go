// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestUnreadLSMListRefusesInWordsThatAreTrue (N114): a held open is refused whenever the active module list cannot be
// read, which is the safe answer (without the list no module's labels can be compared, and a label the completing
// process lacks could admit what the agent's own open would not). The decision is unchanged by the words; the error says
// what failed and why, and offers a remedy that exists: on a kernel before 6.8 there is no syscall to permit.
func TestUnreadLSMListRefusesInWordsThatAreTrue(t *testing.T) {
	deniedFile := func(string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: "/sys/kernel/security/lsm", Err: unix.EACCES}
	}
	absentFile := func(string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: "/sys/kernel/security/lsm", Err: unix.ENOENT}
	}
	for _, tc := range []struct {
		name  string
		read  func(string) ([]byte, error)
		mods  func() ([]uint64, error)
		wants []string
		nots  []string
	}{
		{"Debian 13, Docker defaults: seccomp refuses the call, AppArmor the file", deniedFile,
			func() ([]uint64, error) { return nil, unix.EPERM },
			[]string{"could not be read", "lsm_list_modules(2) was refused", "seccomp filter outside Tego", "docker-default AppArmor", "permit lsm_list_modules in the outer seccomp filter"},
			[]string{"older than Linux 6.8"}},
		{"Debian 12, Docker defaults: a kernel with no call and no file", absentFile,
			func() ([]uint64, error) { return nil, unix.ENOSYS },
			[]string{"could not be read", "ENOSYS", "older than Linux 6.8", "is not there", "only the file can answer"},
			[]string{"seccomp filter outside Tego, such as Docker"}},
	} {
		err := checkOpenLabelAuthority(1, 1, unix.O_RDONLY, tc.read, tc.mods, false)
		if err == nil {
			t.Fatalf("%s: an unreadable module list admitted a held open", tc.name)
		}
		for _, w := range tc.wants {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q lacks %q", tc.name, err, w)
			}
		}
		for _, w := range tc.nots {
			if strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q says %q", tc.name, err, w)
			}
		}
	}
	// The assertion about AppArmor's namespace never waives module discovery.
	if err := checkOpenLabelAuthority(1, 1, unix.O_RDONLY, absentFile, func() ([]uint64, error) { return nil, unix.ENOSYS }, true); err == nil {
		t.Fatal("fs.apparmor_assume_root_namespace admitted a held open with no module list")
	}
}
