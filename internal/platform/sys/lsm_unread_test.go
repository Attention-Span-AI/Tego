// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLSMListUnreadNamesTheCauseThatIsTrue (N114): the words for an unreadable active LSM list say which way failed and
// why, from the errors themselves, and offer only a remedy that exists for that cause. On a kernel older than 6.8 there
// is no syscall to permit; under Docker's default profiles the call is refused by seccomp and the file by AppArmor.
func TestLSMListUnreadNamesTheCauseThatIsTrue(t *testing.T) {
	pathErr := &os.PathError{Op: "open", Path: "/sys/kernel/security/lsm", Err: unix.ENOENT}
	deniedFile := &os.PathError{Op: "open", Path: "/sys/kernel/security/lsm", Err: unix.EACCES}
	for _, tc := range []struct {
		name         string
		sysErr, file error
		why, remedy  []string
		notWhy       []string
	}{
		{"Debian 12 under Docker's defaults: no syscall, no file", fmt.Errorf("lsm_list_modules(2): %w", unix.ENOSYS), pathErr,
			[]string{"ENOSYS", "older than Linux 6.8", "/sys/kernel/security/lsm is not there"},
			[]string{"older than 6.8 only the file can answer", "expose a readable /sys/kernel/security/lsm", "kernel 6.8 or later"}, []string{"seccomp filter outside Tego, such as Docker"}},
		{"Debian 13 under Docker's defaults: seccomp refuses the call, AppArmor the file", fmt.Errorf("lsm_list_modules(2): %w", unix.EPERM), deniedFile,
			[]string{"was refused (operation not permitted)", "seccomp filter outside Tego, such as Docker's default profile", "docker-default AppArmor"},
			[]string{"permit lsm_list_modules in the outer seccomp filter", "expose a readable /sys/kernel/security/lsm"}, []string{"older than Linux 6.8"}},
		{"a bare errno and the standard not-exist error", unix.EPERM, os.ErrNotExist,
			[]string{"was refused (operation not permitted)", "is not there"}, []string{"permit lsm_list_modules"}, nil},
		{"the call was not tried", nil, deniedFile, []string{"/sys/kernel/security/lsm was refused"}, []string{"permit lsm_list_modules"}, []string{"lsm_list_modules(2)"}},
		{"some other failure", errors.New("boom"), errors.New("bang"), []string{"lsm_list_modules(2) failed (boom)", "could not be read (bang)"}, []string{"permit lsm_list_modules"}, nil},
	} {
		why, remedy := LSMListUnread(tc.sysErr, tc.file)
		for _, w := range tc.why {
			if !strings.Contains(why, w) {
				t.Errorf("%s: why %q lacks %q", tc.name, why, w)
			}
		}
		for _, w := range tc.notWhy {
			if strings.Contains(why, w) {
				t.Errorf("%s: why %q says %q, which is not what happened", tc.name, why, w)
			}
		}
		for _, w := range tc.remedy {
			if !strings.Contains(remedy, w) {
				t.Errorf("%s: remedy %q lacks %q", tc.name, remedy, w)
			}
		}
	}
}
