// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestOneLandlockWrapperPerSyscall is ADR 0029 (2) for every Landlock syscall: production code issues
// landlock_create_ruleset, landlock_add_rule and landlock_restrict_self from exactly one place each, the
// wrappers in landlock.go; every other caller (enforce/landlock's syscall seam, the ABI probe, the
// descriptor kind check) goes through them. Tests may issue them directly.
func TestOneLandlockWrapperPerSyscall(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root: %v", err)
	}
	// The syscall number as Go code names it (unix.SYS_..., or syscall.SYS_...): a tool that names the
	// syscall in a string or a comment (tools/fdcheck's producer table) issues nothing.
	syscallRE := regexp.MustCompile(`\b(?:unix|syscall)\.SYS_LANDLOCK_(CREATE_RULESET|ADD_RULE|RESTRICT_SELF)\b`)
	sites := make(map[string][]string)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range syscallRE.FindAllStringSubmatch(string(data), -1) {
			sites[m[1]] = append(sites[m[1]], rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range []string{"CREATE_RULESET", "ADD_RULE", "RESTRICT_SELF"} {
		if got := sites[sc]; len(got) != 1 || got[0] != "internal/platform/sys/landlock.go" {
			t.Errorf("SYS_LANDLOCK_%s is issued from %q; want once, from internal/platform/sys/landlock.go", sc, got)
		}
	}
}

// TestLandlockWrappersReturnTheErrno: the raw wrappers return the kernel's errno unwrapped, so every caller
// (and enforce/landlock's fake seam) compares answers with errors.Is and adds its own context once.
func TestLandlockWrappersReturnTheErrno(t *testing.T) {
	if _, err := LandlockABI(); err != nil {
		t.Skipf("no Landlock here: %v", err)
	}
	attr := unix.LandlockPathBeneathAttr{Parent_fd: -1}
	err := LandlockAddRule(-1, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&attr), 0)
	var errno unix.Errno
	if !errors.As(err, &errno) || errno != unix.EBADF || err.Error() != unix.EBADF.Error() {
		t.Fatalf("landlock_add_rule on fd -1 = %v; want the bare EBADF", err)
	}
	bad := LandlockRulesetAttr{Handled_access_fs: 1 << 63}
	if fd, err := LandlockCreateRuleset(&bad, 0); fd != -1 || !errors.Is(err, unix.EINVAL) || err.Error() != unix.EINVAL.Error() {
		t.Fatalf("landlock_create_ruleset with an unknown right = %d, %v; want -1 and the bare EINVAL", fd, err)
	}
}

// TestLandlockCreateRulesetTail: the attr is the ABI 10 layout on every kernel. One below ABI 10 knows its first
// 24 bytes, takes a zero tail, and refuses a non-zero one rather than ignore it, so the struct's growth cannot
// loosen or drop a ruleset there. An ABI 10 kernel reads the tail as quiet masks, which is not this test's case.
func TestLandlockCreateRulesetTail(t *testing.T) {
	abi, err := LandlockABI()
	if err != nil {
		t.Skipf("no Landlock here: %v", err)
	}
	if size := unsafe.Sizeof(LandlockRulesetAttr{}); size != 48 {
		t.Fatalf("landlock_ruleset_attr is %d bytes, want the 48 this test and the kernels below ABI 10 were held to", size)
	}
	attr := LandlockRulesetAttr{Handled_access_fs: unix.LANDLOCK_ACCESS_FS_READ_FILE}
	fd, err := LandlockCreateRulesetFD(&attr)
	if err != nil {
		t.Fatalf("ABI %d refused a 48-byte attr with a zero tail: %v", abi, err)
	}
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	if abi >= 10 {
		return
	}
	attr.Quiet_access_fs = unix.LANDLOCK_ACCESS_FS_READ_FILE
	if fd, err := LandlockCreateRuleset(&attr, 0); fd != -1 || !errors.Is(err, unix.E2BIG) {
		t.Fatalf("ABI %d with a non-zero tail = %d, %v; want -1 and E2BIG", abi, fd, err)
	}
}
