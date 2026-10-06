// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"strconv"
	"strings"
)

//go:embed testdata/sysnum_linux_amd64.txt testdata/sysnum_linux_arm64.txt
var sysnumFiles embed.FS

// LinuxSyscalls is the Linux syscall table of goarch ("amd64" or "arm64"), name to number: golang.org/x/sys's
// generated unix/zsysnum_linux_<goarch>.go, lower-cased with SYS_ dropped (umount2, rt_sigqueueinfo, prlimit64).
// It is embedded, not read from the module cache, so a test binary copied into the KVM guest has it too;
// TestSyscallTablesMatchXSys checks the embedded copy against the x/sys source the module pins. It exists so the
// seccomp filter's and the supervisor's hand-typed numbers are checked against a source neither was typed from:
// a wrong number that lands on another dispatched syscall passes every test that only asks a handler exists.
func LinuxSyscalls(goarch string) (map[string]uint32, error) {
	b, err := sysnumFiles.ReadFile("testdata/sysnum_linux_" + goarch + ".txt")
	if err != nil {
		return nil, fmt.Errorf("testutil: no syscall table for %q: %w", goarch, err)
	}
	return parseSysnum(b)
}

// parseSysnum reads "name number" lines, skipping blank lines and # comments.
func parseSysnum(b []byte) (map[string]uint32, error) {
	m := map[string]uint32{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		name, num, ok := strings.Cut(s, " ")
		if !ok {
			return nil, fmt.Errorf("testutil: syscall table line %d: %q is not \"name number\"", line, s)
		}
		n, err := strconv.ParseUint(num, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("testutil: syscall table line %d: %w", line, err)
		}
		if _, dup := m[name]; dup {
			return nil, fmt.Errorf("testutil: syscall table line %d: %s twice", line, name)
		}
		m[name] = uint32(n)
	}
	return m, sc.Err()
}
