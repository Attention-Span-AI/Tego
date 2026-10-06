// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sysConst is one generated constant of x/sys's zsysnum files: "\tSYS_NAME = 123".
var sysConst = regexp.MustCompile(`(?m)^\s+SYS_([A-Z0-9_]+)\s+= (\d+)\s*$`)

// TestSyscallTablesMatchXSys checks the embedded tables LinuxSyscalls serves against the golang.org/x/sys source
// this module pins (`go list -m`), entry for entry both ways, so the tables the filter and supervisor tests check
// their numbers against are x/sys's, not a third hand-typed copy. An x/sys upgrade that adds syscalls fails it
// until testdata/sysnum_linux_*.txt is regenerated from the new zsysnum files.
func TestSyscallTablesMatchXSys(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("locating golang.org/x/sys: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatal("go list -m gave golang.org/x/sys no directory (not downloaded?)")
	}
	for _, goarch := range []string{"amd64", "arm64"} {
		src, err := os.ReadFile(filepath.Join(dir, "unix", "zsysnum_linux_"+goarch+".go"))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]uint32{}
		for _, m := range sysConst.FindAllSubmatch(src, -1) {
			n, err := strconv.ParseUint(string(m[2]), 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			want[strings.ToLower(string(m[1]))] = uint32(n)
		}
		if len(want) < 300 {
			t.Fatalf("%s: only %d SYS_ constants parsed from x/sys; the generated file's layout changed", goarch, len(want))
		}
		got, err := LinuxSyscalls(goarch)
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(got, want) {
			for name, nr := range want {
				if g, ok := got[name]; !ok || g != nr {
					t.Errorf("%s: %s is %d in x/sys, %d (present %v) in the embedded table", goarch, name, nr, g, ok)
				}
			}
			for name := range got {
				if _, ok := want[name]; !ok {
					t.Errorf("%s: %s is in the embedded table, not in x/sys", goarch, name)
				}
			}
		}
	}
}

// TestParseSysnumRefusesMalformedLines keeps a damaged table from reading as a short one.
func TestParseSysnumRefusesMalformedLines(t *testing.T) {
	for _, bad := range []string{"openat\n", "openat x\n", "openat 1\nopenat 2\n"} {
		if _, err := parseSysnum([]byte(bad)); err == nil {
			t.Errorf("parseSysnum(%q) = nil error", bad)
		}
	}
	m, err := parseSysnum([]byte("# c\n\nopenat 257\n"))
	if err != nil || len(m) != 1 || m["openat"] != 257 {
		t.Errorf("parseSysnum = %v, %v", m, err)
	}
}
