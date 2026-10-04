// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const strictClientHelperEnv = "TEGO_STRICT_CLIENT_FILTER_HELPER"

// TestStrictClientFilterOnRealKernel verifies the native filter's import and
// listener refusals as actual syscalls in an isolated unprivileged child.
func TestStrictClientFilterOnRealKernel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStrictClientFilterHelper$")
	cmd.Env = append(os.Environ(), strictClientHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("strict filter child: %v: %s", err, out)
	}
	var got map[string]int
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("report %q: %v", out, err)
	}
	tab, _ := tableFor(NativeArch())
	if len(got) != len(tab.ClientDeny) {
		t.Fatalf("reported %v", got)
	}
	for _, s := range tab.ClientDeny {
		if got[s.Name] != int(unix.ENOSYS) {
			t.Errorf("%s actual errno=%d want ENOSYS", s.Name, got[s.Name])
		}
	}
}

func TestStrictClientFilterHelper(t *testing.T) {
	if os.Getenv(strictClientHelperEnv) != "1" {
		t.Skip("helper only")
	}
	runtime.LockOSThread()
	filter, err := assembleFilter(NativeArch(), filterOpts{abi: 10, strictNet: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0]))}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		t.Fatal(errno)
	}
	tab, _ := tableFor(NativeArch())
	got := map[string]int{}
	for _, s := range tab.ClientDeny {
		_, _, errno := unix.RawSyscall(uintptr(s.NR), ^uintptr(0), 0, 0)
		got[s.Name] = int(errno)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(data))
	// No test framework cleanup or another task runs on the filtered thread.
	os.Exit(0)
}
