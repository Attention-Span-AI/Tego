// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"golang.org/x/sys/unix"
)

// A socket inherited from an outside creator must still apply the original
// governed task's bind policy. Creator-only attribution would allow both cases.
func TestPlaneImportedUnixBindOnRealKernel(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-policy", true: "declared-name"}[allow], func(t *testing.T) {
			name := fmt.Sprintf("tego-import-bind-%d-%v", os.Getpid(), allow)
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			outside := os.NewFile(uintptr(fd), "outside-created-unbound-socket")
			defer outside.Close()
			contract := &agent.Contract{Net: &agent.NetSection{Listen: []string{}}}
			if allow {
				contract.Net.Listen = []string{"unix:@" + name}
			}
			listen, _, _, err := agent.CompileListenerControl(contract, nil)
			if err != nil {
				t.Fatal(err)
			}
			rt := &agent.RuleTable{Contract: contract, Listen: listen, Tier: backend.TierCgroup, Record: agent.RecordFull}
			h, dir, _ := realControlRun(t, "import-bind", rt)
			if !h.NetworkGuarantees().ListenerBind || !h.BindOutcomes() {
				t.Fatal("actual bind plane/outcome proof missing")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPlaneImportedUnixBindHelper$")
			cmd.Env = append(os.Environ(), "TEGO_IMPORTED_BIND_HELPER="+name)
			cmd.ExtraFiles = []*os.File{outside}
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child actual bind: %v %s", err, out)
			}
			got, err := strconv.Atoi(strings.TrimSpace(string(out)))
			want := int(unix.EACCES)
			if allow {
				want = 0
			}
			if err != nil || got != want {
				t.Fatalf("imported bind got %q, want errno %d", out, want)
			}
		})
	}
}

func TestPlaneImportedUnixBindHelper(t *testing.T) {
	name := os.Getenv("TEGO_IMPORTED_BIND_HELPER")
	if name == "" {
		return
	}
	errno := 0
	if err := unix.Bind(3, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
		var value unix.Errno
		if !errors.As(err, &value) {
			os.Exit(2)
		}
		errno = int(value)
	}
	fmt.Println(errno)
	os.Exit(0)
}
