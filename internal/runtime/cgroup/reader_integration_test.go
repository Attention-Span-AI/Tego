// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// readerRole is the environment variable that makes this test's binary one of the two processes of
// TestIntegrationThePlacementFixReadByAnotherUserNamesSudo: "admin", the shell of the person who types sudo -u, which
// starts "svc", the process of the account tego runs as.
const readerRole = "TEGO_TEST_PLACEMENT_READER"

// The two accounts, with no passwd entry needed: uid 4243 is the administrator, 4242 the service account.
const (
	adminUID = 4243
	svcUID   = 4242
)

// TestIntegrationThePlacementFixReadByAnotherUserNamesSudo is the review's M1 through the real path, with no stub:
// a process of uid 4242 whose parent is a process of uid 4243 (the shell an administrator typed sudo -u in) is refused
// by canPlace with the remedy CanPlace gives it, placementRemedy, which asks config.ReadByAnother over the real /proc.
// The remedy, which tego doctor prints after "fix: " and tego run, watch and test print at the end of their error line,
// names the command that opens the shell as 4242 (ScopeAsCommand), never the bare one, which typed in the
// administrator's shell opens the administrator's own scope (acceptance 3, 2026-11-11). Root only: it starts the two
// processes with their uids. The unit tests stub the reader (TestThePlacementFixOpensTheShellAsThatUserForAnotherReader)
// or feed /proc trees (config's TestStartedByAnotherReadsTheLoginAndTheProcessTree); this one runs the real chain.
func TestIntegrationThePlacementFixReadByAnotherUserNamesSudo(t *testing.T) {
	switch os.Getenv(readerRole) {
	case "admin":
		// The administrator's shell: start the account's process, as sudo -u does, with the capabilities root gave it.
		cmd := exec.Command(os.Args[0], "-test.run=^TestIntegrationThePlacementFixReadByAnotherUserNamesSudo$")
		cmd.Env = append(os.Environ(), readerRole+"=svc")
		cmd.Dir = "/"
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: svcUID, Gid: svcUID, Groups: []uint32{}}}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "the account's process: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "svc":
		// A refusal for the place: no cgroup.procs to write above this process, so canPlace says what to do instead.
		err := canPlace("/nonexistent-tego-mount", []byte("0::/user.slice/user-4243.slice/session-1.scope\n"),
			"/nonexistent-tego-mount/user.slice/user-4242.slice/user@4242.service", placementRemedy)
		var de *DetectError
		if !errors.As(err, &de) || !errors.Is(err, ErrBesideSubtree) {
			fmt.Printf("canPlace = %v, want the placement refusal\n", err)
			os.Exit(1)
		}
		fmt.Printf("uid=%d\nremedy=%s\nerror=%s\n", os.Getuid(), de.Remedy, err.Error())
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: starts processes of uids 4243 and 4242")
	}
	self := testutil.ExecutableForAnyUID(t)
	cmd := exec.Command(self, "-test.run=^TestIntegrationThePlacementFixReadByAnotherUserNamesSudo$")
	cmd.Env = append(os.Environ(), readerRole+"=admin")
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: adminUID, Gid: adminUID, Groups: []uint32{}},
		AmbientCaps: []uintptr{unix.CAP_SETUID, unix.CAP_SETGID},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the administrator's process: %v\n%s", err, out)
	}
	said := string(out)
	want := ScopeAsCommand(svcUID, "bash")
	if !strings.Contains(said, fmt.Sprintf("uid=%d\n", svcUID)) {
		t.Fatalf("the account's process did not run as uid %d:\n%s", svcUID, said)
	}
	for _, line := range []string{"remedy=", "error="} {
		got := ""
		for _, l := range strings.Split(said, "\n") {
			if strings.HasPrefix(l, line) {
				got = l
			}
		}
		if !strings.Contains(got, want) || !strings.Contains(got, "from your own login shell, not one sudo or su opened") ||
			strings.Contains(got, "open one with systemd-run --user --scope bash") {
			t.Errorf("%s read by uid %d's shell is %q, want %q from your own login shell, never the bare command", line, adminUID, got, want)
		}
	}
	if !strings.HasPrefix(want, "sudo -u ") || !strings.HasSuffix(want, " XDG_RUNTIME_DIR=/run/user/4242 systemd-run --user --scope bash") {
		t.Errorf("ScopeAsCommand(%d) = %q, want sudo -u, the account and its logind folder", svcUID, want)
	}
}
