// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The relay runs outside the agent's session. An agent may omit O_NOCTTY, but
// opening its peer must not acquire a controlling terminal for the supervisor,
// including when policy subsequently refuses delivery.
func TestIntegrationPtyPeerPreservesSession(t *testing.T) {
	const child = "TEGO_TEST_PTY_SESSION"
	if os.Getenv(child) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestIntegrationPtyPeerPreservesSession$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("session helper: %v\n%s", err, out)
		}
		return
	}
	before, err := sys.ControllingTTYDevice()
	if err != nil || before != 0 {
		t.Fatalf("new session has tty %d: %v", before, err)
	}
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(master) //nolint:errcheck // isolated terminal fixture
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	slave, err := peerFromMaster(master, unix.O_RDWR, -1) // hostile caller omits O_NOCTTY
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close() //nolint:errcheck // isolated peer
	after, err := sys.ControllingTTYDevice()
	if err != nil || after != 0 {
		t.Fatalf("peer open acquired supervisor tty %d: %v", after, err)
	}
}
