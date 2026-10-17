// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestAwaitReadyNamesWhyTheDeputyDidNotStart: the stage reads the deputy's readiness socket as the deputy writes it. A
// 1 byte is ready. A 0 byte and text is the reason the deputy gave (its fatal line), which the stage's report and so
// the run's warning name; an end of stream with no message is a deputy that died before it could say. Each failure is
// ECHILD. A KVM run's held start failed with "no child processes" alone, which named no cause.
func TestAwaitReadyNamesWhyTheDeputyDidNotStart(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte // nil: the deputy's end closes with nothing sent
		want string // "" for ready
	}{
		{"ready", []byte{1}, ""},
		{"a reason", append([]byte{0}, "seccomp(SET_MODE_FILTER, TSYNC): permission denied"...), "seccomp(SET_MODE_FILTER, TSYNC): permission denied"},
		{"no reason", nil, "with no reason (killed or crashed)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0]) //nolint:errcheck // a test socket
			if tc.msg != nil {
				if _, err := unix.Write(fds[1], tc.msg); err != nil {
					t.Fatal(err)
				}
			}
			_ = unix.Close(fds[1])
			err = awaitReady(fds[0], 5*time.Second)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ready: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, syscall.ECHILD) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("awaitReady = %v, want ECHILD naming %q", err, tc.want)
			}
		})
	}
}
