// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestPlaneControlOwnedSocketAndPtraceFixtures(t *testing.T) {
	pre := planeMakeEach
	if err := pre.prepareControls(); err != nil {
		pre.closeControls()
		t.Fatal(err)
	}
	defer pre.closeControls()
	for _, hook := range []string{"socket_bind", "socket_listen", "ptrace_access_check", "ptrace_traceme"} {
		if err := planeControlAction(hook, pre); err != nil {
			t.Errorf("outside the governed cgroup %s: %v", hook, err)
		}
	}
	if pre.keyErr == nil {
		if err := planeControlAction("key_permission", pre); err != nil {
			t.Errorf("outside the governed cgroup key_permission: %v", err)
		}
	} else {
		t.Logf("private key fixture unavailable here: %v; other control fixtures still exercised", pre.keyErr)
	}
	// A successful listen must have changed the actual socket's state.
	if accepting, err := unix.GetsockoptInt(pre.listening, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || accepting != 1 {
		t.Fatalf("listen fixture did not actually listen: %d %v", accepting, err)
	}
}
