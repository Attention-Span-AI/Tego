// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
)

// TestTheCgroupHandleGrantsWhatTheSupervisorTakes: startNotifyLoop finds the kernel's one-connect grants by asserting
// the tier's handle onto the supervisor's shapes, and a handle that no longer matches one leaves that Option nil
// without a compile error. Then an approved TCP connect, or an approved abstract unix name, is refused ask-unavailable
// at tiers 2 and 3 although the kernel could take its grant. This pins both shapes to cgroup's Handle, which serves
// tiers cgroup and bpflsm (GrantUnix takes the socket's cookie since ADR 0023's ratchet met ASK-UNIX).
func TestTheCgroupHandleGrantsWhatTheSupervisorTakes(t *testing.T) {
	var h any = (*cgroupenforce.Handle)(nil)
	if _, ok := h.(unixGranter); !ok {
		t.Error("cgroup's Handle is no unixGranter: an approved abstract unix name would be refused at tiers 2 and 3")
	}
	if _, ok := h.(connectGranter); !ok {
		t.Error("cgroup's Handle is no connectGranter: an approved TCP or UDP connect would be refused at tiers 2 and 3")
	}
	if _, ok := h.(datagramGranter); !ok {
		t.Error("cgroup's Handle is no datagramGranter: an approved UDP datagram would be refused at tiers 2 and 3")
	}
}
