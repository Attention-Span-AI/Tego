// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// liveRaceRun runs modeGateRace's target under a contract with no net: section and host_sockets: true with a live block
// on the exact loopback port it races to, in place of a gate, and returns the harness and the receivers' counts.
func liveRaceRun(t *testing.T, kind string) (h *harness, blocked, benign int64) {
	t.Helper()
	benignC, benignTCP := countingTCP(t)
	blockedC, blockedTCP := countingTCP(t)
	_, benignUDP := countingUDP(t)
	_, blockedUDP := countingUDP(t)
	o := liveblock.New("r-race")
	if _, _, err := o.Add(liveblock.KindNet, "127.0.0.1:"+strconv.Itoa(blockedTCP), "t", time.Now()); err != nil {
		t.Fatal(err)
	}
	set := liveblock.Compile(o, liveblock.Resolved{})
	env := helperRace + "=" + strings.Join([]string{
		kind, strconv.Itoa(benignTCP), strconv.Itoa(blockedTCP), strconv.Itoa(benignUDP), strconv.Itoa(blockedUDP),
		strconv.Itoa(gateRaceAttempts),
	}, ",")
	h = startHarnessWith(t, harnessOpts{mode: modeGateRace, env: []string{env}, hostSockets: true,
		live: func() *liveblock.Set { return set }})
	h.stop(t)
	time.Sleep(300 * time.Millisecond) // the receivers' goroutines count what the target has already had answered
	return h, blockedC.Load(), benignC.Load()
}

// TestLiveBlockConnectRelayedRaceFree on a real kernel, real filter and real Loop: under host_sockets: true, a contract
// that continues its connects, a sibling thread that rewrites the address after the supervisor checked it does not reach
// the destination a live block names exactly. Before, a connect checked on a benign copy was answered CONTINUE and the
// kernel read the address again: 121 of 600 connects reached the blocked server while the ledger's line named the benign one.
// Now the copy is what is connected, as under a net gate (TestGateConnectRelayedRaceFree): the benign copy reaches the
// benign port, the unix-spelled one gets EAFNOSUPPORT, and the blocked one is refused.
func TestLiveBlockConnectRelayedRaceFree(t *testing.T) {
	h, blocked, benign := liveRaceRun(t, "connect")
	if c := h.check(t, "gate_direct"); !isErrno(c.Err, refusalErrno) {
		t.Fatalf("an unraced connect to the blocked port = %q, want the block's refusal", c.Err)
	}
	assertRaceClosed(t, h, "race_connect", blocked, benign)
}

// TestLiveBlockFastOpenRelayedRaceFree is TestLiveBlockConnectRelayedRaceFree for sendto(MSG_FASTOPEN) on a fresh TCP
// socket, which connects to the address the kernel reads (R12).
func TestLiveBlockFastOpenRelayedRaceFree(t *testing.T) {
	h, blocked, benign := liveRaceRun(t, "fastopen")
	if strings.Contains(h.check(t, "race_fastopen").Out, unix.EOPNOTSUPP.Error()) {
		t.Skip("TCP Fast Open client disabled on this host (net.ipv4.tcp_fastopen)")
	}
	assertRaceClosed(t, h, "race_fastopen", blocked, benign)
}
