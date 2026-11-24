// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/syslookup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAnObservedUnspecSendIsAConnectionToAnUnreadAddress is GAPS C61. In an observe run a send whose address is
// AF_UNSPEC is continued: an attempted send whose destination and result were not established (rule net.unspec-send,
// dst unspec). It is no disconnect: the receipt does not count it among the routine socket calls that name no place.
// It lists the attempt as an observed connection to an unread address. A connect(2) disassociation stays routine.
func TestAnObservedUnspecSendIsAConnectionToAnUnreadAddress(t *testing.T) {
	obs := record.VerdictObserved
	net := func(dst, rule string) line {
		return line{kind: record.KindNet, at: time.Second, verdict: obs, rule: rule, payload: record.NetPayload{Proto: "udp", Dst: dst}}
	}
	rc := compute(t, []line{watchedStart(), net("unspec", "net.unspec"), net("unspec", "net.unspec-send"),
		net("unspec", "net.unspec-send"), end(2*time.Second, 0)}, Options{})
	if rc.RoutineSockets != 1 {
		t.Errorf("routine sockets = %d, want 1: only the connect(2) reset is a disconnect", rc.RoutineSockets)
	}
	if len(rc.Connections) != 1 || rc.Connections[0].Destination != syslookup.UnreadSendPlace || rc.Connections[0].Count != 2 ||
		rc.ConnectionTries != 2 {
		t.Fatalf("connections = %+v, tries %d; want 2 to %q", rc.Connections, rc.ConnectionTries, syslookup.UnreadSendPlace)
	}
	var text bytes.Buffer
	_ = rc.Text(&text)
	for _, want := range []string{"\nConnections\n  2 connections to 1 place.\n", syslookup.UnreadSendPlace + "  2  recorded, not blocked",
		"  Also 1 routine socket call that names no place"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("receipt lacks %q:\n%s", want, text.String())
		}
	}

	// Alone, the send is the run's only connection and no routine call is claimed.
	rc = compute(t, []line{watchedStart(), net("unspec", "net.unspec-send"), end(time.Second, 0)}, Options{})
	text.Reset()
	_ = rc.Text(&text)
	if rc.RoutineSockets != 0 || strings.Contains(text.String(), "routine socket") || !strings.Contains(text.String(), syslookup.UnreadSendPlace) {
		t.Errorf("a lone unspec send: routine sockets %d\n%s", rc.RoutineSockets, text.String())
	}
}
