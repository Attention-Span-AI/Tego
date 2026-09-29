// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRelayedConnectCarriesTheKernelsRefusal is enforce-cgroup-observe.md R5, E5 and R15 (a breadcrumb that is
// gone, as after Detach, is `observed`, never a failure) from the supervisor's
// side: at tier 2 the run's connect4/6 decides a connect this loop relays on the agent's socket, and when it
// refuses one this loop allowed, the relay returns EPERM. The line then says what the kernel did and why,
// read from the run's breadcrumb; a breadcrumb that does not name this connect freshly makes the line
// `observed` rather than attribute someone else's decision; one that says the kernel allowed keeps this
// loop's allow; and any other errno is the connect's own result, which the kernel is not asked about.
func TestRelayedConnectCarriesTheKernelsRefusal(t *testing.T) {
	const addr = 0x40000
	sa := sockaddrIn4("93.184.216.34", 443)
	rules := []agent.NetRule{netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34")}
	const kernelRule = "net[kernel-row]"
	tests := []struct {
		name       string
		connectErr error
		kernel     record.Verdict
		wantAsked  bool
		wantVerd   record.Verdict
		wantRule   string
		wantReason record.Reason
	}{
		{"kernel refused", unix.EPERM, record.VerdictRefused, true,
			record.VerdictRefused, kernelRule, record.ReasonNetNotAllowed},
		{"no fresh breadcrumb names it", unix.EPERM, "", true,
			record.VerdictObserved, "net[api.example.com:443]", ""},
		{"kernel allowed, EPERM from elsewhere", unix.EPERM, record.VerdictAllow, true,
			record.VerdictAllow, "net[api.example.com:443]", ""},
		{"another errno is the connect's own", unix.ECONNREFUSED, record.VerdictRefused, false,
			record.VerdictAllow, "net[api.example.com:443]", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, sa)
			f.sockType = unix.SOCK_STREAM
			f.connectErr = tc.connectErr
			l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
			var asked netip.AddrPort
			n := notifFor(connectNR(), 4242, 5, addr, uint64(len(sa)))
			l.kernelNet = func(ap netip.AddrPort, proto string, notified time.Time) (record.Verdict, string, record.Reason) {
				asked = ap
				if proto != "tcp" {
					t.Errorf("asked with proto %q, want the stream socket's tcp", proto)
				}
				if !notified.Equal(n.recvAt) {
					t.Errorf("asked with notified %v, want the notification's arrival %v", notified, n.recvAt)
				}
				if tc.kernel == record.VerdictRefused {
					return tc.kernel, kernelRule, record.ReasonNetNotAllowed
				}
				return tc.kernel, "", ""
			}
			l.handle(n)
			if got, ok := f.lastResp(); !ok || got.Error != -int32(tc.connectErr.(unix.Errno)) {
				t.Fatalf("response = %+v, want the relayed errno %v (I3)", got, tc.connectErr)
			}
			if tc.wantAsked != asked.IsValid() {
				t.Fatalf("kernel asked = %v (%v), want %v", asked.IsValid(), asked, tc.wantAsked)
			}
			if tc.wantAsked && asked != netip.MustParseAddrPort("93.184.216.34:443") {
				t.Errorf("kernel asked about %v", asked)
			}
			ev := sink.one(t)
			if ev.Kind != record.KindNet || ev.Verdict != tc.wantVerd || ev.Rule != tc.wantRule || ev.Reason != tc.wantReason {
				t.Errorf("line = %s %s rule %q reason %q, want %s rule %q reason %q", ev.Kind, ev.Verdict, ev.Rule,
					ev.Reason, tc.wantVerd, tc.wantRule, tc.wantReason)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
		})
	}
}
