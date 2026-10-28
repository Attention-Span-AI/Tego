// SPDX-License-Identifier: Apache-2.0

package syslookup

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestRoutine(t *testing.T) {
	const off = "unmatched"
	for _, c := range []struct {
		dst, rule string
		want      bool
	}{
		{"unix:/var/run/nscd/socket", off, true},
		{"/run/nscd/socket", off, true},
		{"unix:/run/systemd/userdb/io.systemd.Multiplexer", off, true},
		{"unix:/run/systemd/resolve/io.systemd.Resolve", off, true},
		{"unix:/run/dbus/system_bus_socket", off, true},
		{"unix:/run/user/1000/bus", off, true},
		{"unix:/run/user/1000/bus2", off, false},
		{"/run/user/x/bus", off, false},
		{"unix:/var/run/docker.sock", off, false},
		{"unix:/tmp/agent.sock", off, false},
		// Port 53 on this machine is a stub resolver, whatever the line's rule.
		{"127.0.0.53:53", ResolverRule, true},
		{"127.0.0.53:53", off, true},
		{"[::1]:53", off, true},
		{"[::ffff:127.0.0.53]:53", off, true},
		{"localhost:53", off, true},
		// Anywhere else only the engine's word makes it a lookup: the port says nothing.
		{"8.8.8.8:53", ResolverRule, true},
		{"[2001:db8::53]:53", ResolverRule, true},
		{"dns.google:53", ResolverRule, true},
		{"8.8.8.8:53", off, false},
		{"203.0.113.9:53", off, false},
		{"203.0.113.9:53", "net[203.0.113.9:53]", false},
		{"[2001:db8::53]:53", off, false},
		{"dns.google:53", off, false},
		{"127.attacker.example:53", off, false},
		{"127.0.0.1:9821", off, false},
		{"10.0.0.1:530", off, false},
		{"fe80::53", off, false},
		{"", off, false},
	} {
		if got := Routine(c.dst, c.rule); got != c.want {
			t.Errorf("Routine(%q, %q) = %v, want %v", c.dst, c.rule, got, c.want)
		}
	}
}

// TestResolverRuleIsTheEngines: the classifier reads the rule the engine writes, which it cannot import.
func TestResolverRuleIsTheEngines(t *testing.T) {
	if ResolverRule != agent.ResolverRule {
		t.Errorf("ResolverRule = %q, the engine writes %q", ResolverRule, agent.ResolverRule)
	}
}
