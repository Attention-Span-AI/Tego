// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

type dialLookup struct {
	addresses []netip.Addr
	calls     int
}

func (r *dialLookup) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls++
	return r.addresses, nil
}

func TestValidatedDialFreezesAnswerAndBlocksLaterRebinding(t *testing.T) {
	lookup := &dialLookup{addresses: []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("93.184.216.34")}}
	var targets []string
	d := newValidatedDial(agent.ModelEndpoint{Host: "API.Example.com.", Port: 8443}, nil, lookup, func(_ context.Context, network, target string) (net.Conn, error) {
		targets = append(targets, network+" "+target)
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	}, nil)
	d.hosts = hostaddr.New(func() ([]net.Addr, error) { return nil, nil }, time.Now, time.Second)
	conn, err := d.DialContext(context.Background(), "tcp", "api.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if lookup.calls != 1 || len(targets) != 1 || targets[0] != "tcp 93.184.216.34:8443" {
		t.Fatalf("lookups=%d targets=%v", lookup.calls, targets)
	}
	lookup.addresses = []netip.Addr{netip.MustParseAddr("10.0.0.9")}
	if _, err := d.DialContext(context.Background(), "tcp", "api.example.com:8443"); err == nil {
		t.Fatal("public model rebound to private network")
	}
	if len(targets) != 1 {
		t.Fatal("refused rebinding reached dial")
	}
	if _, err := d.DialContext(context.Background(), "tcp", "api.example.com:443"); err == nil {
		t.Fatal("alternate port dialed")
	}
	if _, err := d.DialContext(context.Background(), "tcp", "attacker.test:8443"); err == nil {
		t.Fatal("alternate host dialed")
	}
}

func TestValidatedDialFailClosedHostIdentityAndMachineRange(t *testing.T) {
	lookup := &dialLookup{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	extra := []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}
	dials := 0
	d := newValidatedDial(agent.ModelEndpoint{Host: "api.example.com", Port: 443}, extra, lookup, func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, fmt.Errorf("unexpected dial")
	}, nil)
	extra[0] = netip.MustParsePrefix("10.0.0.0/8")
	if _, err := d.DialContext(context.Background(), "tcp", "api.example.com:443"); err == nil || dials != 0 {
		t.Fatal("machine denial alias or bypass")
	}
	d.rules.DeniedResolved = nil
	d.hosts = hostaddr.New(func() ([]net.Addr, error) { return nil, fmt.Errorf("enumeration failed") }, time.Now, time.Second)
	if _, err := d.DialContext(context.Background(), "tcp", "api.example.com:443"); err == nil || dials != 0 {
		t.Fatal("unknown host addresses admitted")
	}
	d.hosts = hostaddr.New(func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("93.184.216.34"), Mask: net.CIDRMask(32, 32)}}, nil
	}, time.Now, time.Second)
	if _, err := d.DialContext(context.Background(), "tcp", "api.example.com:443"); err == nil || dials != 0 {
		t.Fatal("model name admitted this host's interface")
	}
}

// TestValidatedDialRefusesWhatTheLocalTableSendsHere is agent-contract R18's this-host class in the forwarder, read as
// the supervisor's resolved-address check reads it: a model name answered with an address of an AnyIP range the local
// routing table sends here (`ip route add local 198.51.100.0/24 dev lo`) reaches a server bound to all interfaces, as
// one answered with the host's LAN address does, so it is not dialed; the name's other address is. Read from the
// interfaces alone it was dialed. The dial newValidatedDial makes reads the real table: 127.0.0.2 is no interface's
// address and is this host's by the `local 127.0.0.0/8` route the kernel keeps for loopback.
func TestValidatedDialRefusesWhatTheLocalTableSendsHere(t *testing.T) {
	lookup := &dialLookup{addresses: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}
	var targets []string
	d := newValidatedDial(agent.ModelEndpoint{Host: "api.example.com", Port: 443}, nil, lookup, func(_ context.Context, network, target string) (net.Conn, error) {
		targets = append(targets, target)
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	}, nil)
	if local, known := d.hosts.Has(netip.MustParseAddr("127.0.0.2")); !local || !known {
		t.Errorf("the forwarder's snapshot = %v, %v for 127.0.0.2: it does not read the local table", local, known)
	}
	d.hosts = hostaddr.NewWithLocalTable(func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}}, nil
	}, func() (hostaddr.LocalTable, error) {
		return hostaddr.LocalTable{Local: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}, nil
	}, time.Now, time.Second)
	if _, err := d.DialContext(context.Background(), "tcp", "api.example.com:443"); err == nil || len(targets) != 0 {
		t.Fatalf("a model name in an AnyIP range was dialed: %v, %v", targets, err)
	}
	lookup.addresses = []netip.Addr{netip.MustParseAddr("198.51.100.8"), netip.MustParseAddr("203.0.113.9")}
	conn, err := d.DialContext(context.Background(), "tcp", "api.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(targets) != 1 || targets[0] != "203.0.113.9:443" {
		t.Fatalf("dialed %v, want the name's address past the range alone", targets)
	}
}
