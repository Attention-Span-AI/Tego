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
