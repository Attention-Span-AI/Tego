// SPDX-License-Identifier: Apache-2.0

package nextrun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers from answers (a name it does not hold resolves to 192.0.2.1) and records every name it is
// asked. With hold set, every lookup waits until hold is closed, whatever its context says, as a resolver that does
// not honor its context would.
type fakeResolver struct {
	answers map[string]error
	empty   map[string]bool
	hold    chan struct{}

	mu    sync.Mutex
	asked []string
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.asked = append(f.asked, host)
	f.mu.Unlock()
	if f.hold != nil {
		<-f.hold
		return nil, ctx.Err()
	}
	if err := f.answers[host]; err != nil {
		return nil, err
	}
	if f.empty[host] {
		return nil, nil
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

func (f *fakeResolver) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.asked)
	slices.Sort(out)
	return out
}

// TestUnresolvedHosts: the host names a change adds are looked up once each, and those that do not resolve come back
// with DNS's own short words, in the order the entries name them; an entry that needs no DNS is never looked up.
func TestUnresolvedHosts(t *testing.T) {
	r := &fakeResolver{
		answers: map[string]error{
			"api.exmple.test": &net.DNSError{Err: "no such host", Name: "api.exmple.test", Server: "127.0.0.53:53", IsNotFound: true},
			"flaky.test":      &net.DNSError{Err: "server misbehaving", Name: "flaky.test", Server: "127.0.0.53:53"},
		},
		empty: map[string]bool{"empty.test": true},
	}
	added := []string{"api.example.test:443", "api.exmple.test:443", "192.0.2.7:443", "10.0.0.0/8:443", "unix:/run/x.sock",
		"tcp://empty.test:80", "udp://api.exmple.test:53", "API.Exmple.Test.:8443", "no port here", "flaky.test:443"}
	got := UnresolvedHosts(t.Context(), r, added, time.Second)
	want := []Unresolved{{"api.exmple.test", "no such host"}, {"empty.test", "no addresses"}, {"flaky.test", "server misbehaving"}}
	if !slices.Equal(got, want) {
		t.Errorf("UnresolvedHosts = %+v, want %+v", got, want)
	}
	if names := r.names(); !slices.Equal(names, []string{"api.example.test", "api.exmple.test", "empty.test", "flaky.test"}) {
		t.Errorf("looked up %q: each host name once, and no address, CIDR or socket", names)
	}
	if got := UnresolvedHosts(t.Context(), r, []string{"api.example.test:443"}, time.Second); got != nil {
		t.Errorf("a host that resolves: %+v", got)
	}
	r = &fakeResolver{}
	if got := UnresolvedHosts(t.Context(), r, []string{"192.0.2.7:443", "unix:@abstract"}, time.Second); got != nil || len(r.names()) != 0 {
		t.Errorf("no host name: %+v, asked %q", got, r.names())
	}
}

// TestUnresolvedHostsBudget: a resolver that never answers, even past its context, does not hold the caller past the
// budget: the host comes back as unanswered within it.
func TestUnresolvedHostsBudget(t *testing.T) {
	r := &fakeResolver{hold: make(chan struct{})}
	t.Cleanup(func() { close(r.hold) })
	const budget = 50 * time.Millisecond
	start := time.Now()
	got := UnresolvedHosts(t.Context(), r, []string{"slow.test:443", "slower.test:443"}, budget)
	if elapsed := time.Since(start); elapsed > budget+time.Second {
		t.Errorf("waited %s on a resolver that never answers; the budget is %s", elapsed, budget)
	}
	want := []Unresolved{{"slow.test", "no answer within 50ms"}, {"slower.test", "no answer within 50ms"}}
	if !slices.Equal(got, want) {
		t.Errorf("UnresolvedHosts = %+v, want %+v", got, want)
	}
}

// TestUnresolvedHostsDeadline: a resolver that honors its context ends with the budget, and says so.
func TestUnresolvedHostsDeadline(t *testing.T) {
	r := resolverFunc(func(ctx context.Context, host string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	})
	got := UnresolvedHosts(t.Context(), r, []string{"slow.test:443"}, 20*time.Millisecond)
	if want := []Unresolved{{"slow.test", "no answer within 20ms"}}; !slices.Equal(got, want) {
		t.Errorf("UnresolvedHosts = %+v, want %+v", got, want)
	}
}

// TestUnresolvedHostsCancelled: when the caller's context ends first nothing is blamed on a host.
func TestUnresolvedHostsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	r := resolverFunc(func(ctx context.Context, _ string) ([]netip.Addr, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if got := UnresolvedHosts(ctx, r, []string{"gone.test:443"}, time.Second); got != nil {
		t.Errorf("a cancelled check blamed %+v", got)
	}
}

// TestUnresolvedHostsBounded: one change has at most maxHosts names looked up.
func TestUnresolvedHostsBounded(t *testing.T) {
	var added []string
	for i := range maxHosts + 4 {
		added = append(added, fmt.Sprintf("h%d.test:443", i))
	}
	r := &fakeResolver{}
	UnresolvedHosts(t.Context(), r, added, time.Second)
	if n := len(r.names()); n != maxHosts {
		t.Errorf("looked up %d names, want %d", n, maxHosts)
	}
}

type resolverFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	return f(ctx, host)
}
