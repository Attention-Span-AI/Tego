// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// armedRunner starts the real supervisor loop over a pipe, as TestStartNotifyLoopReturnsOnceTheLoopIsArmed
// does, with m as the machine config, and returns the runner once the loop is armed.
func armedRunner(t *testing.T, m *config.Machine) *runner {
	t.Helper()
	g, gctx := newGroup(context.Background())
	r := &runner{
		log:     slog.New(slog.DiscardHandler),
		rt:      &agent.RuleTable{Contract: &agent.Contract{Name: "resolver-test"}},
		id:      identity.RunID("r-00000000-000000000000a-aaaaaa"),
		agentID: identity.AgentID("resolver-test"),
		deps:    Deps{Config: m},
		queue:   NewQueue(4), group: g, notifyFD: listenerPipe(t),
	}
	t.Cleanup(func() {
		g.Cancel()
		_ = g.Wait()
	})
	done := make(chan error, 1)
	go func() { done <- r.startNotifyLoop(gctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("startNotifyLoop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor loop never armed")
	}
	if r.dnsSet == nil {
		t.Fatal("no resolver set was handed to the supervisor")
	}
	return r
}

// TestAnExplicitResolverListReplacesResolvConf is spec/config/v0's `resolver:` setting reaching the
// supervisor: a machine config that names its DNS servers gets exactly those on R14's port-53
// exception. The run used to read /etc/resolv.conf whatever the config said, so the operator's list
// was silently ignored and UDP/53 went to whichever servers the file named instead.
func TestAnExplicitResolverListReplacesResolvConf(t *testing.T) {
	// TEST-NET addresses, which no resolv.conf on a real machine lists.
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.53:53"),
		netip.MustParseAddrPort("[2001:db8::53]:53"),
	}
	m := config.Builtin()
	m.Resolver = config.Setting[config.ResolverMode]{Value: config.ResolverMode{Servers: want}}
	r := armedRunner(t, m)
	if got := r.dnsSet.ResolverAddrs(); !slices.Equal(got, want) {
		t.Fatalf("the supervisor was given resolvers %v, want the configured %v", got, want)
	}

	// An explicit empty list is an operator who wants no resolver exception, not one who wants the
	// file's: DNS then has to be declared in net.allow like any other destination (E32).
	m = config.Builtin()
	m.Resolver = config.Setting[config.ResolverMode]{Value: config.ResolverMode{}}
	if got := armedRunner(t, m).dnsSet.ResolverAddrs(); len(got) != 0 {
		t.Fatalf("an empty resolver list gave the supervisor %v, want none", got)
	}
}

// TestAutoResolverReadsResolvConf is the other half: `resolver: auto`, the built-in default, is the
// nameservers of /etc/resolv.conf at run start (identity-config.md E28).
func TestAutoResolverReadsResolvConf(t *testing.T) {
	m := config.Builtin()
	if !m.Resolver.Value.Auto {
		t.Fatalf("the built-in resolver setting is %v, want auto", m.Resolver.Value)
	}
	want := dns.SystemResolvers()
	if got := armedRunner(t, m).dnsSet.ResolverAddrs(); !slices.Equal(got, want) {
		t.Fatalf("resolver: auto gave the supervisor %v, want resolv.conf's %v", got, want)
	}
}
