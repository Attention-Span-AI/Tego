// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// released reports whether nothing accepts on addr any more.
func released(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return true
	}
	_ = c.Close()
	return false
}

// A listener closed without ever being served releases its socket. http.Server.Close closes only the
// listeners Serve was handed, so the one NewListener bound stayed open and kept accepting into the backlog.
func TestCloseWithoutServeReleasesTheSocket(t *testing.T) {
	l, err := NewListener(agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !released(t, addr) {
		t.Errorf("%s still accepts connections after Close without Serve", addr)
	}
	if err := l.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
}

// Manager.Stop without Start, which its doc allows, releases every listener's socket.
func TestManagerStopWithoutStartReleasesTheSockets(t *testing.T) {
	m, err := NewManager([]agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com"},
		{Provider: "openai", Host: "api.openai.com"},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	for _, l := range m.Listeners() {
		addrs = append(addrs, l.Addr().String())
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	for _, a := range addrs {
		if !released(t, a) {
			t.Errorf("%s still accepts connections after Stop without Start", a)
		}
	}
}

// A NewManager whose later entry cannot be built releases the sockets its earlier entries bound. The
// first entry binds a pinned port; the second, with no host, is refused.
func TestNewManagerFailureReleasesEarlierSockets(t *testing.T) {
	addr := freeLoopbackAddr(t)
	_, err := NewManager([]agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com"},
		{Provider: "openai"},
	}, Options{Listen: addr})
	if err == nil {
		t.Fatal("NewManager accepted a models[] entry without a host")
	}
	if !released(t, addr) {
		t.Errorf("%s still accepts connections after NewManager failed", addr)
	}
}

// freeLoopbackAddr is a loopback address whose port was free a moment ago.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	probe, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	return addr
}

// A pinned forwarder.listen with more than one models[] entry gives the first entry the pinned
// port and every later entry an ephemeral one on the same host. Each entry binding the pinned port lost the whole
// forwarder to EADDRINUSE on the second.
func TestPinnedListenWithTwoModelsBindsEveryEntry(t *testing.T) {
	addr := freeLoopbackAddr(t)
	m, err := NewManager([]agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com"},
		{Provider: "openai", Host: "api.openai.com"},
		{Provider: "anthropic", Host: "llm.example.com"},
	}, Options{Listen: addr})
	if err != nil {
		t.Fatalf("NewManager with a pinned port and three entries: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	ls := m.Listeners()
	if len(ls) != 3 {
		t.Fatalf("got %d listeners, want 3", len(ls))
	}
	if got := ls[0].Addr().String(); got != addr {
		t.Errorf("first listener at %s, want the pinned %s", got, addr)
	}
	seen := map[string]bool{}
	for _, l := range ls {
		ap, ok := l.AddrPort()
		if !ok || !ap.Addr().IsLoopback() {
			t.Errorf("listener %s is not on loopback", l.Addr())
		}
		if seen[l.Addr().String()] {
			t.Errorf("two listeners share %s", l.Addr())
		}
		seen[l.Addr().String()] = true
	}
}

func TestPinnedListen(t *testing.T) {
	for addr, want := range map[string]bool{
		"": false, "127.0.0.1:0": false, "127.0.0.1:00": false, "[::1]:0": false, "localhost:0": false,
		"127.0.0.1:8080": true, "[::1]:9": true, "localhost:65535": true, "127.0.0.1": false,
	} {
		if got := pinnedListen(addr); got != want {
			t.Errorf("pinnedListen(%q) = %v, want %v", addr, got, want)
		}
	}
}
