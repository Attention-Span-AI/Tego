// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestDNSCompiledPolicyOwnsMutableInputAndInitialDeadline(t *testing.T) {
	const src = "version: 0\nname: dns-policy\ncommand: [/bin/true]\nnet:\n  allow: [api.example.com:443]\n  dns: {mode: broker, allow: [api.example.com], types: [A], max_stale: 0s, cache: 0}\n"
	c, ds, err := LoadBytes("dns.yaml", []byte(src), nil)
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	now := time.Unix(1700000000, 0)
	rt, ds, err := Compile(c, &config.Machine{}, Offline(), WithClock(func() time.Time { return now }), WithMountInfo(""))
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	if len(rt.Net) != 1 || rt.Net[0].ExpiresAt != now.Add(DefaultDNSTTL) {
		t.Fatalf("initial expiry missing: %+v", rt.Net)
	}
	*c.Net.DNS.Cache, *c.Net.DNS.MaxStale = 512, Duration(time.Hour)
	c.Net.DNS.Allow[0], c.Net.DNS.Types[0] = "attacker.test", "TXT"
	if *rt.DNS.Cache != 0 || *rt.DNS.MaxStale != 0 || rt.DNS.Allow[0] != "api.example.com" || rt.DNS.Types[0] != "A" {
		t.Fatal("compiled DNS settings alias declaration")
	}
	if _, ok := rt.DNSQueries.Match("api.example.com", 1); !ok {
		t.Fatal("compiled matcher changed")
	}
}

func TestNetworkPolicyRefusesIgnoredOrUnboundedControls(t *testing.T) {
	for _, clause := range []string{
		"dns: {mode: system, allow: [api.example.com]}",
		"dns: {mode: off, cache: 0}", "dns: {max_stale: 25h}",
		"dns: {mode: broker, types: [TYPE0]}", "dns: {mode: broker, max_parallel: 0}",
		"proxy: {max_streams: 8}", "proxy: {http2: true, max_tunnel_bytes: 1MiB}",
		"proxy: {http2: true, connect: [other.example.com:443]}",
		"proxy: {http2: true, websocket: [{host: api.example.com, methods: [POST], allow: [/]}]}",
	} {
		src := "version: 0\nname: invalid-policy\ncommand: [/bin/true]\ncapture: forwarder\nmodels: [{host: api.example.com, port: 443, provider: anthropic}]\nnet: {" + clause + "}\n"
		if _, _, err := LoadBytes("bad.yaml", []byte(src), nil); err == nil {
			t.Fatalf("ignored or invalid policy loaded: %s", clause)
		}
	}
}

func TestProxyCompiledScopeIsFixedAndImmutable(t *testing.T) {
	src := "version: 0\nname: proxy-policy\ncommand: [/bin/true]\ncapture: forwarder\nmodels: [{host: API.Example.com., port: 8443, provider: anthropic}]\nnet:\n  proxy: {http2: true, max_streams: 4, connect: ['api.example.com:8443'], websocket: [{host: api.example.com, allow: [/socket]}]}\n"
	c, ds, err := LoadBytes("proxy.yaml", []byte(src), nil)
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	p, err := CompileProxyPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Net.Proxy.Connect[0], c.Net.Proxy.WebSocket[0].Allow[0] = "attacker.test:8443", "/elsewhere"
	if !p.HTTP2Enabled() || p.Bounds().MaxStreams != 4 {
		t.Fatal("compiled protocol bounds missing")
	}
	if _, ok := p.Connect("api.example.com:8443"); !ok {
		t.Fatal("compiled CONNECT changed")
	}
	if _, ok := p.Connect("api.example.com:443"); ok {
		t.Fatal("CONNECT broadened to another port")
	}
	for _, tc := range []struct {
		path string
		want bool
	}{{"/socket", true}, {"/socket/channel", true}, {"/socket-other", false}, {"/socket/%2fsecret", false}, {"/socket/..;/admin", false}, {"/socket/..%3B/admin", false}} {
		if rule, ok := p.WebSocket("api.example.com:8443", tc.path); ok != tc.want || ok && !strings.HasPrefix(rule, "net.proxy.websocket[") {
			t.Fatalf("WS %q: %s %v", tc.path, rule, ok)
		}
	}
}
