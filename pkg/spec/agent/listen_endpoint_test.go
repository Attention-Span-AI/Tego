// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"testing"
)

func TestParseListenEndpoint(t *testing.T) {
	for _, tc := range []struct {
		raw, proto, host string
		port             int
	}{
		{"tcp://127.0.0.1:8080", ProtoTCP, "127.0.0.1", 8080},
		{"udp://0.0.0.0:0", ProtoUDP, "0.0.0.0", 0},
		{"tcp://[::]:0", ProtoTCP, "::", 0},
		{"udp://[::ffff:192.0.2.1]:53", ProtoUDP, "192.0.2.1", 53},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			e, err := ParseListenEndpoint(tc.raw)
			if err != nil || e.Proto != tc.proto || e.Host != tc.host || e.Port != tc.port || !e.Static() {
				t.Fatalf("got %+v, %v", e, err)
			}
		})
	}
	for _, raw := range []string{
		"127.0.0.1:8080", "tcp://localhost:8080", "udp://192.0.2.0/24:53",
		"tcp://[fe80::1%eth0]:8080", "tcp://127.0.0.1:65536", "tcp://127.0.0.1:-1",
		"tcp://user@127.0.0.1:80", "tcp://127.0.0.1:80/path", "udp://127.0.0.1:53?x=1",
		"udp://127.0.0.1:53#fragment", "http://127.0.0.1:80", "tcp://:80",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseListenEndpoint(raw); !errors.Is(err, ErrEndpoint) {
				t.Fatalf("wanted ErrEndpoint, got %v", err)
			}
		})
	}
	for _, raw := range []string{"unix:/run/listener.sock", "unix:@listener"} {
		e, err := ParseListenEndpoint(raw)
		if err != nil || e.Proto != ProtoUnix || e.Kind != EndpointUnix {
			t.Fatalf("%q: got %+v, %v", raw, e, err)
		}
	}
}
