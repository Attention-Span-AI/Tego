// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"strings"
	"testing"
)

// TestLoadTestTableConformanceActions is ADR 0017 (b)'s compile --test grammar (plans/adr0017 C9, ADR 0019's "an
// answer for every runnable action"): fs.link, fs.attr, net.socket, net.send and exec.anonymous rows load into the
// kinds the decision core answers, with every field a row of that action needs and nothing it cannot use.
func TestLoadTestTableConformanceActions(t *testing.T) {
	const src = `version: 0
tests:
  - action: fs.link
    path: out/a
    dest: out/b
    expect: allow
  - action: fs.attr
    path: out/a
    expect: allow
  - action: net.socket
    family: AF_INET
    type: SOCK_STREAM
    expect: allow
  - action: net.socket
    family: 2
    type: 2
    protocol: IPPROTO_ICMP
    expect: refused
  - action: net.socket
    family: AF_TIPC
    type: SOCK_SEQPACKET
    socketpair: true
    expect: refused
  - action: net.send
    host_port: 127.0.0.1:53
    expect: allow
  - action: net.send
    path: unix:@log
    expect: refused
  - action: exec.anonymous
    expect: refused
    rule: exec-anon
  - action: net.socket
    family: af_inet6
    type: sock_dgram
    protocol: 262
    expect: refused
`
	table, ds, err := LoadTestTableBytes("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	rows := table.Rows
	if len(rows) != 9 {
		t.Fatalf("%d rows", len(rows))
	}
	if r := rows[0]; r.Kind != ActionFSLink || r.Path != "out/a" || r.Dest != "out/b" || r.Label() != "fs.link out/a -> out/b" {
		t.Errorf("link row: %+v (%s)", r, r.Label())
	}
	if r := rows[1]; r.Kind != ActionFSAttr || r.Path != "out/a" {
		t.Errorf("attr row: %+v", r)
	}
	if r := rows[2]; r.Kind != ActionNetSocket || r.Socket != (SocketTriple{Family: 2, Type: 1}) ||
		r.Label() != "net.socket AF_INET SOCK_STREAM protocol 0" {
		t.Errorf("socket row: %+v (%s)", r, r.Label())
	}
	if r := rows[3]; r.Socket != (SocketTriple{Family: 2, Type: 2, Protocol: 1}) {
		t.Errorf("numeric socket row: %+v", r)
	}
	if r := rows[4]; r.Socket != (SocketTriple{Family: 30, Type: 5, Pair: true}) || r.Label() != "net.socket socketpair AF_TIPC SOCK_SEQPACKET protocol 0" {
		t.Errorf("socketpair row: %+v (%s)", r, r.Label())
	}
	if r := rows[5]; r.Kind != ActionNetSend || r.Host != "127.0.0.1" || r.Port != 53 || r.Proto != ProtoUDP {
		t.Errorf("send row: %+v", r)
	}
	if r := rows[6]; r.Kind != ActionNetSend || r.Path != "unix:@log" || r.Proto != "" {
		t.Errorf("unix send row: %+v", r)
	}
	if r := rows[7]; r.Kind != ActionExecAnon || r.Rule != ExecAnonRule || r.Label() != "exec.anonymous" {
		t.Errorf("anonymous exec row: %+v (%s)", r, r.Label())
	}
	if r := rows[8]; r.Socket != (SocketTriple{Family: 10, Type: 2, Protocol: 262}) {
		t.Errorf("lower-case names: %+v", r)
	}
	// The action a row builds carries its own fields.
	if a := rows[2].action("/w", ""); a.Kind != ActionNetSocket || a.Socket != rows[2].Socket {
		t.Errorf("socket action: %+v", a)
	}
	if a := rows[0].action("/w", ""); a.Path != "/w/out/a" || a.DestPath != "/w/out/b" {
		t.Errorf("link action: %+v", a)
	}
	if a := rows[5].action("/w", ""); a.Host != "127.0.0.1" || a.Port != 53 || a.Proto != ProtoUDP {
		t.Errorf("send action: %+v", a)
	}
}

// TestLoadTestTableConformanceActionErrors: each new action refuses a row it cannot evaluate, and a key that
// belongs to another action, before any row runs (§7).
func TestLoadTestTableConformanceActionErrors(t *testing.T) {
	for _, tc := range []struct{ name, row, want string }{
		{"link without dest", "{action: fs.link, path: /a, expect: allow}", "fs.link test needs path and dest"},
		{"attr without path", "{action: fs.attr, expect: allow}", "fs.attr test needs a path"},
		{"socket without family", "{action: net.socket, type: SOCK_STREAM, expect: allow}", "net.socket test needs family and type"},
		{"socket without type", "{action: net.socket, family: AF_INET, expect: allow}", "net.socket test needs family and type"},
		{"unknown family", "{action: net.socket, family: AF_NOPE, type: 1, expect: allow}", `family "AF_NOPE"`},
		{"negative type", "{action: net.socket, family: 2, type: -1, expect: allow}", `type "-1"`},
		{"unknown protocol", "{action: net.socket, family: 2, type: 1, protocol: IPPROTO_X, expect: allow}", `protocol "IPPROTO_X"`},
		{"socket with a path", "{action: net.socket, family: 2, type: 1, path: /x, expect: allow}", "net.socket test takes family, type, protocol and socketpair"},
		{"socketpair not a bool", "{action: net.socket, family: 1, type: 1, socketpair: yes, expect: allow}", `socketpair "yes"`},
		{"family on another action", "{action: fs.read, path: /x, family: 2, expect: allow}", "family, type, protocol and socketpair belong to net.socket"},
		{"send over tcp", "{action: net.send, host_port: '127.0.0.1:53', proto: tcp, expect: allow}", "net.send is a datagram"},
		{"send without a target", "{action: net.send, expect: allow}", "net.send test needs host_port or a unix: path"},
		{"anonymous with a path", "{action: exec.anonymous, path: /x, expect: refused}", "exec.anonymous test names no image"},
		{"anonymous with argv", "{action: exec.anonymous, argv: [x], expect: refused}", "exec.anonymous test names no image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table, ds, err := LoadTestTableBytes("t.yaml", []byte("tests:\n  - "+tc.row+"\n"))
			if err == nil || table != nil || !errors.Is(err, ErrInvalidTestTable) {
				t.Fatalf("accepted: %+v %v", table, err)
			}
			found := false
			for _, d := range ds {
				found = found || strings.Contains(d.Message, tc.want)
			}
			if !found {
				t.Errorf("no diagnostic carries %q:\n%s", tc.want, render(ds))
			}
		})
	}
}
