// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// socketProbe tries each socket shape and writes what each returned, "ok" or the errno's name, as JSON.
const socketProbe = `import errno, json, socket, sys
res = {}
def attempt(name, f):
    try:
        f().close()
        res[name] = "ok"
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))
attempt("sctp", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132))
attempt("udplite", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 136))
attempt("vsock", lambda: socket.socket(40, socket.SOCK_STREAM, 0))
attempt("tcp", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
attempt("udp6", lambda: socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0))
attempt("unixpair", lambda: socket.socketpair(socket.AF_UNIX)[0])
attempt("netlink", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0))
attempt("netlink_generic", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16))
attempt("netlink_diag", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 4))
# ADR 0018 (7): an upper-layer protocol on an unconnected TCP socket. With the smc module loaded, "smc" turned the
# socket into AF_SMC (43) in place; the family it ends with is recorded either way.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
try:
    s.setsockopt(socket.IPPROTO_TCP, 31, b"smc")
    res["ulp_smc"] = "ok"
except OSError as e:
    res["ulp_smc"] = errno.errorcode.get(e.errno, str(e.errno))
res["ulp_domain"] = str(s.getsockopt(socket.SOL_SOCKET, 39))
s.close()
json.dump(res, open(sys.argv[1], "w"))
`

// TestSocketFamiliesOutsideTheNetRulesAreRefused is ADR 0018 on the real kernel at tier 1. Under a net:
// section an SCTP socket reached any address through setsockopt(SCTP_SOCKOPT_CONNECTX) and a peerless send()
// with no ledger line; now socket(2) refuses it, and UDP-Lite and AF_VSOCK, with the errno a kernel without
// them answers, and each refusal is a ledger line, as are the netlink protocols but NETLINK_ROUTE (ADR 0128). TCP, UDP,
// a unix socketpair and NETLINK_ROUTE still work, and a contract with no net: section refuses none of them. setsockopt(TCP_ULP, "smc"), which with the smc module loaded
// turned an admitted TCP socket into AF_SMC in place (ADR 0018 (7)), is refused with ENOENT and a
// line, and the socket stays AF_INET.
func TestSocketFamiliesOutsideTheNetRulesAreRefused(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		net  string
		want map[string]string
	}{
		{"net: {}", "net: {}\n", map[string]string{"sctp": "EPROTONOSUPPORT", "udplite": "EPROTONOSUPPORT",
			"vsock": "EAFNOSUPPORT", "tcp": "ok", "udp6": "ok", "unixpair": "ok", "netlink": "ok",
			"netlink_generic": "EPROTONOSUPPORT", "netlink_diag": "EPROTONOSUPPORT", "ulp_smc": "ENOENT", "ulp_domain": "2"}},
		{"no net: section", "", map[string]string{"tcp": "ok", "udp6": "ok", "unixpair": "ok", "netlink": "ok",
			"netlink_generic": "ok", "netlink_diag": "ok"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("sockfam", []string{python}, []string{python, resolved})+tc.net)
			script := filepath.Join(f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(socketProbe), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			out := filepath.Join(f.out, "result.json")
			if _, err := Run(context.Background(), f.rt, []string{python, script, out}, f.deps(t, nil)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("the probe wrote nothing: %v", err)
			}
			got := map[string]string{}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %s, want %s (all: %v)", k, got[k], v, got)
				}
			}
			var refused []string
			for _, e := range events(t, runDirs(t, f.root)[0]) {
				if e.Kind != record.KindRefused {
					continue
				}
				var p record.RefusedPayload
				if err := e.DecodePayload(&p); err == nil && (p.Op == "socket" || p.Op == "socketpair" || p.Op == "setsockopt") {
					refused = append(refused, p.Target)
				}
			}
			joined := strings.Join(refused, "; ")
			if tc.net == "" {
				if len(refused) != 0 {
					t.Errorf("a contract with no net: section refused sockets: %s", joined)
				}
				return
			}
			for _, want := range []string{"AF_INET SOCK_STREAM protocol 132", "AF_INET SOCK_DGRAM protocol 136", "AF_VSOCK SOCK_STREAM protocol 0",
				"AF_NETLINK SOCK_RAW protocol 16", "AF_NETLINK SOCK_DGRAM protocol 4", `TCP_ULP "smc"`} {
				if !strings.Contains(joined, want) {
					t.Errorf("no refused line for %s; refused: %s", want, joined)
				}
			}
		})
	}
}
