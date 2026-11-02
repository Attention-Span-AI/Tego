// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
)

// gateSpellingProbe dials the servers at ports p and q in the spellings of this host and sends a datagram to the group
// on p, and writes what each came to as JSON. r is a port no rule names.
const gateSpellingProbe = `import errno, json, socket, sys
p, q, r, lan, out = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]

def err(e):
    return errno.errorcode.get(e.errno, str(e.errno))

def dial(family, addr):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(addr)
        return "connected"
    except OSError as e:
        return err(e)
    finally:
        s.close()

def group(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(b"g", addr)
        return "sent"
    except OSError as e:
        return err(e)
    finally:
        s.close()

A, B = socket.AF_INET, socket.AF_INET6
res = {
    "p named": dial(A, ("127.0.0.1", p)),
    "p mapped": dial(B, ("::ffff:127.0.0.1", p)),
    "p other loopback": dial(A, ("127.0.0.2", p)),
    "p mapped other loopback": dial(B, ("::ffff:127.0.0.2", p)),
    "p v6 loopback": dial(B, ("::1", p)),
    "p unspecified": dial(A, ("0.0.0.0", p)),
    "p group": group(("224.0.0.1", p)),
    "q named": dial(B, ("::1", q)),
    "q v4 loopback": dial(A, ("127.0.0.1", q)),
    "r no rule": dial(A, ("127.0.0.1", r)),
}
if lan:
    res["p lan"] = dial(A, (lan, p))
json.dump(res, open(out, "w"))
`

// TestIntegrationGateNetToEverySpelling is a `net to` rule on a loopback literal on the real kernel, with TCP servers
// on all interfaces outside the run. Under each contract shape, the one with no net: section, where the gate is the only
// refusal, and two whose net.allow admits the spellings by CIDR, every spelling of this host on the rule's port is
// refused and the server takes nothing, and a port no rule names connects.
func TestIntegrationGateNetToEverySpelling(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	lan := ""
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			lan = n.IP.String()
			break
		}
	}
	for _, tc := range []struct{ name, section string }{
		{"no net section", ""},
		{"every address by CIDR", "net:\n  allow: [\"0.0.0.0/0:%[1]d\", \"[::/0]:%[1]d\", \"0.0.0.0/0:%[2]d\", \"[::/0]:%[2]d\", \"0.0.0.0/0:%[3]d\"]\n"},
		{"loopback by CIDR", "net:\n  allow: [\"127.0.0.0/8:%[1]d\", \"[::1/128]:%[1]d\", \"127.0.0.0/8:%[2]d\", \"[::1/128]:%[2]d\", \"127.0.0.1:%[3]d\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serve := func(accepted *atomic.Int64) int {
				l, err := net.Listen("tcp", ":0") // every interface, both families
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = l.Close() })
				go func() {
					for {
						c, err := l.Accept()
						if err != nil {
							return
						}
						accepted.Add(1)
						_ = c.Close()
					}
				}()
				return l.Addr().(*net.TCPAddr).Port
			}
			var ruled, open atomic.Int64
			p, q, r := serve(&ruled), serve(&ruled), serve(&open)
			section := tc.section
			if section != "" {
				section = fmt.Sprintf(section, p, q, r)
			}
			gate := fmt.Sprintf("gate:\n  rules:\n    - \"net to 127.0.0.1:%d\": 100\n    - \"net to [::1]:%d\": 100\n  thresholds: {allow: 50, ask: 80}\n", p, q)
			f := newFixture(t, contractFor("gatespelling", []string{python}, []string{python, resolved})+section+gate)
			script := filepath.Join(f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(gateSpellingProbe), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			out := filepath.Join(f.out, "result.json")
			argv := []string{python, script, strconv.Itoa(p), strconv.Itoa(q), strconv.Itoa(r), lan, out}
			if _, err := Run(context.Background(), f.rt, argv, f.deps(t, nil)); err != nil {
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
			for name, v := range got {
				want := "EACCES"
				if name == "r no rule" {
					want = "connected"
				}
				if v != want {
					t.Errorf("%s = %s, want %s", name, v, want)
				}
			}
			if n := ruled.Load(); n != 0 {
				t.Errorf("the servers the rules name took %d connections (%v)", n, got)
			}
			if n := open.Load(); n != 1 {
				t.Errorf("the server no rule names took %d connections, want 1", n)
			}
		})
	}
}
