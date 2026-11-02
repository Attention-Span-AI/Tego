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
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// listenProbe tries each way to get a listener and writes what each came to as JSON: "listening" or "ok", or the
// errno's name. A listen with no bind takes its port through the kernel's autobind, which never reaches
// security_socket_bind, so it is the shape Landlock's BIND_TCP cannot see.
const listenProbe = `import errno, json, os, socket, sys

def autobind(family):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.listen(1)
    return "listening" if s.getsockname()[1] else "no port"

def bound():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return "ok"

def unixserver():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("probe.sock")
    s.listen(1)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect("probe.sock")
    conn, _ = s.accept()
    c.send(b"x")
    return "ok" if conn.recv(1) == b"x" else "lost"

res = {}
def attempt(name, f):
    try:
        res[name] = f()
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))

out = sys.argv[1]
os.chdir(os.path.dirname(out))
attempt("autobind4", lambda: autobind(socket.AF_INET))
attempt("autobind6", lambda: autobind(socket.AF_INET6))
attempt("bound", bound)
attempt("unix", unixserver)
json.dump(res, open(out, "w"))
`

// TestIntegrationListenerAdmission is enforce-landlock R6 on the real kernel. Under a net: section with no net.listen
// no TCP listener comes up, autobind included, each attempt a refused line, and a unix server still works, on the
// duplicate. Without a net: section nothing changes. A port-zero declaration admits the autobind it names.
func TestIntegrationListenerAdmission(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		net        string
		autobind   string
		bound      string
		unix       string // a listener policy declares no unix socket here, so it refuses this one's bind
		listenLine int    // refused listen lines
	}{
		{"an allow-list and no listen", "net:\n  allow: [\"1.1.1.1:443\"]\n", "EACCES", "EACCES", "ok", 2},
		{"an empty allow-list and no listen", "net:\n  allow: []\n", "EACCES", "EACCES", "ok", 2},
		{"listen: []", "net:\n  listen: []\n", "EACCES", "EACCES", "EACCES", 2},
		{"no net: section", "", "listening", "ok", "ok", 0},
		{"an ephemeral declaration", "net:\n  listen: [\"tcp://127.0.0.1:0\"]\n", "EACCES", "ok", "EACCES", 2},
		{"an ephemeral wildcard declaration", "net:\n  listen: [\"tcp://0.0.0.0:0\", \"tcp://[::]:0\"]\n", "listening", "ok", "EACCES", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("listenprobe", []string{python}, []string{python, resolved})+tc.net)
			script := filepath.Join(f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(listenProbe), 0o644); err != nil {
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
			if got["autobind4"] != tc.autobind {
				t.Errorf("IPv4 autobind = %q, want %q (all: %v)", got["autobind4"], tc.autobind, got)
			}
			if v6 := got["autobind6"]; v6 != tc.autobind && v6 != "EAFNOSUPPORT" { // a kernel with IPv6 off
				t.Errorf("IPv6 autobind = %q, want %q (all: %v)", v6, tc.autobind, got)
			}
			if got["bound"] != tc.bound {
				t.Errorf("bound listen = %q, want %q (all: %v)", got["bound"], tc.bound, got)
			}
			if got["unix"] != tc.unix {
				t.Errorf("unix server = %q, want %q (all: %v)", got["unix"], tc.unix, got)
			}
			refused := 0
			for _, l := range lines(t, events(t, runDirs(t, f.root)[0]), record.KindNet) {
				if l["op"] == "listen" && l["_verdict"] == string(record.VerdictRefused) {
					refused++
				}
			}
			want := tc.listenLine
			if got["autobind6"] == "EAFNOSUPPORT" && want > 0 {
				want--
			}
			if refused != want {
				t.Errorf("refused listen lines = %d, want %d", refused, want)
			}
		})
	}
}

// TestIntegrationDeclaredServers: a Python and a Node HTTP server on a declared net.listen entry still bind, listen,
// accept and answer, through the supervisor's bind and listen on the held socket.
func TestIntegrationDeclaredServers(t *testing.T) {
	const py = `import http.server, sys, threading, urllib.request
port = int(sys.argv[1])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"served")
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", port), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
body = urllib.request.urlopen("http://127.0.0.1:%d/" % port).read()
open(sys.argv[2], "wb").write(body)
server.shutdown()
`
	const js = `const http = require("http"), fs = require("fs");
const port = Number(process.argv[2]);
const server = http.createServer((req, res) => res.end("served"));
server.listen(port, "127.0.0.1", () => {
  http.get({host: "127.0.0.1", port}, res => {
    let body = "";
    res.on("data", d => body += d);
    res.on("end", () => { fs.writeFileSync(process.argv[3], body); server.close(); process.exit(0); });
  });
});
`
	for _, tc := range []struct{ program, file, source string }{
		{"python3", "server.py", py},
		{"node", "server.js", js},
	} {
		t.Run(tc.program, func(t *testing.T) {
			bin, err := exec.LookPath(tc.program)
			if err != nil {
				t.Skipf("no %s: %v", tc.program, err)
			}
			resolved, err := filepath.EvalSymlinks(bin)
			if err != nil {
				t.Fatal(err)
			}
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := probe.Addr().(*net.TCPAddr).Port
			if err := probe.Close(); err != nil {
				t.Fatal(err)
			}
			section := fmt.Sprintf("net:\n  allow: [\"127.0.0.1:%d\"]\n  listen: [\"tcp://127.0.0.1:%d\"]\n", port, port)
			f := newFixture(t, contractFor("declaredserver", []string{bin}, []string{bin, resolved})+section)
			script := filepath.Join(f.dir, tc.file)
			if err := os.WriteFile(script, []byte(tc.source), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			out := filepath.Join(f.out, "body")
			if _, err := Run(context.Background(), f.rt, []string{bin, script, strconv.Itoa(port), out}, f.deps(t, nil)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			body, err := os.ReadFile(out)
			if err != nil || string(body) != "served" {
				t.Fatalf("the server answered %q (%v), want served", body, err)
			}
		})
	}
}
