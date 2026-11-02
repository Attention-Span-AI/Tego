// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type sink struct {
	mu  sync.Mutex
	evs []*record.Event
}

func (s *sink) Emit(ev *record.Event) {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
}

func (s *sink) of(kind record.Kind) []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*record.Event
	for _, e := range s.evs {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

var filesCmd = []string{"python3", "/opt/fake-mcp/server.py"}

func filesServer() Server {
	return Server{Name: "files", Command: filesCmd, Rules: mcptool.Rules{Deny: []string{"delete_file"}, Ask: []string{"write_file"}}}
}

// start makes a started service whose admitter admits everything as pid (or refuses with admitErr).
func start(t *testing.T, admitErr error, servers ...Server) (*Service, *sink, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(Options{Servers: servers, Exe: "/usr/bin/tego", Poll: 20 * time.Millisecond,
		admit: func(net.Conn, int, uint64) (admission, error) {
			if admitErr != nil {
				return admission{}, admitErr
			}
			return admission{pid: os.Getpid()}, nil
		},
		stillShim: func(admission) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	sk := &sink{}
	if err := s.Start(context.Background(), source.RunRef{ID: "r-test", Agent: "a", Dir: dir, CgroupID: 1}, sk); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s, sk, dir
}

// shim is a test's in-process stand-in for `tego mcp relay`.
type shim struct {
	t  *testing.T
	c  net.Conn
	fw *FrameWriter
	fr *FrameReader
}

func dial(t *testing.T, s *Service, server string, argv []string) (*shim, Frame) {
	t.Helper()
	c, err := net.Dial("tcp", s.ctl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	sh := &shim{t: t, c: c, fw: NewFrameWriter(c), fr: NewFrameReader(c, 0)}
	if err := sh.fw.Write(Frame{V: ProtocolVersion, Server: server, Argv: argv, PID: os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	return sh, sh.read()
}

func (sh *shim) read() Frame {
	sh.t.Helper()
	_ = sh.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := sh.fr.Read()
	if err != nil {
		sh.t.Fatalf("read frame: %v", err)
	}
	return f
}

func (sh *shim) client(line string) {
	sh.t.Helper()
	if err := sh.fw.Write(Frame{C: []byte(line)}); err != nil {
		sh.t.Fatal(err)
	}
}

func toolCall(id int, tool string) string {
	return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
}

func TestAdmissionRefusals(t *testing.T) {
	t.Run("peer refused", func(t *testing.T) {
		s, _, _ := start(t, ErrPeer, filesServer())
		if _, f := dial(t, s, "files", filesCmd); f.OK || !strings.Contains(f.Error, "not admitted") {
			t.Fatalf("answer %+v", f)
		}
	})
	s, _, _ := start(t, nil, filesServer(), Server{Name: "web", URL: "http://127.0.0.1:1/mcp"})
	for _, c := range []struct {
		name, server string
		argv         []string
		want         string
	}{
		{"undeclared server", "other", filesCmd, "not behind this run's relay"},
		{"wrong argv", "files", []string{"python3", "/tmp/evil.py"}, "not server files's declared command"},
		{"http server", "web", filesCmd, "is an HTTP server"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, f := dial(t, s, c.server, c.argv); f.OK || !strings.Contains(f.Error, c.want) {
				t.Fatalf("answer %+v, want %q", f, c.want)
			}
		})
	}
}

func TestAllowDenyRecorded(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, f := dial(t, s, "files", filesCmd)
	if !f.OK {
		t.Fatalf("hello refused: %+v", f)
	}
	sh.client(toolCall(1, "read_file"))
	if f := sh.read(); string(f.ToServer) != toolCall(1, "read_file") {
		t.Fatalf("allowed call: %+v", f)
	}
	sh.client(toolCall(2, "delete_file"))
	f = sh.read()
	if f.ToServer != nil || !strings.Contains(string(f.ToClient), `"code":-32001`) || !strings.Contains(string(f.ToClient), `"id":2`) {
		t.Fatalf("denied call: to_server %q to_client %q", f.ToServer, f.ToClient)
	}
	// Other messages pass untouched.
	sh.client(`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}`)
	if f := sh.read(); !strings.Contains(string(f.ToServer), "initialize") {
		t.Fatalf("initialize: %+v", f)
	}
	lines := sk.of(record.KindMCP)
	if len(lines) != 2 {
		t.Fatalf("mcp lines %d, want 2", len(lines))
	}
	if l := lines[0]; l.Verdict != record.VerdictAllow || l.Source != record.SourceProxy || l.Rule != "mcp[files]" || l.Authority != record.AuthorityRule {
		t.Errorf("allow line %+v", l)
	}
	if l := lines[1]; l.Verdict != record.VerdictRefused || l.Reason != record.ReasonMCPToolDenied || l.Rule != "mcp[files].tools.deny[delete_file]" {
		t.Errorf("refused line %+v", l)
	}
	var p record.MCPPayload
	if err := lines[1].DecodePayload(&p); err != nil || p.Name != "files" || p.Tool != "delete_file" || p.Transport != "stdio" {
		t.Errorf("payload %+v %v", p, err)
	}
}

func TestAskPaths(t *testing.T) {
	for _, c := range []struct {
		name   string
		fn     AskFunc
		pass   bool
		reason string
	}{
		{"approved", func(context.Context, ask.Request) (ask.Decision, error) { return ask.Decision{Approved: true}, nil }, true, ""},
		{"denied", func(context.Context, ask.Request) (ask.Decision, error) {
			return ask.Decision{Reason: ask.ReasonDenied}, nil
		}, false, "ask-denied"},
		{"timeout", func(context.Context, ask.Request) (ask.Decision, error) {
			return ask.Decision{Reason: ask.ReasonTimeout}, nil
		}, false, "ask-timeout"},
		{"broker error", func(context.Context, ask.Request) (ask.Decision, error) {
			return ask.Decision{}, ask.ErrUnavailable
		}, false, "ask-unavailable"},
		{"no broker", nil, false, "ask-unavailable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, sk, _ := start(t, nil, filesServer())
			var got ask.Request
			if c.fn != nil {
				s.ConfigureMCPAsk(func(ctx context.Context, r ask.Request) (ask.Decision, error) {
					got = r
					return c.fn(ctx, r)
				})
			}
			sh, _ := dial(t, s, "files", filesCmd)
			sh.client(toolCall(7, "write_file"))
			f := sh.read()
			if c.pass != (f.ToServer != nil) {
				t.Fatalf("frame %+v", f)
			}
			if !c.pass && !strings.Contains(string(f.ToClient), c.reason) {
				t.Fatalf("refusal %s, want %s", f.ToClient, c.reason)
			}
			if c.fn != nil && (got.Op != OpMCPTool || got.Target != "files write_file" || got.Hold != "request" || got.Rule != "mcp[files].tools.ask[write_file]" || got.PID != os.Getpid()) {
				t.Errorf("ask request %+v", got)
			}
			l := sk.of(record.KindMCP)
			if len(l) != 1 {
				t.Fatalf("mcp lines %d", len(l))
			}
			if c.pass && (l[0].Verdict != record.VerdictAllow || l[0].Authority != record.AuthorityHuman) {
				t.Errorf("approved line %+v", l[0])
			}
			if !c.pass && (l[0].Verdict != record.VerdictRefused || string(l[0].Reason) != c.reason) {
				t.Errorf("refused line %+v", l[0])
			}
		})
	}
}

func TestOnlyHeldCallWaits(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	release := make(chan struct{})
	s.ConfigureMCPAsk(func(ctx context.Context, _ ask.Request) (ask.Decision, error) {
		<-release
		return ask.Decision{Approved: true}, nil
	})
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(toolCall(1, "write_file"))
	sh.client(toolCall(2, "read_file"))
	if f := sh.read(); !strings.Contains(string(f.ToServer), "read_file") {
		t.Fatalf("the allowed call waited behind the held one: %+v", f)
	}
	close(release)
	if f := sh.read(); !strings.Contains(string(f.ToServer), "write_file") {
		t.Fatalf("held call after approval: %+v", f)
	}
}

func TestOverlayChangeDecidesNextCall(t *testing.T) {
	s, sk, dir := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(toolCall(1, "delete_file"))
	if f := sh.read(); f.ToClient == nil {
		t.Fatal("delete_file passed before the switch")
	}
	if _, err := mcptools.Update(context.Background(), dir, "r-test", func(o *mcptools.Overlay) (bool, error) {
		return o.Set("files", "delete_file", mcptools.Allow, "uid:1 pid:2 cli", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	sh.client(toolCall(2, "delete_file"))
	if f := sh.read(); f.ToServer == nil {
		t.Fatalf("delete_file refused after the allow switch: %s", f.ToClient)
	}
	// Tighten back: read_file denied live.
	if _, err := mcptools.Update(context.Background(), dir, "r-test", func(o *mcptools.Overlay) (bool, error) {
		return o.Set("files", "read_file", mcptools.Deny, "uid:1 pid:2 dashboard", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	sh.client(toolCall(3, "read_file"))
	if f := sh.read(); !strings.Contains(string(f.ToClient), "mcp[files].live[read_file]") {
		t.Fatalf("read_file after the deny switch: %+v", f)
	}
	gaps := sk.of(record.KindGap)
	if len(gaps) != 2 {
		t.Fatalf("gap lines %d, want one per change", len(gaps))
	}
	var p record.GapPayload
	if err := gaps[0].DecodePayload(&p); err != nil || p.Why != record.GapMCPToolChanged || p.MCPTool == nil ||
		p.MCPTool.Tool != "delete_file" || p.MCPTool.Decision != "allow" || p.MCPTool.Serial != 1 {
		t.Fatalf("gap %+v %v", p, err)
	}
}

func TestToolsListFilteredAndSeen(t *testing.T) {
	s, _, dir := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(`{"jsonrpc":"2.0","id":"L1","method":"tools/list"}`)
	if f := sh.read(); f.ToServer == nil {
		t.Fatal("tools/list not passed")
	}
	result := `{"jsonrpc":"2.0","id":"L1","result":{"tools":[{"name":"read_file"},{"name":"write_file"},{"name":"delete_file"}]}}`
	if err := sh.fw.Write(Frame{S: []byte(result)}); err != nil {
		t.Fatal(err)
	}
	f := sh.read()
	if strings.Contains(string(f.ToClient), "delete_file") || !strings.Contains(string(f.ToClient), "write_file") {
		t.Fatalf("filtered list %s", f.ToClient)
	}
	// An unrelated server message passes as it came.
	if err := sh.fw.Write(Frame{S: []byte(result)}); err != nil {
		t.Fatal(err)
	}
	if f := sh.read(); string(f.ToClient) != result {
		t.Fatalf("a result answering no tools/list was changed: %s", f.ToClient)
	}
	seen, err := mcptools.ReadSeen(dir)
	if err != nil || strings.Join(seen["files"], ",") != "delete_file,read_file,write_file" {
		t.Fatalf("seen %v %v", seen, err)
	}
}

func TestBatchWithRefusedCallAnsweredWhole(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(`[` + toolCall(1, "read_file") + `,` + toolCall(2, "delete_file") + `]`)
	f := sh.read()
	if f.ToServer != nil {
		t.Fatal("a batch with a denied call reached the server")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(f.ToClient, &arr); err != nil || len(arr) != 2 {
		t.Fatalf("batch answer %s", f.ToClient)
	}
	if n := len(sk.of(record.KindMCP)); n != 2 {
		t.Fatalf("mcp lines %d", n)
	}
}

// denyDuringHold is an AskFunc on a person who approves a card after another person's Deny of the same tool landed.
func denyDuringHold(t *testing.T, dir, server, tool string) AskFunc {
	return func(ctx context.Context, _ ask.Request) (ask.Decision, error) {
		if _, err := mcptools.Update(ctx, dir, "r-test", func(o *mcptools.Overlay) (bool, error) {
			return o.Set(server, tool, mcptools.Deny, "uid:1 pid:2 cli", time.Now())
		}); err != nil {
			t.Error(err)
		}
		return ask.Decision{Approved: true}, nil
	}
}

// TestDenyDuringHoldIsNotForwarded: an approval answers the question asked, and a Deny put in force during the hold is
// a later rule. The call is refused by it, with no frame to the server (ADR 0126 §4).
func TestDenyDuringHoldIsNotForwarded(t *testing.T) {
	s, sk, dir := start(t, nil, filesServer())
	s.ConfigureMCPAsk(denyDuringHold(t, dir, "files", "write_file"))
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(toolCall(7, "write_file"))
	f := sh.read()
	if f.ToServer != nil || !strings.Contains(string(f.ToClient), "mcp[files].live[write_file]") {
		t.Fatalf("frame %+v", f)
	}
	l := sk.of(record.KindMCP)
	if len(l) != 1 || l[0].Verdict != record.VerdictRefused || string(l[0].Reason) != mcptool.ReasonDenied ||
		l[0].Authority != record.AuthorityRule || l[0].Rule != "mcp[files].live[write_file]" {
		t.Fatalf("mcp lines %+v", l)
	}
}

// TestDenyDuringHoldIsNotForwardedHTTP is the same over HTTP: no request reaches the server.
func TestDenyDuringHoldIsNotForwardedHTTP(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer upstream.Close()
	s, sk, dir := start(t, nil, Server{Name: "web", URL: upstream.URL + "/mcp", Rules: mcptool.Rules{Ask: []string{"write_file"}}})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	s.https[0].holderPID = os.Getpid
	s.ConfigureMCPAsk(denyDuringHold(t, dir, "web", "write_file"))
	resp, err := http.Post(s.httpURLs()["web"], "application/json", strings.NewReader(toolCall(7, "write_file")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "mcp[web].live[write_file]") || hits.Load() != 0 {
		t.Fatalf("answer %s, %d requests upstream", b, hits.Load())
	}
	if l := sk.of(record.KindMCP); len(l) != 1 || l[0].Verdict != record.VerdictRefused || l[0].Rule != "mcp[web].live[write_file]" {
		t.Fatalf("mcp lines %+v", l)
	}
}

// TestHTTPRelayRefusesNotUTF8 is TestClientLineNotUTF8Refused over HTTP: a bad byte is one more reading of the name the
// relay decided, and the raw body must not reach the server. A readable body reaches it in the one wire form.
func TestHTTPRelayRefusesNotUTF8(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, string(b))
		mu.Unlock()
	}))
	defer upstream.Close()
	s, _, _ := start(t, nil, Server{Name: "web", URL: upstream.URL + "/mcp", Rules: mcptool.Rules{Deny: []string{"delete_file"}}})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	post := func(body string) string {
		t.Helper()
		resp, err := http.Post(s.httpURLs()["web"], "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file` + "\xff" + `"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call` + "\xff" + `","params":{"name":"delete_file"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","x":"` + "\xc0\x8d" + `"}`,
	} {
		if answer := post(body); !strings.Contains(answer, `"code":-32700`) {
			t.Fatalf("%q: answer %s", body, answer)
		}
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("%d bodies reached the server: %q", n, seen)
	}
	post(`{ "jsonrpc": "2.0", "id": 3, "method": "ping" }`)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != `{"jsonrpc":"2.0","id":3,"method":"ping"}` {
		t.Fatalf("the server got %q, want the wire form", seen)
	}
}

// TestOverlayTransientReadErrorIsRetried: a read error that says nothing of the file (EMFILE, EIO) is not remembered as
// handled, or a Deny written then is not put in force until the file changes again. A file refused for what it is stays
// unread until it changes. Either way one warning is written for one file, not one a poll.
func TestOverlayTransientReadErrorIsRetried(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		wantReads int
		wantDeny  bool
	}{
		{"EMFILE", unix.EMFILE, 2, true},
		{"untrusted", mcptools.ErrUntrusted, 1, false},
		{"invalid", mcptools.ErrInvalid, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu     sync.Mutex
				failed = true
				reads  int
				logged bytes.Buffer
			)
			dir := t.TempDir()
			s, err := New(Options{Servers: []Server{filesServer()}, Exe: "/usr/bin/tego", Poll: time.Hour,
				Logger: slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &logged}, nil)),
				read: func(d, run string) (*mcptools.Overlay, error) {
					mu.Lock()
					defer mu.Unlock()
					reads++
					if failed {
						return nil, tc.err
					}
					return mcptools.Read(d, run)
				}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := mcptools.Update(context.Background(), dir, "r-test", func(o *mcptools.Overlay) (bool, error) {
				return o.Set("files", "read_file", mcptools.Deny, "uid:1 pid:2 cli", time.Now())
			}); err != nil {
				t.Fatal(err)
			}
			s.run = source.RunRef{ID: "r-test", Agent: "a", Dir: dir, CgroupID: 1}
			if got := s.decide("files", "read_file").Decision; got == mcptool.Deny {
				t.Fatalf("decided %s on a read that failed", got)
			}
			s.decide("files", "read_file")
			mu.Lock()
			gotReads, warnings := reads, strings.Count(logged.String(), "cannot be read")
			failed = false
			mu.Unlock()
			if gotReads != tc.wantReads || warnings != 1 {
				t.Fatalf("%d reads, %d warnings, want %d and 1", gotReads, warnings, tc.wantReads)
			}
			if got := s.decide("files", "read_file").Decision == mcptool.Deny; got != tc.wantDeny {
				t.Fatalf("once the error passed: deny in force %v, want %v", got, tc.wantDeny)
			}
		})
	}
}

// lockedWriter takes the test's own lock for a log's writes, so the buffer can be read under it.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func TestGateRelayedConsumesPendingStart(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	child := exec.Command("sleep", "5")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	if s.Relayed("files", child.Process.Pid) {
		t.Fatal("relayed before any shim was admitted")
	}
	sh, f := dial(t, s, "files", filesCmd)
	if !f.OK {
		t.Fatal(f.Error)
	}
	if s.Relayed("other", child.Process.Pid) {
		t.Fatal("relayed for another server")
	}
	if !s.Relayed("files", child.Process.Pid) {
		t.Fatal("the admitted shim's start was not relayed")
	}
	if s.Relayed("files", child.Process.Pid) {
		t.Fatal("one admitted shim started two servers")
	}
	_ = sh
}

func TestVarsConfigEndpoints(t *testing.T) {
	s, _, _ := start(t, nil, filesServer(), Server{Name: "web", URL: "http://127.0.0.1:9/mcp", Rules: mcptool.Rules{Deny: []string{"x"}}})
	rt := t.TempDir()
	if err := s.UseRuntimeDir(rt); err != nil {
		t.Fatal(err)
	}
	v := s.Vars()
	if v[EnvRelay] != s.ctl.Addr().String() || v[EnvConfig] != filepath.Join(rt, ConfigName) {
		t.Fatalf("vars %v", v)
	}
	b, err := os.ReadFile(v[EnvConfig])
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]clientServer `json:"mcpServers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if f := cfg.MCPServers["files"]; f.Command != "/usr/bin/tego" || strings.Join(f.Args, " ") != "mcp relay --server files -- python3 /opt/fake-mcp/server.py" {
		t.Errorf("files entry %+v", f)
	}
	if w := cfg.MCPServers["web"]; w.Type != "http" || !strings.HasPrefix(w.URL, "http://127.0.0.1:") || !strings.HasSuffix(w.URL, "/mcp") {
		t.Errorf("web entry %+v", w)
	}
	if n := len(s.Endpoints()); n != 2 {
		t.Errorf("endpoints %d, want control + one http relay", n)
	}
	var st unix.Stat_t
	if err := unix.Stat(v[EnvConfig], &st); err != nil || st.Mode&0o777 != 0o444 {
		t.Errorf("config mode %o", st.Mode&0o777)
	}
}

func TestHTTPRelay(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		calls = append(calls, m.Method+" "+m.Params.Name)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if m.Method == "tools/list" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"tools":[{"name":"read_file"},{"name":"delete_file"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"content":[]}}`))
	}))
	defer upstream.Close()
	s, sk, _ := start(t, nil, Server{Name: "web", URL: upstream.URL + "/mcp", Rules: mcptool.Rules{Deny: []string{"delete_file"}}})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	relay := s.httpURLs()["web"]
	post := func(body string) string {
		resp, err := http.Post(relay, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := bufio.NewReader(resp.Body).ReadString(0)
		return b
	}
	if got := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); strings.Contains(got, "delete_file") || !strings.Contains(got, "read_file") {
		t.Fatalf("tools/list through the relay: %s", got)
	}
	if got := post(toolCall(2, "read_file")); !strings.Contains(got, `"result"`) {
		t.Fatalf("allowed call: %s", got)
	}
	if got := post(toolCall(3, "delete_file")); !strings.Contains(got, "-32001") {
		t.Fatalf("denied call: %s", got)
	}
	mu.Lock()
	got := append([]string(nil), calls...)
	mu.Unlock()
	for _, c := range got {
		if strings.Contains(c, "delete_file") {
			t.Fatal("the denied call reached the server")
		}
	}
	if n := len(sk.of(record.KindMCP)); n != 2 {
		t.Fatalf("mcp lines %d", n)
	}
	// A peer the admission refuses is served nothing.
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return ErrPeer }
	// Admission is per connection: a new one is asked again.
	fresh := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := fresh.Post(relay, "application/json", strings.NewReader(toolCall(4, "read_file")))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("refused peer got %d", resp.StatusCode)
	}
}

// TestHTTPRelayRefusesAnUndecidedBody: a POST body is the only one the relay decides, so a request by any other method
// that carries a body is refused and never reaches the server: every method, sized or chunked, is one more way to send
// the tools/call a rule denies. A bodyless GET (the server's event stream) and DELETE (the end of a session) still pass.
func TestHTTPRelayRefusesAnUndecidedBody(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+" "+string(b))
		mu.Unlock()
	}))
	defer upstream.Close()
	s, sk, _ := start(t, nil, Server{Name: "web", URL: upstream.URL + "/mcp", Rules: mcptool.Rules{Deny: []string{"delete_file"}}})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	relay := s.httpURLs()["web"]
	u, err := url.Parse(relay)
	if err != nil {
		t.Fatal(err)
	}
	call := toolCall(1, "delete_file")
	// raw sends the request as written: a chunked body, and the methods http.Client will not send one with.
	raw := func(t *testing.T, head, body string) int {
		t.Helper()
		c, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write([]byte(head + "\r\nHost: " + u.Host + "\r\nConnection: close\r\n" + body)); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	sized := "Content-Length: " + strconv.Itoa(len(call)) + "\r\n\r\n" + call
	chunked := "Transfer-Encoding: chunked\r\n\r\n" + strconv.FormatInt(int64(len(call)), 16) + "\r\n" + call + "\r\n0\r\n\r\n"
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodOptions, http.MethodTrace, "post", "PROPFIND"} {
		for form, body := range map[string]string{"sized": sized, "chunked": chunked} {
			t.Run(method+" "+form, func(t *testing.T) {
				if got := raw(t, method+" /mcp HTTP/1.1", body); got != http.StatusMethodNotAllowed {
					t.Fatalf("status %d, want 405", got)
				}
			})
		}
	}
	mu.Lock()
	reached := append([]string(nil), seen...)
	seen = nil
	mu.Unlock()
	if len(reached) != 0 {
		t.Fatalf("a body the relay never decided reached the server: %q", reached)
	}
	refusals := sk.of(record.KindMCP)
	if len(refusals) == 0 {
		t.Fatal("the refused bodies left no line")
	}
	for _, ev := range refusals {
		if ev.Verdict != record.VerdictRefused || ev.Rule != "mcp[web].relay" || ev.Reason != mcptool.ReasonDenied {
			t.Fatalf("line %s rule %s reason %s", ev.Verdict, ev.Rule, ev.Reason)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method+" with no body passes", func(t *testing.T) {
			req, err := http.NewRequest(method, relay, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 1 || seen[0] != method+" " {
				t.Fatalf("the server saw %q", seen)
			}
			seen = nil
		})
	}
	// The decided path is untouched: a POST is still decided and answered, and its body alone reaches the server.
	resp, err := http.Post(relay, "application/json", strings.NewReader(toolCall(2, "read_file")))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != http.MethodPost+" "+toolCall(2, "read_file") {
		t.Fatalf("the server saw %q", seen)
	}
}

func TestProcAdmitRefusesOutsideRunAndNonShim(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			time.Sleep(time.Second)
			_ = c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// A cgroup id no directory has: the peer is outside the run.
	if _, err := procAdmit(c, os.Getpid(), 1); !errors.Is(err, ErrPeer) {
		t.Fatalf("outside the run: %v", err)
	}
	// The test's own cgroup: inside, same image, but not `tego mcp relay`.
	cg, err := procCgroupPath(os.Getpid())
	if err != nil {
		t.Skip("no unified cgroup:", err)
	}
	mount, err := cgroup2Mount()
	if err != nil {
		t.Skip(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(mount+cg, &st); err != nil {
		t.Skip(err)
	}
	if _, err := procAdmit(c, os.Getpid(), st.Ino); err == nil || !strings.Contains(err.Error(), "mcp relay") {
		t.Fatalf("a non-shim argv was admitted: %v", err)
	}
	// A pid that does not hold the socket.
	if _, err := procAdmit(c, 1, st.Ino); !errors.Is(err, ErrPeer) {
		t.Fatalf("a pid not holding the socket: %v", err)
	}
	if !isShimArgv([]string{"/usr/bin/tego", "mcp", "relay", "--server", "x", "--", "py"}) || isShimArgv([]string{"tego", "run", "--", "mcp", "relay"}) {
		t.Fatal("isShimArgv")
	}
}
