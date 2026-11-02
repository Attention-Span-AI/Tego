// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// maxHTTPBody bounds a client POST body the relay reads to decide (ADR 0126 §4: 4 MiB).
const maxHTTPBody = 4 << 20

// maxHTTPResult bounds a tools/list response the relay reads to filter.
const maxHTTPResult = 8 << 20

// httpRelay is one relayed url server's listener: the agent's only route to that server (compile derives no
// net.allow entry for its URL once it has tools:).
type httpRelay struct {
	s      *Service
	sv     Server
	target *url.URL
	ln     net.Listener
	srv    *http.Server
	client *http.Client
	// admitConn places a connection's peer in the run; nil is the socket's cgroup check. Tests replace it.
	admitConn func(remote, local netip.AddrPort, runCgroup uint64) error
	// holderPID names a request's process; nil is holder's cgroup walk. Tests replace it.
	holderPID func() int
}

// connVerdict is one connection's admission, made once.
type connVerdict struct {
	once sync.Once
	err  error
}

type connVerdictKey struct{}

func newHTTPRelay(s *Service, sv Server) (*httpRelay, error) {
	u, err := url.Parse(sv.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("mcprelay: server %s: url %q is not http(s)", sv.Name, sv.URL)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("mcprelay: http relay listener for %s: %w", sv.Name, err)
	}
	h := &httpRelay{s: s, sv: sv, target: u, ln: ln}
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConns: 16, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 0}
	h.client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	h.srv = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, connVerdictKey{}, &connVerdict{})
		}}
	return h, nil
}

// URL is the relay URL the agent's client is given: the declared URL's path on this listener.
func (h *httpRelay) URL() string {
	p := h.target.EscapedPath()
	if p == "" {
		p = "/"
	}
	return "http://" + h.ln.Addr().String() + p
}

func (h *httpRelay) start() {
	h.s.wg.Add(1)
	go func() {
		defer h.s.wg.Done()
		_ = h.srv.Serve(h.ln)
	}()
}

func (h *httpRelay) close() {
	if h.srv != nil {
		_ = h.srv.Close()
	}
	_ = h.ln.Close()
}

// httpURLs are the relay URLs of the url servers, by name.
func (s *Service) httpURLs() map[string]string {
	out := map[string]string{}
	for _, h := range s.https {
		out[h.sv.Name] = h.URL()
	}
	return out
}

// admit refuses a connection that is not the run's: the socket's cgroup (the kernel's record of where the client
// made it) must be the run's cgroup or below it.
func (h *httpRelay) admit(r *http.Request) error {
	v, _ := r.Context().Value(connVerdictKey{}).(*connVerdict)
	check := func() error {
		remote, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPeer, err)
		}
		la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if la == nil {
			return fmt.Errorf("%w: no local address", ErrPeer)
		}
		local, err := netip.ParseAddrPort(la.String())
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPeer, err)
		}
		h.s.mu.Lock()
		cg := h.s.run.CgroupID
		h.s.mu.Unlock()
		if h.admitConn != nil {
			return h.admitConn(remote, local, cg)
		}
		return socketInRun(remote, local, cg)
	}
	if v == nil {
		return check()
	}
	v.once.Do(func() { v.err = check() })
	return v.err
}

// socketInRun is the HTTP relay's admission: the client socket's cgroup id (sock_diag) is the run's cgroup or one
// of its descendants.
func socketInRun(remote, local netip.AddrPort, runCgroup uint64) error {
	if runCgroup == 0 {
		return fmt.Errorf("%w: the run has no cgroup id", ErrPeer)
	}
	id, err := peer.TCPSocketCgroup(remote, local)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeer, err)
	}
	if id == runCgroup {
		return nil
	}
	dir, err := runCgroupDir(runCgroup)
	if err != nil {
		return err
	}
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || found {
			return nil
		}
		var st unix.Stat_t
		if unix.Stat(p, &st) == nil && st.Ino == id {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if !found {
		return fmt.Errorf("%w: the client's socket is not the run's", ErrPeer)
	}
	return nil
}

var (
	cgDirMu sync.Mutex
	cgDirs  = map[uint64]string{}
)

// runCgroupDir is the cgroup2 directory whose inode is id, found once by a walk of the hierarchy.
func runCgroupDir(id uint64) (string, error) {
	cgDirMu.Lock()
	defer cgDirMu.Unlock()
	if d, ok := cgDirs[id]; ok {
		return d, nil
	}
	mount, err := cgroup2Mount()
	if err != nil {
		return "", err
	}
	var found string
	_ = filepath.WalkDir(mount, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || found != "" {
			return nil
		}
		var st unix.Stat_t
		if unix.Stat(p, &st) == nil && st.Ino == id {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if found == "" {
		return "", fmt.Errorf("%w: no cgroup directory has id %d", ErrPeer, id)
	}
	cgDirs[id] = found
	return found, nil
}

// ServeHTTP relays one request.
func (h *httpRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.admit(r); err != nil {
		h.s.opts.Logger.Warn("mcp relay: refused an http peer outside the run", "server", h.sv.Name, "err", err)
		w.Header().Set("Connection", "close")
		http.Error(w, "this relay serves only the run it was bound for", http.StatusForbidden)
		return
	}
	ctx := withConnEnds(r)
	// Only a POST body is read and decided, so any other method's body is refused here: passed on, it was a way to send
	// a tools/call around every rule. ContentLength is -1 for a chunked body and 0 only for none.
	if r.Method != http.MethodPost && r.ContentLength != 0 {
		h.s.emitCall(h.holder(ctx), h.sv.Name, TransportHTTP, "", "mcp["+h.sv.Name+"].relay", record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Tego's MCP relay decides POST bodies only, so this request was not passed to the server", http.StatusMethodNotAllowed)
		return
	}
	var body []byte
	lists := map[string]bool{}
	if r.Method == http.MethodPost {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody+1))
		if err != nil || len(b) > maxHTTPBody {
			http.Error(w, "Tego's MCP relay reads request bodies up to 4 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		// The body is read and sent in its wire form, as a stdio line is: json.Valid and the decoder both pass a bad
		// byte, so a raw body is one name decided here and another to a reader that drops the byte.
		wire, ok := wireForm(b)
		var (
			calls []call
			batch bool
		)
		if ok {
			calls, batch, ok = readCalls(wire)
		}
		if !ok {
			writeJSON(w, []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Tego's MCP relay could not read this message, so it was not passed to the server"}}`))
			return
		}
		for _, cl := range calls {
			if cl.method == "tools/list" && len(cl.id) > 0 {
				lists[string(cl.id)] = true
			}
		}
		if answer, pass := h.decide(ctx, calls, batch); !pass {
			writeJSON(w, answer)
			return
		}
		body = wire
	}
	h.forward(w, r, body, lists)
}

// withConnEnds is the request's context carrying its connection's ends, for holder; a request whose ends cannot be
// read keeps the plain context, and holder then names no process.
func withConnEnds(r *http.Request) context.Context {
	ctx := r.Context()
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ctx
	}
	la, _ := ctx.Value(http.LocalAddrContextKey).(net.Addr)
	if la == nil {
		return ctx
	}
	local, err := netip.ParseAddrPort(la.String())
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, holderKey{}, connEnds{netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()), netip.AddrPortFrom(local.Addr().Unmap(), local.Port())})
}

// decide decides a POST body's calls. pass is true when the body goes to the server; otherwise answer is the
// JSON-RPC response the client gets.
func (h *httpRelay) decide(ctx context.Context, calls []call, batch bool) (answer []byte, pass bool) {
	server := h.sv.Name
	relayRule := "mcp[" + server + "].relay"
	// Every tools/call line names the run's process holding the connection, as a stdio line names its shim: one
	// lookup a body, made only when the body holds a call (0 when the socket cannot be placed in the run).
	pid := 0
	for _, cl := range calls {
		if cl.isCall {
			pid = h.holder(ctx)
			break
		}
	}
	if !batch {
		cl := calls[0]
		if !cl.isCall {
			return nil, true
		}
		if cl.tool == "" {
			h.s.emitCall(pid, server, TransportHTTP, "", relayRule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
			return mcptool.Refusal(cl.id, server, "", relayRule, mcptool.ReasonDenied), false
		}
		res := h.s.decide(server, cl.tool)
		switch res.Decision {
		case mcptool.Allow:
			h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityRule, "")
			return nil, true
		case mcptool.Ask:
			ok, reason := false, "ask-unavailable"
			if pid > 0 {
				ok, reason = h.s.askPerson(ctx, server, cl.tool, res.Rule, pid)
			}
			if ok {
				// As on stdio (decideCall): a Deny put in force during the hold outranks the approval.
				if now := h.s.decide(server, cl.tool); now.Decision == mcptool.Deny {
					h.s.emitCall(pid, server, TransportHTTP, cl.tool, now.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
					return mcptool.Refusal(cl.id, server, cl.tool, now.Rule, mcptool.ReasonDenied), false
				}
				h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityHuman, "")
				return nil, true
			}
			h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityRule, reason)
			return mcptool.Refusal(cl.id, server, cl.tool, res.Rule, reason), false
		default:
			h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
			return mcptool.Refusal(cl.id, server, cl.tool, res.Rule, mcptool.ReasonDenied), false
		}
	}
	type decided struct {
		cl  call
		res mcptool.Result
	}
	ds := make([]decided, len(calls))
	refuse := false
	for i, cl := range calls {
		ds[i].cl = cl
		if !cl.isCall {
			continue
		}
		ds[i].res = mcptool.Result{Decision: mcptool.Deny, Rule: relayRule}
		if cl.tool != "" {
			ds[i].res = h.s.decide(server, cl.tool)
		}
		if ds[i].res.Decision != mcptool.Allow {
			refuse = true
		}
	}
	if !refuse {
		for _, d := range ds {
			if d.cl.isCall {
				h.s.emitCall(pid, server, TransportHTTP, d.cl.tool, d.res.Rule, record.VerdictAllow, record.AuthorityRule, "")
			}
		}
		return nil, true
	}
	var out []json.RawMessage
	for _, d := range ds {
		rule, reason := relayRule, mcptool.ReasonDenied
		if d.cl.isCall {
			rule = d.res.Rule
			if d.res.Decision == mcptool.Ask {
				reason = "ask-unavailable"
			}
			h.s.emitCall(pid, server, TransportHTTP, d.cl.tool, rule, record.VerdictRefused, record.AuthorityRule, reason)
		}
		if len(d.cl.id) > 0 {
			out = append(out, mcptool.Refusal(d.cl.id, server, d.cl.tool, rule, reason))
		}
	}
	b, _ := json.Marshal(out)
	return b, false
}

func writeJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// hopHeaders are not forwarded (RFC 9110 §7.6.1).
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// forward sends the request to the declared URL and streams the answer back, filtering a tools/list result. body is
// the decided POST body, nil for a request that carries none: nothing else of the agent's reaches the server as a body.
func (h *httpRelay) forward(w http.ResponseWriter, r *http.Request, body []byte, lists map[string]bool) {
	u := *h.target
	u.RawQuery = r.URL.RawQuery
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), rd)
	if err != nil {
		http.Error(w, "relay: "+err.Error(), http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		out.Header[k] = append([]string(nil), vs...)
	}
	for _, k := range hopHeaders {
		out.Header.Del(k)
	}
	out.Host = h.target.Host
	resp, err := h.client.Do(out)
	if err != nil {
		http.Error(w, "Tego's MCP relay could not reach server "+h.sv.Name+": "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range resp.Header {
		w.Header()[k] = append([]string(nil), vs...)
	}
	for _, k := range hopHeaders {
		w.Header().Del(k)
	}
	isList := func(id json.RawMessage) bool { return lists[string(id)] }
	ct := resp.Header.Get("Content-Type")
	switch {
	case len(lists) > 0 && strings.HasPrefix(ct, "application/json"):
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResult+1))
		if err != nil || len(b) > maxHTTPResult {
			http.Error(w, "relay: tools/list answer too large", http.StatusBadGateway)
			return
		}
		b = h.filterBody(b, isList)
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(b)
	case len(lists) > 0 && strings.HasPrefix(ct, "text/event-stream"):
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		fl, _ := w.(http.Flusher)
		br := bufio.NewReaderSize(resp.Body, 64<<10)
		for {
			line, oversize, err := ReadLine(br, maxHTTPResult)
			if err != nil {
				return
			}
			if oversize {
				continue
			}
			if data, ok := bytes.CutPrefix(line, []byte("data:")); ok {
				line = append([]byte("data: "), h.s.filterResponse(h.sv.Name, bytes.TrimSpace(data), isList)...)
			}
			if _, err := w.Write(append(line, '\n')); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	default:
		w.WriteHeader(resp.StatusCode)
		fl, _ := w.(http.Flusher)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if fl != nil {
					fl.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	}
}

// holderKey carries the request's connection ends to holder.
type holderKey struct{}

type connEnds struct{ remote, local netip.AddrPort }

// holder is the pid of the run's process holding the request's connection, 0 when it cannot be named: the broker
// asks a person only for a call it can place in the run by a process.
func (h *httpRelay) holder(ctx context.Context) int {
	if h.holderPID != nil {
		return h.holderPID()
	}
	ends, _ := ctx.Value(holderKey{}).(connEnds)
	if !ends.remote.IsValid() {
		return 0
	}
	inode, err := peerSocketInode(ends.remote, ends.local)
	if err != nil {
		return 0
	}
	h.s.mu.Lock()
	cg := h.s.run.CgroupID
	h.s.mu.Unlock()
	dir, err := runCgroupDir(cg)
	if err != nil {
		return 0
	}
	pid := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || pid != 0 {
			return nil
		}
		b, rerr := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		if rerr != nil {
			return nil
		}
		for _, f := range strings.Fields(string(b)) {
			if n, cerr := strconv.Atoi(f); cerr == nil && holdsSocket(n, inode) {
				pid = n
				return filepath.SkipAll
			}
		}
		return nil
	})
	return pid
}

// filterBody filters a JSON response body: one message or a batch.
func (h *httpRelay) filterBody(b []byte, isList func(json.RawMessage) bool) []byte {
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return b
	}
	if t[0] == '{' {
		return h.s.filterResponse(h.sv.Name, t, isList)
	}
	var arr []json.RawMessage
	if json.Unmarshal(t, &arr) != nil {
		return b
	}
	for i := range arr {
		arr[i] = h.s.filterResponse(h.sv.Name, arr[i], isList)
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return b
	}
	return out
}
