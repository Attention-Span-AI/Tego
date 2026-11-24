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
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
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
	// procs is how the relay reads the run's processes to name a request's holder; nil is the real /proc. Tests replace it.
	procs procView
	// sockInfo is the exact socket lookup; nil is peer.TCPSocketInfo. Tests replace it.
	sockInfo func(remote, local netip.AddrPort) (peer.SocketInfo, error)
}

// connVerdict is one connection's admission, made once, and what was learned of the connection with it: the socket's
// cgroup and inode from the one exact lookup, and the process found to hold it (holder), kept for the connection's
// later requests so a keep-alive connection pays for the walk once.
type connVerdict struct {
	once sync.Once
	err  error
	// info is the admission's lookup of the client socket; haveInfo says it answered.
	info     peer.SocketInfo
	haveInfo bool

	mu     sync.Mutex
	holder heldBy
	// unplaced is when a search last found no holder; the connection's next calls within holderRetry are not searched for
	// again (a holder that cannot be told is the same for the calls that follow).
	unplaced time.Time
}

// holderRetry is how long a connection whose holder could not be named goes without another search.
const holderRetry = 2 * time.Second

type connVerdictKey struct{}

func newHTTPRelay(s *Service, sv Server) (*httpRelay, error) {
	if sv.BusinessRules {
		return nil, ErrBusinessUnavailable
	}
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
		info, err := socketInRun(h.lookup, remote, local, cg)
		if err == nil && v != nil {
			v.info, v.haveInfo = info, true
		}
		return err
	}
	if v == nil {
		return check()
	}
	v.once.Do(func() { v.err = check() })
	return v.err
}

// lookup is the exact lookup of a client socket: the cgroup it was made in and its inode, from one sock_diag request.
func (h *httpRelay) lookup(remote, local netip.AddrPort) (peer.SocketInfo, error) {
	if h.sockInfo != nil {
		return h.sockInfo(remote, local)
	}
	return peer.TCPSocketInfo(remote, local)
}

// socketInRun is the HTTP relay's admission: the client socket's cgroup id (sock_diag) is the run's cgroup or one
// of its descendants. It returns what the lookup said of the socket, for the holder's search.
func socketInRun(lookup func(remote, local netip.AddrPort) (peer.SocketInfo, error), remote, local netip.AddrPort, runCgroup uint64) (peer.SocketInfo, error) {
	if runCgroup == 0 {
		return peer.SocketInfo{}, fmt.Errorf("%w: the run has no cgroup id", ErrPeer)
	}
	info, err := lookup(remote, local)
	if err != nil {
		return peer.SocketInfo{}, fmt.Errorf("%w: %w", ErrPeer, err)
	}
	if info.CgroupID == runCgroup {
		return info, nil
	}
	if !cgroupBelow(runCgroup, info.CgroupID) {
		return peer.SocketInfo{}, fmt.Errorf("%w: the client's socket is not the run's", ErrPeer)
	}
	return info, nil
}

// cgroupBelow reports whether the cgroup whose id is id is a descendant of the one whose id is run: a walk of the run's own
// subtree, which is small, for a directory with that inode. A yes is kept (a cgroup's id is fixed for the boot, and a
// descendant stays one), so a connection of the run's pays for the walk once; a no is not, since a run makes cgroups
// as it goes, and an outsider's walk is bounded by the run's subtree, not the machine's.
func cgroupBelow(run, id uint64) bool {
	k := [2]uint64{run, id}
	cgDirMu.Lock()
	known := cgBelow[k]
	cgDirMu.Unlock()
	if known {
		return true
	}
	dir, err := runCgroupDir(run)
	if err != nil {
		return false
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
	if found {
		cgDirMu.Lock()
		cgBelow[k] = true
		cgDirMu.Unlock()
	}
	return found
}

var (
	cgDirMu sync.Mutex
	cgDirs  = map[uint64]string{}
	cgBelow = map[[2]uint64]bool{}
)

// runCgroupDir is the cgroup2 directory whose inode is id, found once by a walk of the hierarchy and kept while that
// directory still has the id (a removed one is looked for again).
func runCgroupDir(id uint64) (string, error) {
	cgDirMu.Lock()
	defer cgDirMu.Unlock()
	if d, ok := cgDirs[id]; ok {
		var st unix.Stat_t
		if unix.Stat(d, &st) == nil && st.Ino == id {
			return d, nil
		}
		delete(cgDirs, id)
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
	if h.sv.BusinessRules {
		http.Error(w, ErrBusinessUnavailable.Error(), http.StatusForbidden)
		return
	}
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
	var (
		body    []byte
		lists   bool
		answers []json.RawMessage // the refusals a batch's refused members are answered with
	)
	if r.Method == http.MethodPost {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody+1))
		if err != nil || len(b) > maxHTTPBody {
			if len(b) > maxHTTPBody {
				h.recordUnreadable(ctx)
			}
			http.Error(w, "Tego's MCP relay reads request bodies up to 4 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		// The body is read and sent in its wire form, as a stdio line is: json.Valid and the decoder both pass a bad
		// byte, so a raw body is one name decided here and another to a reader that drops the byte.
		wire, ok := wireForm(b)
		var (
			calls []call
			batch bool
			st    = readUnreadable
		)
		if ok {
			calls, batch, st = readBatch(wire)
		}
		switch st {
		case readTooMany:
			h.recordUnreadable(ctx)
			writeJSON(w, tooManyAnswer)
			return
		case readUnreadable:
			h.recordUnreadable(ctx)
			writeJSON(w, unreadableAnswer)
			return
		case readOK:
		}
		d := h.decide(ctx, calls, batch, wire)
		if d.body == nil {
			// Nothing goes to the server: every member was refused (a single message's answer, or a batch's, which has
			// none for a member with no id: all of those, and the batch has no answer at all).
			switch {
			case len(d.answers) == 0:
				w.WriteHeader(http.StatusAccepted)
			case batch:
				writeJSON(w, joinJSON(d.answers))
			default:
				writeJSON(w, d.answers[0])
			}
			return
		}
		body, lists, answers = d.body, d.lists, d.answers
	}
	h.forward(ctx, w, r, body, lists, answers)
}

// recordUnreadable is the line of a POST body the relay refused unread: it may have held a call, and none of it passed.
func (h *httpRelay) recordUnreadable(ctx context.Context) {
	h.s.emitCall(h.holder(ctx), h.sv.Name, TransportHTTP, "", "mcp["+h.sv.Name+"].relay", record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
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

// httpDecision is what the relay does with a POST body.
type httpDecision struct {
	// body goes to the server: the body as it came (one message), or the members that passed as a batch; nil when
	// nothing does.
	body []byte
	// lists is whether a tools/list request passes: its answer is read, whatever its id is spelt or says, and filtered.
	lists bool
	// answers are the errors of the refused members that have an id, in the order of the members.
	answers []json.RawMessage
}

// decide decides a POST body's messages, each on its own (ADR 0126 §4, amended 2026-11-21).
func (h *httpRelay) decide(ctx context.Context, calls []call, batch bool, wire []byte) httpDecision {
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
	lists := false
	if !batch {
		cl := calls[0]
		if cl.method == "tools/list" {
			lists = true
		}
		if !cl.isCall {
			return httpDecision{body: wire, lists: lists}
		}
		if cl.tool == "" {
			h.s.emitCall(pid, server, TransportHTTP, "", relayRule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
			return httpDecision{answers: []json.RawMessage{mcptool.Refusal(cl.id, server, "", relayRule, mcptool.ReasonDenied)}}
		}
		res := h.s.decide(server, cl.tool)
		switch res.Decision {
		case mcptool.Allow:
			h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityRule, "")
			return httpDecision{body: wire, lists: lists}
		case mcptool.Ask:
			ok, reason := false, "ask-unavailable"
			if pid > 0 {
				ok, reason = h.s.askPerson(ctx, server, cl.tool, res.Rule, pid)
			}
			if ok {
				// As on stdio (holdAsk): a Deny put in force during the hold outranks the approval.
				if now := h.s.decide(server, cl.tool); now.Decision == mcptool.Deny {
					h.s.emitCall(pid, server, TransportHTTP, cl.tool, now.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
					return httpDecision{answers: []json.RawMessage{mcptool.Refusal(cl.id, server, cl.tool, now.Rule, mcptool.ReasonDenied)}}
				}
				h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityHuman, "")
				return httpDecision{body: wire, lists: lists}
			}
			h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityRule, reason)
			return httpDecision{answers: []json.RawMessage{mcptool.Refusal(cl.id, server, cl.tool, res.Rule, reason)}}
		default:
			h.s.emitCall(pid, server, TransportHTTP, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
			return httpDecision{answers: []json.RawMessage{mcptool.Refusal(cl.id, server, cl.tool, res.Rule, mcptool.ReasonDenied)}}
		}
	}
	// A batch: every member on its own. The members the rules ask about are asked together, each as its own card, since
	// the one answer waits for all of them anyway.
	items := h.s.planBatch(server, calls)
	type verdict struct {
		ok     bool
		reason string
	}
	asked := make([]verdict, len(items))
	var wg sync.WaitGroup
	for i, it := range items {
		if it.kind != itemAsk {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			asked[i] = verdict{false, "ask-unavailable"}
			if pid > 0 {
				ok, reason := h.s.askPerson(ctx, server, it.cl.tool, it.res.Rule, pid)
				asked[i] = verdict{ok, reason}
			}
		}()
	}
	wg.Wait()
	var d httpDecision
	var pass []json.RawMessage
	refuse := func(it batchItem, authority record.Authority) {
		h.s.emitCall(pid, server, TransportHTTP, it.cl.tool, it.rule, record.VerdictRefused, authority, it.reason)
		if len(it.cl.id) > 0 {
			d.answers = append(d.answers, it.answer(server))
		}
	}
	for i, it := range items {
		cl := it.cl
		if it.kind == itemAsk {
			v := asked[i]
			switch {
			case !v.ok:
				it.kind, it.rule, it.reason = itemRefuse, it.res.Rule, v.reason
			default:
				if now := h.s.decide(server, cl.tool); now.Decision == mcptool.Deny {
					it.kind, it.rule, it.reason = itemRefuse, now.Rule, mcptool.ReasonDenied
					break
				}
				h.s.emitCall(pid, server, TransportHTTP, cl.tool, it.res.Rule, record.VerdictAllow, record.AuthorityHuman, "")
				it.kind = itemPass
				pass = append(pass, cl.raw)
				continue
			}
			refuse(it, record.AuthorityRule)
			continue
		}
		if it.kind == itemRefuse {
			refuse(it, record.AuthorityRule)
			continue
		}
		if cl.isCall {
			h.s.emitCall(pid, server, TransportHTTP, cl.tool, it.res.Rule, record.VerdictAllow, record.AuthorityRule, "")
		}
		if cl.method == "tools/list" {
			lists = true
		}
		pass = append(pass, cl.raw)
	}
	if len(pass) > 0 {
		d.body, d.lists = joinJSON(pass), lists
	}
	return d
}

func writeJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// hopHeaders are not forwarded (RFC 9110 §7.6.1).
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// mediaType is a Content-Type's media type, lower case; "" for none that parses.
func mediaType(ct string) string {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return mt
}

// forward sends the request to the declared URL and streams the answer back, filtering every tools/list result in it.
// body is the decided POST body, nil for a request that carries none: nothing else of the agent's reaches the server as a body.
// lists says the body held a tools/list. answers are the errors of a batch's refused members, which the one HTTP answer
// carries with the server's: the JSON array of the answer takes them as members, an event stream takes them as its first
// event, and an answer with no body (202, for a batch of notifications) is replaced by them.
//
// The relay reads what it filters, so the server is asked for the answer in the form the relay reads (Accept-Encoding:
// identity, whatever the client accepts) and an answer in another form (Content-Encoding) that it would have to read is not
// passed on. A tools/list whose answer the relay cannot read as JSON or as an event stream is not passed on unfiltered, and
// an answer it cannot add the errors to is not passed on without them: either is a 502 and a line of the record. An event
// stream is read by whole events whatever opened it (a GET that resumes one replays answers), and each answer in it that has
// a tools array is filtered, whatever its id is.
func (h *httpRelay) forward(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, lists bool, answers []json.RawMessage) {
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
	// Set, not left to the client: the transport decodes only what it asked for itself, so a client's gzip would reach the
	// filter as bytes.
	out.Header.Set("Accept-Encoding", "identity")
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
	// An answer that is not a success (a 401, a 500) is the server's own failure of the whole POST, which nothing the batch
	// held took part in: it passes as it came.
	ok2xx := resp.StatusCode < 300
	if !ok2xx {
		answers = nil
	}
	mt := mediaType(resp.Header.Get("Content-Type"))
	stream := mt == "text/event-stream" && ok2xx
	reads := lists || len(answers) > 0
	encoded := resp.ContentLength != 0 && !identityEncoding(resp.Header.Get("Content-Encoding"))
	switch {
	case (reads || stream) && ok2xx && encoded:
		h.refuseAnswer(ctx, w, "the server's answer is encoded ("+resp.Header.Get("Content-Encoding")+"), so it could not be read and was not passed on")
	case reads && (mt == "application/json" || strings.HasSuffix(mt, "+json")):
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResult+1))
		if err != nil || len(b) > maxHTTPResult {
			if err == nil {
				// The answer is dropped and the client gets a 502: the record says which server and what the limit was.
				h.s.emitOversize(record.GapMCPResponseOversize, h.sv.Name, 0, maxHTTPResult)
			}
			http.Error(w, "relay: tools/list answer too large", http.StatusBadGateway)
			return
		}
		if lists {
			var ok bool
			if b, ok = h.filterBody(b); !ok {
				h.refuseAnswer(ctx, w, "the server's answer to a tools/list could not be read as JSON-RPC, so it was not passed on")
				return
			}
		}
		if len(answers) > 0 {
			var ok bool
			if b, ok = addAnswers(b, answers); !ok {
				h.refuseAnswer(ctx, w, "the server's answer could not be read as JSON-RPC, so the errors of this batch's refused messages could not be added to it")
				return
			}
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(b)
	case stream:
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		fl, _ := w.(http.Flusher)
		if len(answers) > 0 {
			_, _ = w.Write(append(append([]byte("data: "), joinJSON(answers)...), '\n', '\n'))
			if fl != nil {
				fl.Flush()
			}
		}
		h.filterEvents(ctx, w, fl, resp.Body, lists)
	case len(answers) > 0 && resp.ContentLength == 0:
		// Nothing to carry them in, as a batch of notifications is answered: the errors are the answer.
		for _, k := range []string{"Content-Length", "Content-Type", "Content-Encoding"} {
			w.Header().Del(k)
		}
		writeJSON(w, joinJSON(answers))
	case reads && ok2xx && resp.ContentLength != 0:
		h.refuseAnswer(ctx, w, "the server's answer is neither JSON nor an event stream, so it could not be read and was not passed on")
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

// identityEncoding reports whether a Content-Encoding header says the body is as it was written.
func identityEncoding(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || strings.EqualFold(v, "identity")
}

// filterEvents copies an event stream to w event by event, as a client reads it (events end at a blank line, lines at LF, CR
// or CRLF, the data lines of one event are one message joined by LF), and filters the message of each event as a message:
// an answer with a tools array loses the tools the rules deny. A message that is not complete JSON passes as it came, except
// when a tools/list was asked (strict): then it is dropped and recorded, since it may have been the list. An event past the
// size bound is left out and recorded, as a line past it always was. Fields other than data (event, id, retry, comments) pass.
func (h *httpRelay) filterEvents(ctx context.Context, w http.ResponseWriter, fl http.Flusher, body io.Reader, strict bool) {
	type event struct {
		other, data [][]byte
		size        int
		dropped     bool
	}
	var ev event
	write := func(b ...[]byte) bool {
		for _, x := range b {
			if _, err := w.Write(x); err != nil {
				return false
			}
		}
		return true
	}
	flush := func() bool {
		e := ev
		ev = event{}
		if e.dropped || len(e.other)+len(e.data) == 0 {
			return true
		}
		for _, l := range e.other {
			if !write(l, []byte("\n")) {
				return false
			}
		}
		if len(e.data) > 0 {
			vals := make([][]byte, len(e.data))
			for i, l := range e.data {
				v := bytes.TrimPrefix(l, []byte("data:"))
				vals[i] = bytes.TrimPrefix(v, []byte(" "))
			}
			msg := bytes.Join(vals, []byte("\n"))
			switch {
			case !json.Valid(bytes.TrimSpace(msg)) && strict:
				h.recordUnreadable(ctx)
				return true
			case !json.Valid(bytes.TrimSpace(msg)):
				for _, l := range e.data {
					if !write(l, []byte("\n")) {
						return false
					}
				}
			default:
				if out := h.s.filterResponse(h.sv.Name, bytes.TrimSpace(msg)); !bytes.Equal(out, bytes.TrimSpace(msg)) {
					if !write([]byte("data: "), out, []byte("\n")) {
						return false
					}
				} else {
					for _, l := range e.data {
						if !write(l, []byte("\n")) {
							return false
						}
					}
				}
			}
		}
		if !write([]byte("\n")) {
			return false
		}
		if fl != nil {
			fl.Flush()
		}
		return true
	}
	br := bufio.NewReaderSize(body, 64<<10)
	for {
		line, size, err := ReadLineSize(br, maxHTTPResult)
		if err != nil {
			if err == io.EOF || len(line) > 0 {
				flush()
			}
			return
		}
		if size > 0 {
			// The message is left out of the stream: the record says which server, how big and what the limit was.
			h.s.emitOversize(record.GapMCPStreamOversize, h.sv.Name, size, maxHTTPResult)
			ev.dropped = true
			continue
		}
		// A line ends at LF (and ReadLineSize has taken a CR before it); a client also ends one at a CR alone.
		for _, part := range bytes.Split(line, []byte("\r")) {
			if len(part) == 0 {
				if !flush() {
					return
				}
				continue
			}
			if ev.size += len(part); ev.size > maxHTTPResult {
				if !ev.dropped {
					h.s.emitOversize(record.GapMCPStreamOversize, h.sv.Name, int64(ev.size), maxHTTPResult)
				}
				ev.dropped = true
				continue
			}
			if bytes.HasPrefix(part, []byte("data:")) {
				ev.data = append(ev.data, append([]byte(nil), part...))
			} else {
				ev.other = append(ev.other, append([]byte(nil), part...))
			}
		}
	}
}

// refuseAnswer is a server answer the relay would not pass on (forward): a 502 with why, and a line of the record.
func (h *httpRelay) refuseAnswer(ctx context.Context, w http.ResponseWriter, why string) {
	h.recordUnreadable(ctx)
	for _, k := range []string{"Content-Length", "Content-Type", "Content-Encoding"} {
		w.Header().Del(k)
	}
	http.Error(w, "Tego's MCP relay: "+why, http.StatusBadGateway)
}

// addAnswers is a server's JSON answer with the errors of a batch's refused members added: a batch's own array takes them
// as more members, one message becomes an array of it and them, no answer is an array of them. ok is false for an answer
// that is neither.
func addAnswers(b []byte, answers []json.RawMessage) ([]byte, bool) {
	t := bytes.TrimSpace(b)
	switch {
	case len(t) == 0:
		return joinJSON(answers), true
	case t[0] == '[':
		var arr []json.RawMessage
		if json.Unmarshal(t, &arr) != nil {
			return nil, false
		}
		return joinJSON(append(arr, answers...)), true
	case t[0] == '{' && json.Valid(t):
		return joinJSON(append([]json.RawMessage{t}, answers...)), true
	}
	return nil, false
}

// holderKey carries the request's connection ends to holder.
type holderKey struct{}

type connEnds struct{ remote, local netip.AddrPort }

// holder is the pid of the run's process holding the request's connection, 0 when it cannot be named: the broker asks a
// person only for a call it can place in the run by a process. A connection keeps its holder for its later requests, so
// a client that sends a call a request pays for one search (holderSearch), not one a call.
func (h *httpRelay) holder(ctx context.Context) int {
	if h.holderPID != nil {
		return h.holderPID()
	}
	ends, _ := ctx.Value(holderKey{}).(connEnds)
	if !ends.remote.IsValid() {
		return 0
	}
	v, _ := ctx.Value(connVerdictKey{}).(*connVerdict)
	if v == nil {
		v = &connVerdict{}
	}
	procs := h.procs
	if procs == nil {
		procs = realProcs{}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.holder.pid != 0 && v.holder.stillHolds(procs) {
		return v.holder.pid
	}
	v.holder = heldBy{}
	if !v.unplaced.IsZero() && time.Since(v.unplaced) < holderRetry {
		return 0
	}
	h.s.mu.Lock()
	cg := h.s.run.CgroupID
	h.s.mu.Unlock()
	info := v.info
	if !v.haveInfo {
		var err error
		if info, err = h.lookup(ends.remote, ends.local); err != nil || info.Inode == 0 {
			// No exact lookup (a kernel without TCP sock_diag): the kernel's table says whose socket it is.
			ino, terr := peerSocketInode(ends.remote, ends.local)
			if terr != nil {
				return 0
			}
			info = peer.SocketInfo{Inode: ino}
		}
		v.info, v.haveInfo = info, true
	}
	v.holder = holderSearch(procs, info, cg)
	v.unplaced = time.Time{}
	if v.holder.pid == 0 {
		v.unplaced = time.Now()
	}
	return v.holder.pid
}

// filterBody filters a JSON response body: one message or a batch. ok is false for a body that is not JSON-RPC JSON, which a
// caller that asked for a tools/list does not pass on.
func (h *httpRelay) filterBody(b []byte) ([]byte, bool) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || (t[0] != '{' && t[0] != '[') || !json.Valid(t) {
		return b, false
	}
	return h.s.filterResponse(h.sv.Name, t), true
}
