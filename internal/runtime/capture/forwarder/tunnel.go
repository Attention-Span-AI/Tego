// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var errTunnelLimit = errors.New("forwarder: tunnel byte ceiling reached")

type proxyTunnel struct {
	client, upstream io.Closer
	cancel           context.CancelFunc
	once             sync.Once
}

func (t *proxyTunnel) close() {
	t.closeWith(false)
}

func (t *proxyTunnel) closeWith(graceful bool) {
	t.once.Do(func() {
		t.cancel()
		if client, ok := t.client.(interface{ GracefulClose() error }); graceful && ok {
			_ = client.GracefulClose()
		} else {
			_ = t.client.Close()
		}
		_ = t.upstream.Close()
	})
}

type streamCloser struct {
	body       io.ReadCloser
	controller *http.ResponseController
}

func (s streamCloser) Close() error {
	_ = s.controller.SetWriteDeadline(time.Now())
	return s.body.Close()
}
func (s streamCloser) GracefulClose() error { return s.body.Close() }

func websocketRoundTripper(base http.RoundTripper) http.RoundTripper {
	if transport, ok := base.(*http.Transport); ok {
		clone := transport.Clone()
		clone.Protocols = new(http.Protocols)
		clone.Protocols.SetHTTP1(true)
		clone.ForceAttemptHTTP2 = false
		clone.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		return clone
	}
	return base
}

func headerToken(h http.Header, key, want string) bool {
	for _, value := range h.Values(key) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func hasUpgrade(r *http.Request) bool {
	return len(r.Header.Values("Upgrade")) > 0 || headerToken(r.Header, "Connection", "upgrade")
}

func (l *Listener) protocolDecision(r *http.Request, pid int, op, rule string, allowed bool) {
	port := l.model.Port
	if port == 0 {
		port = 443
	}
	authority := httppolicy.Authority(l.model.Host, port)
	ev := l.event(record.KindNet, l.opts.Clock.Now(), l.opts.Clock.Mono())
	ev.PID, ev.TID, ev.Rule, ev.Authority = pid, pid, rule, record.AuthorityRule
	ev.Verdict = record.VerdictAllow
	if !allowed {
		ev.Verdict, ev.Reason = record.VerdictRefused, record.ReasonNetHTTP
	}
	path := r.URL.EscapedPath()
	if op == "connect_tunnel" {
		path = ""
	}
	_ = ev.SetPayload(record.NetPayload{Op: op, Proto: "tcp", Dst: authority, Host: l.model.Host, HTTPAuthority: authority, Method: r.Method, Path: path, Mechanism: "forwarder"})
	if !allowed || l.runRef().Contract == nil || l.runRef().Contract.Record != agent.RecordOff {
		l.emit(ev)
	}
}

// Each listener has exactly one upstream authority. Neither Host nor a CONNECT
// request target can select a different model or an arbitrary destination.
func (l *Listener) serveExtraProtocol(w http.ResponseWriter, r *http.Request, pid int) bool {
	connect := r.Method == http.MethodConnect
	if !connect && !hasUpgrade(r) {
		return false
	}
	if l.opts.Proxy == nil {
		// No net.proxy grant, so no tunnel: what follows answers as before net.proxy existed. Under
		// net.http, httpDecision refuses CONNECT and Upgrade (SEMANTICS §5); a capture-only listener
		// refuses CONNECT and declines an upgrade offer, h2c's included, by stripping Upgrade and
		// Connection and forwarding the request as HTTP/1.1 (capture-derive.md R20, amended 2026-10-05).
		return false
	}
	if contract := l.runRef().Contract; contract != nil {
		if err := l.opts.Proxy.ValidateLimits(contract.Limits); err != nil {
			op := "websocket"
			if connect {
				op = "connect_tunnel"
			}
			l.protocolDecision(r, pid, op, "net.proxy.unmetered_budget", false)
			closeHTTPUpload(w, r)
			l.reject(w, http.StatusForbidden, "protocol cannot enforce the model budget")
			return true
		}
	}
	port := l.model.Port
	if port == 0 {
		port = 443
	}
	authority := httppolicy.Authority(l.model.Host, port)
	op, rule, allowed := "websocket", "unmatched", false
	if connect {
		op = "connect_tunnel"
		host, rawPort, err := net.SplitHostPort(r.RequestURI)
		n, numberErr := strconv.Atoi(rawPort)
		if err == nil && numberErr == nil && rawPort == strconv.Itoa(n) && n > 0 && n <= 65535 && r.URL.RawQuery == "" && r.URL.Fragment == "" && httppolicy.Authority(agent.CanonicalHost(host), n) == authority {
			rule, allowed = l.opts.Proxy.Connect(authority)
		}
		allowed = allowed && !hasUpgrade(r) && len(r.Header.Values("Expect")) == 0 && len(r.TransferEncoding) == 0
		allowed = allowed && (r.ProtoMajor == 1 && r.ProtoMinor == 1 && r.ContentLength == 0 || r.ProtoMajor == 2 && l.opts.Proxy.HTTP2Enabled() && len(r.Header.Values("Content-Length")) == 0)
	} else {
		_, pathErr := httppolicy.CanonicalPath(r.URL.EscapedPath())
		rule, allowed = l.opts.Proxy.WebSocket(authority, r.URL.EscapedPath())
		allowed = allowed && pathErr == nil && r.URL.Fragment == "" && validWebSocketRequest(r)
		if allowed && l.opts.HTTPPolicy != nil {
			baseRule, baseAllowed, _ := l.opts.HTTPPolicy.Match(authority, r.Method, r.URL.EscapedPath())
			if !baseAllowed {
				rule, allowed = baseRule, false
			}
		}
	}
	if !allowed {
		l.protocolDecision(r, pid, op, rule, false)
		closeHTTPUpload(w, r)
		http.Error(w, "protocol refused by policy", http.StatusForbidden)
		return true
	}
	select {
	case l.opts.tunnelSem <- struct{}{}:
		defer func() { <-l.opts.tunnelSem }()
	default:
		l.protocolDecision(r, pid, op, "proxy-capacity", false)
		closeHTTPUpload(w, r)
		http.Error(w, "protocol concurrency ceiling reached", http.StatusTooManyRequests)
		return true
	}
	l.protocolDecision(r, pid, op, rule, true)
	if connect {
		l.connectTunnel(w, r, pid)
	} else {
		l.webSocketTunnel(w, r, pid)
	}
	return true
}

func validWebSocketRequest(r *http.Request) bool {
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.Method != http.MethodGet || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Expect")) != 0 || !headerToken(r.Header, "Connection", "upgrade") {
		return false
	}
	if values := r.Header.Values("Upgrade"); len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), "websocket") {
		return false
	}
	if values := r.Header.Values("Sec-WebSocket-Version"); len(values) != 1 || values[0] != "13" {
		return false
	}
	if values := r.Header.Values("Sec-WebSocket-Key"); len(values) != 1 {
		return false
	} else if decoded, err := base64.StdEncoding.Strict().DecodeString(values[0]); err != nil || len(decoded) != 16 {
		return false
	}
	count := 0
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, token := range strings.Split(value, ",") {
			count++
			if count > 32 || !validProtocolToken(strings.TrimSpace(token)) {
				return false
			}
		}
	}
	// Extensions need their own frame semantics and are not negotiated here.
	return len(r.Header.Values("Sec-WebSocket-Extensions")) == 0
}

func (l *Listener) ownTunnel(client, upstream io.Closer, cancel context.CancelFunc) (*proxyTunnel, error) {
	tunnel := &proxyTunnel{client: client, upstream: upstream, cancel: cancel}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		tunnel.close()
		return nil, ErrStopped
	}
	l.tunnels[tunnel] = struct{}{}
	l.mu.Unlock()
	return tunnel, nil
}

func (l *Listener) releaseTunnel(t *proxyTunnel) {
	t.close()
	l.mu.Lock()
	delete(l.tunnels, t)
	l.mu.Unlock()
}

func (l *Listener) hijackTunnel(w http.ResponseWriter, upstream io.Closer, cancel context.CancelFunc) (net.Conn, *bufio.ReadWriter, *proxyTunnel, error) {
	// Hold the same lock Close uses across hijack and registration. http.Server
	// no longer owns the client after hijack, so a late registration could leak it.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, nil, nil, ErrStopped
	}
	client, buffer, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, nil, nil, err
	}
	t := &proxyTunnel{client: client, upstream: upstream, cancel: cancel}
	l.tunnels[t] = struct{}{}
	return client, buffer, t, nil
}

func (l *Listener) connectTunnel(w http.ResponseWriter, r *http.Request, pid int) {
	bounds := l.opts.Proxy.Bounds()
	parent := r.Context()
	if r.ProtoMajor == 1 {
		// A TCP write-half close cancels net/http's request context even after
		// hijacking. The tunnel still owes the upstream's final response.
		parent = l.tunnelCtx
	}
	ctx, cancel := context.WithTimeout(parent, bounds.TunnelWall)
	defer cancel()
	upstream, err := l.tunnelDial(ctx, "tcp", l.upstream.Host)
	if err != nil {
		closeHTTPUpload(w, r)
		http.Error(w, "upstream tunnel unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	if r.ProtoMajor == 2 {
		controller := http.NewResponseController(w)
		client := streamCloser{body: r.Body, controller: controller}
		tunnel, err := l.ownTunnel(client, upstream, cancel)
		if err != nil {
			return
		}
		defer l.releaseTunnel(tunnel)
		w.Header().Del("Content-Length")
		w.Header().Del("Transfer-Encoding")
		w.WriteHeader(http.StatusOK)
		if err := controller.Flush(); err != nil {
			return
		}
		writer := &flushWriter{writer: w, controller: controller}
		if rule := runDuplex(ctx, tunnel, r.Body, upstream, upstream, writer, bounds, false, l.activity); rule != "" {
			l.protocolDecision(r, pid, "connect_tunnel", rule, false)
		}
		return
	}
	client, buffer, tunnel, err := l.hijackTunnel(w, upstream, cancel)
	if err != nil {
		http.Error(w, "tunnel unavailable", http.StatusServiceUnavailable)
		return
	}
	defer l.releaseTunnel(tunnel)
	_ = client.SetWriteDeadline(time.Now().Add(l.opts.WriteStallTimeout))
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffer.Flush(); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	if rule := runDuplex(ctx, tunnel, buffer.Reader, upstream, upstream, client, bounds, false, l.activity); rule != "" {
		l.protocolDecision(r, pid, "connect_tunnel", rule, false)
	}
}

type flushWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
}

func (w *flushWriter) Write(b []byte) (int, error) {
	n, err := w.writer.Write(b)
	if err == nil {
		err = w.controller.Flush()
	}
	return n, err
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func validWebSocketResponse(r *http.Request, response *http.Response) bool {
	if response.StatusCode != http.StatusSwitchingProtocols || !headerToken(response.Header, "Connection", "upgrade") || len(response.Header.Values("Upgrade")) != 1 || !strings.EqualFold(strings.TrimSpace(response.Header.Get("Upgrade")), "websocket") || len(response.Header.Values("Sec-WebSocket-Accept")) != 1 || response.Header.Get("Sec-WebSocket-Accept") != websocketAccept(r.Header.Get("Sec-WebSocket-Key")) || len(response.Header.Values("Sec-WebSocket-Extensions")) != 0 {
		return false
	}
	selected := response.Header.Values("Sec-WebSocket-Protocol")
	if len(selected) == 0 {
		return true
	}
	if len(selected) != 1 || !validProtocolToken(selected[0]) {
		return false
	}
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, offered := range strings.Split(value, ",") {
			if strings.TrimSpace(offered) == selected[0] {
				return true
			}
		}
	}
	return false
}

func validProtocolToken(token string) bool {
	if len(token) == 0 || len(token) > 128 {
		return false
	}
	for _, c := range token {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}

func (l *Listener) webSocketTunnel(w http.ResponseWriter, r *http.Request, pid int) {
	bounds := l.opts.Proxy.Bounds()
	ctx, cancel := context.WithTimeout(l.tunnelCtx, bounds.TunnelWall)
	defer cancel()
	out := r.Clone(ctx)
	u := *r.URL
	u.Scheme, u.Host = l.upstream.Scheme, l.upstream.Host
	out.URL, out.Host, out.RequestURI = &u, l.hostHeader(), ""
	out.Header = make(http.Header)
	copyHeader(out.Header, r.Header)
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", "websocket")
	// Connection may name these fields as hop headers. Restore the validated
	// handshake fields explicitly so the upstream sees the handshake we checked.
	out.Header.Set("Sec-WebSocket-Key", r.Header.Get("Sec-WebSocket-Key"))
	out.Header.Set("Sec-WebSocket-Version", "13")
	if protocols := r.Header.Values("Sec-WebSocket-Protocol"); len(protocols) > 0 {
		out.Header.Del("Sec-WebSocket-Protocol")
		for _, protocol := range protocols {
			out.Header.Add("Sec-WebSocket-Protocol", protocol)
		}
	}
	out.Body = nil
	response, err := l.websocketTransport.RoundTrip(out)
	if err != nil {
		closeHTTPUpload(w, r)
		http.Error(w, "WebSocket upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	upstream, ok := response.Body.(io.ReadWriteCloser)
	if !ok || !validWebSocketResponse(r, response) {
		closeHTTPUpload(w, r)
		http.Error(w, "invalid WebSocket upstream handshake", http.StatusBadGateway)
		return
	}
	client, buffer, tunnel, err := l.hijackTunnel(w, upstream, cancel)
	if err != nil {
		http.Error(w, "WebSocket unavailable", http.StatusServiceUnavailable)
		return
	}
	defer l.releaseTunnel(tunnel)
	headers := make(http.Header)
	copyHeader(headers, response.Header)
	headers.Del("Content-Length")
	headers.Del("Transfer-Encoding")
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")
	headers.Set("Sec-WebSocket-Accept", response.Header.Get("Sec-WebSocket-Accept"))
	if selected := response.Header.Get("Sec-WebSocket-Protocol"); selected != "" {
		headers.Set("Sec-WebSocket-Protocol", selected)
	}
	_ = client.SetWriteDeadline(time.Now().Add(l.opts.WriteStallTimeout))
	if _, err := buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return
	}
	if err := headers.Write(buffer); err != nil {
		return
	}
	if _, err := buffer.WriteString("\r\n"); err != nil {
		return
	}
	if err := buffer.Flush(); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	if rule := runDuplex(ctx, tunnel, buffer.Reader, upstream, upstream, client, bounds, true, l.activity); rule != "" {
		l.protocolDecision(r, pid, "websocket", rule, false)
	}
}

type tunnelBudget struct {
	used     atomic.Int64
	max      int64
	activity chan struct{}
	// meter reports the bytes either pump carries to the run's stall check (limits R4); nil reports nothing.
	meter *activityMeter
}

func (b *tunnelBudget) reserve(n int64) bool {
	for {
		old := b.used.Load()
		if n < 0 || n > b.max-old {
			return false
		}
		if b.used.CompareAndSwap(old, old+n) {
			return true
		}
	}
}
func (b *tunnelBudget) touch() {
	b.meter.chunk()
	select {
	case b.activity <- struct{}{}:
	default:
	}
}

func tunnelCopy(dst io.Writer, src io.Reader, budget *tunnelBudget) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			if !budget.reserve(int64(n)) {
				return errTunnelLimit
			}
			written, writeErr := dst.Write(buffer[:n])
			if written > 0 {
				budget.touch()
			}
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
}

func runDuplex(ctx context.Context, tunnel *proxyTunnel, clientRead io.Reader, upstreamWrite io.Writer, upstreamRead io.Reader, clientWrite io.Writer, bounds agent.ProxyBounds, websocket bool, meter *activityMeter) string {
	budget := &tunnelBudget{max: bounds.MaxTunnelBytes, activity: make(chan struct{}, 1), meter: meter}
	type pumpResult struct {
		err        error
		fromClient bool
	}
	results := make(chan pumpResult, 2)
	pump := func(dst io.Writer, src io.Reader, masked bool) {
		var err error
		if websocket {
			err = websocketFrames(dst, src, masked, bounds.MaxFrameBytes, budget)
		} else {
			err = tunnelCopy(dst, src, budget)
		}
		if errors.Is(err, io.EOF) {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = half.CloseWrite()
			}
		}
		results <- pumpResult{err, masked}
	}
	go pump(upstreamWrite, clientRead, true)
	go pump(clientWrite, upstreamRead, false)
	idle := time.NewTimer(bounds.TunnelIdle)
	defer idle.Stop()
	completed := 0
	refusal := ""
	contextDone, idleDone, activity := ctx.Done(), idle.C, budget.activity
	closeAndJoin := func(graceful bool) {
		tunnel.closeWith(graceful)
		contextDone, idleDone, activity = nil, nil, nil
	}
	for completed < 2 {
		select {
		case result := <-results:
			completed++
			if refusal == "" {
				if errors.Is(result.err, errTunnelLimit) {
					refusal = "net.proxy.byte_ceiling"
				} else if errors.Is(result.err, errWebSocketFrame) {
					refusal = "net.proxy.websocket_framing"
				}
			}
			if websocket {
				if !result.fromClient || !errors.Is(result.err, errWebSocketClosed) {
					closeAndJoin(!result.fromClient && errors.Is(result.err, errWebSocketClosed))
				}
			} else if !result.fromClient || result.err != nil && !errors.Is(result.err, io.EOF) {
				closeAndJoin(!result.fromClient && errors.Is(result.err, io.EOF))
			}
		case <-activity:
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(bounds.TunnelIdle)
		case <-idleDone:
			refusal = "net.proxy.tunnel_idle"
			closeAndJoin(false)
		case <-contextDone:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				refusal = "net.proxy.tunnel_wall"
			}
			closeAndJoin(false)
		}
	}
	return refusal
}
