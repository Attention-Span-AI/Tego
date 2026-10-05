// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// httpDecision runs after authentic peer admission and before any body read or
// upstream operation. net/http owns wire framing; it rejects invalid duplicate
// hosts/lengths and serializes normalized framing on the independent upstream leg.
func (l *Listener) httpDecision(w http.ResponseWriter, r *http.Request, pid int) bool {
	path := r.URL.EscapedPath()
	_, pathErr := httppolicy.CanonicalPath(path)
	upgrade := len(r.Header.Values("Upgrade")) != 0
	for _, v := range r.Header.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			upgrade = upgrade || strings.EqualFold(strings.TrimSpace(token), "upgrade")
		}
	}
	validProtocol := r.ProtoMajor == 1 && r.ProtoMinor == 1 || r.ProtoMajor == 2 && r.ProtoMinor == 0 && l.opts.Proxy.HTTP2Enabled()
	if !validProtocol || r.URL.Fragment != "" || pathErr != nil || !httppolicy.ValidMethod(r.Method) || r.Method == http.MethodConnect || r.Method == "PRI" || upgrade {
		closeHTTPUpload(w, r)
		l.reject(w, http.StatusBadRequest, "unsupported HTTP request")
		return false
	}
	// This authenticated local HEAD health route does not access the upstream.
	// Reject uploads rather than draining attacker-selected bodies outside policy.
	if r.Method == http.MethodHead && (path == HelloPath || path == HelloPath+"/") && r.URL.RawQuery == "" && !r.URL.ForceQuery {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			closeHTTPUpload(w, r)
			l.reject(w, http.StatusBadRequest, "health check has a body")
			return false
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		return false
	}
	port := l.model.Port
	if port == 0 {
		port = 443
	}
	authority := httppolicy.Authority(l.model.Host, port)
	rule, allow := "models["+authority+"]", true
	if l.opts.HTTPPolicy != nil {
		rule, allow, _ = l.opts.HTTPPolicy.Match(authority, r.Method, path)
	}
	// A decision is an HTTP action, never a claim that a socket connected or a
	// vendor processed/charged the request. Query/header values are never retained.
	ev := l.event(record.KindNet, l.opts.Clock.Now(), l.opts.Clock.Mono())
	ev.PID, ev.Rule, ev.Authority = pid, rule, record.AuthorityRule
	ev.Verdict = record.VerdictAllow
	if !allow {
		ev.Verdict, ev.Reason = record.VerdictRefused, record.ReasonNetHTTP
	}
	_ = ev.SetPayload(record.NetPayload{Op: "http_request", Proto: "http", Dst: authority, Host: l.model.Host, HTTPAuthority: authority, Method: r.Method, Path: path})
	if !allow || l.runRef().Contract == nil || l.runRef().Contract.Record != agent.RecordOff {
		l.emit(ev)
	}
	if !allow {
		closeHTTPUpload(w, r)
		http.Error(w, "HTTP request refused by policy", http.StatusForbidden)
	}
	return allow
}

// closeHTTPUpload stops the current upload without waiting for unread bytes.
// HTTP/1 closes the connection: its body cleanup may otherwise drain a small or
// chunked upload. HTTP/2's read deadline belongs to this stream, and the server
// resets an unread stream after its final response. Connection: close would
// instead send GOAWAY and prevent later allowed streams on the same connection.
// The response's independent write deadline remains intact in both protocols.
func closeHTTPUpload(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 {
		w.Header().Set("Connection", "close")
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
}

// closeHTTPConnection is reserved for a refused connection identity or listener
// shutdown. Those affect every stream, and an outsider must release its bounded
// connection slot rather than keep it busy with more refused HTTP/2 requests.
func closeHTTPConnection(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
}

// readyListener proves the policy source actually accepts before child release.
// The manager's private connection supplies the first accept without HTTP data.
type readyListener struct {
	net.Listener
	l    *Listener
	once sync.Once
}

func (r *readyListener) Accept() (net.Conn, error) {
	c, err := r.Listener.Accept()
	r.once.Do(func() {
		if err == nil {
			r.l.serving.Store(true)
		}
		r.l.acceptReady <- err
	})
	return c, err
}
