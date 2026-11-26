// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net/http"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// LimitGate says whether the run's budget has been crossed and the run is being ended: closed is true from the moment
// the limit line is written until the run is gone, and rule and reason name the budget (rule "limits.repeats", reason
// limit-repeats). The runtime builds it from the budget watcher (limits.Watcher.Closed), whose answer is one atomic
// load, so asking costs a request nothing it would notice. A listener with no gate admits every request, as before.
//
// This package never imports limits (TestCaptureLinksNoEngine); the gate is the whole of what it learns about a budget.
type LimitGate func() (rule string, reason record.Reason, closed bool)

// refuseAtLimit is the admission check: a request arriving once the run's budget is crossed is not forwarded. It is
// answered here with 403 and a plain-text line, recorded as a refused net line under the budget's rule and reason, and
// never reaches the upstream, so nothing more is spent in the instant between the limit line and the run's end (the kill
// is a write to the cgroup and lands after it).
//
// It stands at the top of ServeHTTP, after peer admission, so an HTTP request, a CONNECT and a WebSocket upgrade are all
// turned away by the one check; the health check HEAD /api/hello is turned away too, since the run is ending.
//
// 403 is the status every other refusal of this listener uses (policy, a denied ask, a credential), and a client does
// not retry it: the Anthropic and OpenAI SDKs retry only 408, 409, 429 and 5xx, and X-Should-Retry: false tells those that
// obey the header not to try again. A 429 or a 503 would be retried by exactly the clients this must stop.
//
// The gate is asked twice: here, at the top of ServeHTTP, and once more in forward() at the one place every hold (an ask, a
// route, a credential, the body) ends and the request is about to go upstream, so a request held when the budget was crossed is
// refused when it is released, not sent. A request already past that point, and one whose upstream connection is being made,
// is in flight and finishes.
//
// A request admitted before the gate closed is not touched: it is in flight, bounded by the client's own concurrency,
// and finishes and is recorded as any other. So is one the pipeline had not yet counted when the budget was crossed, and a
// request whose limit is not one this gate sees (a run with capture off, or a model host reached directly where the
// contract allows it, goes through no forwarder).
func (l *Listener) refuseAtLimit(w http.ResponseWriter, r *http.Request, pid int) bool {
	gate := l.opts.LimitGate
	if gate == nil {
		return false
	}
	rule, reason, closed := gate()
	if !closed {
		return false
	}
	closeHTTPUpload(w, r)
	port := l.model.Port
	if port == 0 {
		port = 443
	}
	authority := httppolicy.Authority(l.model.Host, port)
	ev := l.event(record.KindNet, l.opts.Clock.Now(), l.opts.Clock.Mono())
	ev.PID, ev.TID, ev.Rule, ev.Authority = pid, pid, rule, record.AuthorityRule
	ev.Verdict, ev.Reason = record.VerdictRefused, reason
	_ = ev.SetPayload(record.NetPayload{Op: "http_request", Proto: "http", Dst: authority, Host: l.model.Host,
		HTTPAuthority: authority, Method: r.Method, Path: clampPath(r.URL.EscapedPath())})
	l.emit(ev)
	w.Header().Set("X-Should-Retry", "false")
	http.Error(w, "Tego refused this request: the run reached its limit ("+rule+") and is being ended; nothing more is sent to the model", http.StatusForbidden)
	return true
}

// clampPath is the path a refusal line records: what policy lines record is checked first (httppolicy.CanonicalPath refuses
// a path over MaxPathBytes before any line is written), and this line is written for a request nothing has validated, so a
// path longer than that is cut to it, not past an escape that would be left half written.
func clampPath(p string) string {
	if len(p) <= httppolicy.MaxPathBytes {
		return p
	}
	p = p[:httppolicy.MaxPathBytes]
	if i := strings.LastIndexByte(p[len(p)-2:], '%'); i >= 0 {
		p = p[:len(p)-2+i]
	}
	return p
}
