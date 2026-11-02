// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"net/http"
)

// KeyLayer is unused: Options.Credentials is nil on every run, and every header is forwarded as the agent sent it.
type KeyLayer interface {
	start(rnd io.Reader) (keyInjector, error)
}

// keyInjector is what listener.go and manager.go ask of a started key layer, each call only when Listener.creds is not
// nil. One per run, shared by the run's listeners like the budget.
type keyInjector interface {
	// refuseTunnel answers a CONNECT or an upgrade the layer will not carry, and reports whether it answered. It runs
	// after peer admission and before every other route out of ServeHTTP.
	refuseTunnel(l *Listener, w http.ResponseWriter, r *http.Request, pid int) bool
	// check decides one request, before its body is read and before any hold or upstream contact, and again after
	// every hold: the second grant is the one inject uses. false means it answered the request itself, and forward
	// ends there.
	check(l *Listener, w http.ResponseWriter, r *http.Request, pid int, via *routeChoice) (keyGrant, bool)
	// inject applies check's grant to out, the outbound copy of the request, and returns the request to send; never
	// to r.Header, which the record, the retry key and the ask read.
	inject(l *Listener, out *http.Request, g keyGrant, r *http.Request, pid int, via *routeChoice) *http.Request
	// vars are the variables the run's agent is given.
	vars(listeners []*Listener) map[string]string
}

// keyGrant is what check allowed one request, carried to inject. It is the layer's own; nil is nothing.
type keyGrant any
