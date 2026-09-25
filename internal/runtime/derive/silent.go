// SPDX-License-Identifier: Apache-2.0

package derive

// SilentPaths is a Parser that can tell, from a request's method and target alone, that the exchange spends
// nothing whatever its answer: a health check, telemetry, token counting, a model listing. A capture source
// that gives up on a request with no answer asks it before reporting the request unmetered (ADR 0037
// amendment 2026-09-24), so a dropped telemetry batch never ends a budgeted run.
type SilentPaths interface {
	// Silent reports that method and target (as the request line wrote it) are a path the parser calls
	// silent. An unknown or ambiguous path is not silent.
	Silent(method, target string) bool
}

// Silent reports whether the parser that owns provider, or failing that host, calls the request silent
// (SilentPaths). A request no parser claims, or whose parser cannot say, is not silent: an unanswered request
// fails closed.
func (d *Dispatcher) Silent(provider, host, method, target string) bool {
	p, ok := d.Parser(provider, host)
	if !ok {
		return false
	}
	s, ok := p.(SilentPaths)
	return ok && s.Silent(method, target)
}
