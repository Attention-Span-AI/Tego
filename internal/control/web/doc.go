// SPDX-License-Identifier: Apache-2.0

// Package web is tego-control serve's dashboard: a loopback-only web view of a ledger root's runs, logs,
// refusals, pending approvals and each run's rules, built from the final design (tokens.css, app.css, sprite.svg)
// with html/template and embed. It serves the listener its caller opened (it opens no socket), reads the ledger
// through internal/control/ledgerview and the contracts through internal/control/rulesview, and does three things
// to a live run through internal/control/runact: Allow and Deny answer a held request as tego approve and tego deny
// do, Block now adds a live block, and Stop stops a run as tego stop does. Each answers 303 back to the page the
// form was on with one plain line, shown once (flash.go); no ledger line is shown raw.
//
// Pages change in place: static/live.js follows GET /events (Server-Sent Events of the live state, live.go) and swaps
// only the live regions whose HTML changed, which the page's own templates render on a region request
// (regions.go); without JavaScript a meta refresh and plain form posts do the same work. live.js posts the forms in
// the background, and an action answers it the same plain line as JSON instead of the 303, which it shows in a toast.
// Logs adds static/logs.js on top: its rows follow the run themselves (GET /logs/rows, after and before a cursor),
// a row opens in place (GET /logs/line), and j/k move through them (logs_rows.go). static/place.js, which live.js
// loads, keeps the reader's place: a chip, a facet, a tab, a pager or a GET form fetches its page and merges it in
// place with live.js's merge, its address in history, and a plain form post comes back to where it was sent from.
// The run page's Block now panel adds static/twin.js: its terminal twin says the command the form makes, as it is
// typed, each word quoted by internal/shellword's rule, the rule of the twins the server writes.
//
// Security minimum: a request whose client socket another local uid owns gets 403 before the token or cookie is
// looked at (peer.go, /proc/net/tcp{,6}, fails closed). One random token, printed in the URL, is exchanged for an
// HttpOnly SameSite=Strict cookie; a request without it gets 401 (a browser a page saying how to sign in again; only
// the favicon is served without it). The Host header must be the loopback address and port (DNS rebinding). GET and HEAD
// change nothing; only POST does, and a POST must also carry the session's CSRF token (an HMAC of the session) in a
// form field and come from the dashboard's own origin (Origin, or Referer when no Origin is sent). Every response
// carries a strict CSP (no inline script or style; the forms need no JavaScript), nosniff, a same-origin referrer
// policy and frame-ancestors 'none'. Agent text reaches a page only through html/template, and every HTML response, the
// toast's line and the CSV download write the invisible characters an agent can hide in a name (a bidi override, a
// zero-width character) as ⟦U+202E⟧ (shown.go visibleHTML, visibleText); the JSONL download keeps the ledger's bytes. A POST, and the ?t= sign-in, whose client socket was made inside a tego run's
// cgroup gets 403 naming the run (governed.go, sock_diag via internal/platform/peer, fails closed): an agent cannot
// change its own governance. A write that is not a narrowing posts the preview's acknowledgement, which the rule
// service checks (internal/control/rules ack.go). docs/adr/0123-dashboard-threat-model.md says what this does not
// cover.
package web
