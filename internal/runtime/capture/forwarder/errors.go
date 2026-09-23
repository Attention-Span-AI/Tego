// SPDX-License-Identifier: Apache-2.0

package forwarder

import "errors"

// ErrListener is a listener that could not be built or bound: an unusable models[] entry, a loopback
// socket the machine refused. It is returned before a run starts, never during one.
var ErrListener = errors.New("forwarder: listener")

// ErrAlreadyStarted is a second Start on one Manager; a run owns its forwarder exactly once.
var ErrAlreadyStarted = errors.New("forwarder: already started")

// ErrStopped is Start after the manager permanently closed its capture listeners.
var ErrStopped = errors.New("forwarder: stopped")

// ErrUpstream is the upstream leg failing: dial, TLS, or a response that stopped before it ended. It
// never reaches the agent as a Go error — the agent sees the status R26 maps it to — and never fails the
// run: capture is best-effort against the agent's own call (§7).
var ErrUpstream = errors.New("forwarder: upstream")

// ErrPeer is a connection from a process that is not part of the run: one this listener could not place
// in the run's cgroup, or one it could not identify at all. It is answered with 403 and never forwarded
// (R19a) — a loopback port is reachable by everything on the host, and this listener serves one run.
var ErrPeer = errors.New("forwarder: peer")
