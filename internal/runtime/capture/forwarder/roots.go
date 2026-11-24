// SPDX-License-Identifier: Apache-2.0

package forwarder

import "crypto/x509"

// loadSystemRoots reads the system trust roots the upstream leg verifies the model's certificate against. The pool is
// loaded once per process, by whichever caller asks first, and the others wait on that one load: a handshake that
// arrives while it runs waits for it instead of starting its own.
//
// SSL_CERT_FILE or the system bundle is read, and with it every file of /etc/ssl/certs: on a busy disk that took
// over two seconds, and it used to happen on the first handshake, with the agent's request waiting (the run's stall
// check now counts that wait as Tego's, Manager.HoldingRequest; this is the cure at the source).
func loadSystemRoots() { _, _ = x509.SystemCertPool() }

// preloadRoots starts load (loadSystemRoots, unless a test stands in) in a goroutine and returns at once: starting the
// forwarder never waits for the disk. The first handshake finds the pool loaded, or waits on the load in progress. A load that fails
// leaves the handshake exactly where it was before there was a preload: it verifies against the system pool and meets
// the same error.
func preloadRoots(load func()) {
	if load == nil {
		load = loadSystemRoots
	}
	go load()
}
