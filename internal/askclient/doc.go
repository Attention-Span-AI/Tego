// SPDX-License-Identifier: Apache-2.0

// Package askclient is the client of a run's ask broker (ADR 0008, ADR 0057, ADR 0100 (7)): it finds the run's live
// launcher through the run's lock (Launcher), dials <run>/ask.sock, refuses a server whose SO_PEERCRED pid is not
// that launcher's, answers the broker's nonce hello, and lists, inspects and answers held requests in the wire
// format of pkg/spec/askproto. LedgerTarget is the one function that turns a held request's target into the form
// the ledger records, which the runtime's ask and answer lines and tego-control's cards both use.
//
// The code moved out of internal/runtime/ask unchanged so that tego-control can reach a
// run's broker without linking the engine; it never imports internal/runtime (a go list test holds that). The
// broker in internal/runtime/ask binds by OpenSocketDir and reads its peers by PeerCred, so both ends find the
// socket and read a peer one way.
package askclient
