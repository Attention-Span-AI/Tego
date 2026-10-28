// SPDX-License-Identifier: Apache-2.0

// Package modelroute is the pure decision of ADR 0127: given a models[] entry as the contract declares it and the
// route a person put in force for it (the run's model-routes.json, "" for none), where the forwarder sends that
// endpoint's next request, whether a change from one route to another gives the run more than it has, and which
// endpoint and route a request line counts for (RequestCounter). It does no I/O and reads no clock: the forwarder,
// the dashboard's routes service and `tego route` hold the overlay and read the ledger.
//
// It lives in pkg/policy rather than internal/check: the forwarder (internal/runtime) uses it, and the engine and the
// read side never import each other (the repo's import direction).
//
// Imports: the standard library, pkg/spec/agent (the contract's models[] and routes), pkg/spec/record (RouteTaken).
// Must not import: internal/..., any package that does I/O.
package modelroute
