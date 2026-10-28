// SPDX-License-Identifier: Apache-2.0

// Package routeact is the dashboard's model routes service (ADR 0127): what the Model routes page shows of a run's
// models[] endpoints, and the live route changes it makes. State reads the run's contract copy (its models[] entries and
// their declared routes), the run's route overlay (internal/modelroutes) and its ledger (the ssl_request lines' route,
// the model-route-changed lines), and resolves each endpoint's route through pkg/policy/modelroute, the forwarder's own
// core, so the page shows where the forwarder sends the next request. Plan previews a change and, for one that widens
// (to any route but direct), returns the acknowledgement Set needs: an HMAC under this process's random key, domain
// tego-route-ack-v1, over the run, the endpoint, the route and the sha256 of the overlay file it was shown against, so
// a stale or forged preview is refused. A revert to direct needs none. Every change, either way, is refused to a caller
// inside a run: the agent never chooses its route. Only routes the contract declares can be chosen: there is no free
// redirect.
//
// The web package parses forms, renders and calls this; it never opens the overlay itself.
//
// Imports: the standard library, gopkg.in/yaml.v3, internal/modelroutes, internal/ledger, internal/runlock,
// internal/control/runact (SelfGoverned), pkg/policy/modelroute, pkg/spec/agent, pkg/spec/record.
// Must not import: internal/runtime, internal/policy, internal/cli (control-links-no-engine).
package routeact
