// SPDX-License-Identifier: Apache-2.0

// Package e2e holds the dashboard's end-to-end journeys: a real tego
// run at tier landlock whose contract asks a person, and a real tego-control serve over that run's ledger root, driven
// through HTTP as a browser would drive it (token cookie, CSRF field, Origin). It has no code of its own; the tests
// are built with the integration tag: launch_test.go (answer, live block, stop) and rules_demo_test.go (the demo's
// Deny, then "Never allow" with "Also apply now":).
package e2e
