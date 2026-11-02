// SPDX-License-Identifier: Apache-2.0

// Package e2e holds the dashboard's end-to-end journeys: a real tego
// run at tier landlock whose contract asks a person, and a real tego-control serve over that run's ledger root, driven
// through HTTP as a browser would drive it (token cookie, CSRF field, Origin). It has no code of its own; the tests
// are built with the integration tag: launch_test.go (answer, live block, stop), rules_demo_test.go (the demo's
// Deny, then "Never allow" with "Also apply now"), rules_change_test.go (Change rules: a program removed with "Also
// apply now", then Undo) and rule_journal_test.go (a `tego rule` change in the journal, undone on the dashboard).
package e2e
