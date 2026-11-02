// SPDX-License-Identifier: Apache-2.0

// Package nextrun compiles a contract's text as tego will compile the next run of it: the run's tier, its run
// command grant, its working directory and the PATH its programs were found on, the machine's profile sources
// (profilesrc.Chain), the invoking user's home, chain anchor and runtime directories, and offline with no DNS at all
// (a host name is resolved at run start, E18). It is the one compile both rule write paths call, `tego rule`
// (internal/cli) and the dashboard's rule service (internal/control/rules), so the same change gets the same verdict
// from either (TestParityCLIAndDashboard).
//
// UnresolvedHosts is the one lookup a change makes: the host names it adds to net.allow or net.ask, all at once and
// within HostBudget, so `tego rule` and the dashboard's previews can warn of one that does not resolve here. It is never
// a refusal: the next run resolves every host when it starts, and a mistyped one fails there.
//
// Imports: the standard library, internal/ledger, internal/profilesrc, pkg/spec/agent, pkg/spec/backend,
// pkg/spec/config, pkg/spec/record.
// Must not import: internal/cli, internal/control, internal/runtime, internal/policy, internal/bpf.
package nextrun
