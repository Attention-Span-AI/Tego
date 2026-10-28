// SPDX-License-Identifier: Apache-2.0

// Package nextrun compiles a contract's text as tego will compile the next run of it: the run's tier, its run
// command grant, its working directory and the PATH its programs were found on, the machine's profile sources
// (profilesrc.Chain), the invoking user's home, chain anchor and runtime directories, and offline (a host name is
// resolved at run start, E18). It is the one compile both rule write paths call, `tego rule` (internal/cli) and the
// dashboard's rule service (internal/control/rules), so the same change gets the same verdict from either
// (TestParityCLIAndDashboard).
//
// Imports: the standard library, internal/ledger, internal/profilesrc, pkg/spec/agent, pkg/spec/backend,
// pkg/spec/config, pkg/spec/record.
// Must not import: internal/cli, internal/control, internal/runtime, internal/policy, internal/bpf.
package nextrun
