// SPDX-License-Identifier: Apache-2.0

// Package profilesrc is where a contract's `extends:` names are read from (ADR 0066 D7): Chain is the one profile
// source both binaries build, the machine config's profiles directory (Dir) and the built-in sources, so tego's
// compile, run and drift and the dashboard's rule writes (internal/control/rules) resolve a profile to the same bytes
// under the same trust rules. It moved here from internal/cli's dirProfiles so tego-control, which may not link the
// engine's command line (TestControlLinksNoEngine), compiles a contract that extends a profile exactly as tego does.
//
// Imports: the standard library, pkg/spec/agent, pkg/spec/config.
// Must not import: internal/cli, internal/control, internal/runtime, internal/policy, internal/bpf.
package profilesrc
