// SPDX-License-Identifier: Apache-2.0

// Package cli implements the tego command line (docs/p0/limits-check-doctor-cli.md §4 cli.Main,
// R25, R26, R29, R30): one Command per subcommand with its own flag.FlagSet, Main's dispatch of
// argv[1] (or the hidden __child stage), the one-line message format of RUN-IDENTITY.md
// (`<file>:<line>[:<col>]: <what> [<code>]`), the exit codes of pkg/spec/identity, and a
// top-level recover that turns a panic into `tego: internal error: <msg> [bug]` and exit 125 so
// no panic escapes the exit-code contract other tools parse.
//
// Every subcommand of R29 is implemented: version, init, compile, doctor, run, stop, status, drift,
// measure, events and gc. __child is not one of them. cmd/tego matches it against os.Args before
// cli.Main is reached, so the child stage runs no CLI setup inside the run's own process; Main
// seeing it means something bypassed that dispatch, and it is reported as an unknown command.
//
// No function but the process's own main calls os.Exit (I6): every Run returns an int, so a
// command is callable in-process from a test with its own stdout and stderr.
//
// Imports: standard library, internal/doctor, pkg/spec/agent, pkg/spec/config, pkg/spec/identity,
// pkg/spec/record. Must not import: cilium/ebpf directly.
package cli
