// SPDX-License-Identifier: Apache-2.0

// Package cli is the `maze` command line: the dispatcher, each command's flags, and what each prints.
// It is the user-facing layer over the engine; the engine's own commands stay in internal/cli.
//
// Commands follow the engine's shape (a Command with a flag set and a Run that returns an exit code
// from pkg/spec/identity) and the command tree in help.go (daily commands at the top level, everything else
// in groups). Only cmd/maze calls os.Exit.
//
// Files: cli.go (dispatch, flags), help.go, start.go (the menu), init.go, render.go and rules.go (the setup and
// review), claude.go (Claude Code's rules → Maze's), save.go, project.go (status), rulecmd.go (allow, block),
// groups.go (workspace, profile), system.go (doctor, version).
//
// Imports: internal/maze/scan, internal/maze/scope, internal/maze/ui, internal/platform/proc (the engine check,
// Linux only), pkg/spec/identity
// Must not import: internal/runtime, internal/ledger, internal/cli, pkg/spec/agent, pkg/spec/config, os/exec
package cli
