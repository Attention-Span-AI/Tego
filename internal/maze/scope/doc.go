// SPDX-License-Identifier: Apache-2.0

// Package scope reads and writes Maze's own files: the rules a person approved, at two scopes, and what the
// engine is handed.
//
//   - ~/.maze/personal.yaml            rules outside any project (keys, logins, startup files, secrets)
//   - <project>/.maze/workspace.yaml   rules inside the project (files, programs, websites); committed
//   - <project>/.maze/state/           Claude Code's settings and sessions during a run, gitignored
//   - ~/.maze/projects/<project id>/   the generated engine contract and its verdict table, outside the project
//     because the engine refuses a contract the agent could rewrite
//   - ~/.maze/approved/<project id>    what the person approved, kept outside the project so an agent working
//     in it can't rewrite the record of what was approved
//   - ~/.maze/agent/                   the agent's own commit-signing key (agent.go), never the person's
//   - <project>/.git/hooks/pre-push    the pre-push check that asks before the agent's commits leave (hook.go); a
//     hook the person had runs after it
//
// Every write is a temporary file renamed into place, and no path that is a symbolic link is read or replaced:
// a link planted in a project could otherwise send a write anywhere the person can write.
//
// The contract follows the engine's rules for what Maze must never write (no `deny_read: []`, always an
// `env.pass` allowlist, only programs that are installed, no `cost_usd`) and never lets the agent run Maze or
// the engine.
//
// Imports: gopkg.in/yaml.v3 and the standard library (crypto/ed25519 makes the agent's key without ssh-keygen)
// Must not import: internal/runtime, internal/ledger, internal/cli, pkg/spec/agent, pkg/spec/config, os/exec
package scope
