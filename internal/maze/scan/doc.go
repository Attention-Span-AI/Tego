// SPDX-License-Identifier: Apache-2.0

// Package scan answers the questions `maze init` asks before it proposes a single rule: which
// workspace this is, which agent is installed, what an agent running as this user could read
// everywhere (the personal scope), and what this repo holds and needs (the workspace scope).
//
// It reads names and paths, and only the contents it needs to suggest rules: a package.json (which tool
// builds the project), the variable names in a .env file, cut at the '=' so no value is ever kept or
// printed, Claude Code's permission rules (.claude/settings.json, and the deny list of ~/.claude/settings.json),
// and up to a few hundred Python files, searched for the words that load a .env file. A secret file is found by its name, a secret variable by its name. It follows no symbolic link
// into a file it reads, changes nothing on disk, starts no process and makes no network call, so
// `maze init --explain` can run it on any machine. The guided setup asks before scanning a project.
//
// Everything it reads from the machine comes through Env, so a test points it at a temporary home
// directory and a made-up environment and never at the real ones.
//
// The engine decides what is actually blocked; this package only reports what the engine's
// built-in rules already cover (BuiltIn) next to what would need a rule of its own. Its copies of
// the engine's built-in lists (builtInHome, isEnvFile, skipDirs) mirror pkg/spec/agent/compile_fs.go
// by hand, because pkg/spec/agent does not build on macOS and `maze` must.
//
// Imports: standard library only
// Must not import: internal/runtime, internal/ledger, internal/cli, pkg/spec/agent, pkg/spec/config, os/exec
package scan
