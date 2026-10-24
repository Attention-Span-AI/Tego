// SPDX-License-Identifier: Apache-2.0

// Package ui is how `maze` talks to a person at a terminal: color in Maze's accent, the banner, wrapping to
// the terminal's width, and the two prompts a guided setup needs (Enter to continue, yes or no).
//
// It decides once, from the streams it is given, whether a person is there: color and the banner only when
// stdout is a terminal and NO_COLOR (https://no-color.org) is unset, prompts only when stdin is a terminal
// too. Piped or redirected, every command prints plain text a script can read, and nothing waits for input.
//
// It is written on the standard library and golang.org/x/sys alone, so `maze` adds no dependency for it.
//
// Imports: golang.org/x/sys/unix
// Must not import: internal/runtime, internal/ledger, internal/cli, pkg/spec/agent, pkg/spec/config, os/exec
package ui
