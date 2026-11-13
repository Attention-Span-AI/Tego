// SPDX-License-Identifier: Apache-2.0

// Package execmatch is the one argv matcher of exec command rules (ADR 0048 (2)): `exec.deny: [git push]`,
// `exec.allow: [git status]` and the gate's `exec matches` read a command line with it. It is the standard library
// only and makes no I/O: compile, the decision core, the gate and the supervisor hand it facts they copied, and it
// returns what a command rule decides on them.
//
// A command line is not a string. The word that decides what a program does moves with global options that take
// values, with clustered, permuted and abbreviated options, with dashed and argv[0] forms, multicall binaries,
// interpreters and git's in-process autocorrection. A per-tool Row describes one tool's grammar, and Normalize parses
// tokens with it into readings: a subcommand path, options with their values, operands, and where the row cannot be
// sure how the tool reads a token, every reading it could make. A deny or ask entry matches when any reading matches;
// a constrained allow entry only when every reading does. A tool with no row is read by the generic fallback: an
// exact token prefix for allow entries, an over-approximating subsequence for deny and ask entries.
//
// The decision layer also keeps the algorithm from before the separator correction over these rows: deny and
// ask use the union of the two readers, and constrained allow uses their intersection. Pattern.Match and Normalizer
// describe the corrected parser alone.
//
// The rows themselves are data in the rows subpackage, documented in docs/spec/exec-command-rows.md.
package execmatch
