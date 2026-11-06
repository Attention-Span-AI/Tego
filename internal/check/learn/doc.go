// SPDX-License-Identifier: Apache-2.0

// Package learn is C9 learn mode (docs/FEATURES.md, with E65): it reads what a finished run did, from its ledger, and
// proposes a boundary contract that allows that and no more, for a person to review. It is deterministic over the
// record, calls no model, and never removes fs.deny_read: the built-in list is left to apply.
//
// A Learner takes the run's events one at a time (Add) and answers with a Proposal (Proposal), whose Contract is the
// text of the proposed file. Nothing here does I/O: internal/cli reads the ledger and writes the file, so the whole
// of the choosing is a function of the events and Options.
//
// What is proposed, and what never is:
//
//   - command is the run's, from run_start.
//   - fs.write is the directories under the workspace (the run's working directory unless told otherwise) the run
//     wrote to, never a broader one and never one that is or holds tego's own state, plus /dev/null and /dev/tty
//     when the run opened them. A write outside the workspace is reported, not allowed.
//   - exec.allow is the distinct programs the run started, except the agent's own first one.
//   - net.allow is the TCP and UDP endpoints the run connected to, as addresses: the record holds the address a
//     program connected to, never the name it asked for. Dangerous endpoints are never allowed, only reported: the
//     D-Bus buses, systemd's private socket, gpg-agent and the SSH agents, the X server, the container daemons, and
//     every socket ADR 0113's built-in refusals refuse in an enforcing run, whether or not the run made it: any unix
//     socket under the user's runtime directory, a terminal multiplexer's or editor server's, and tego's own (compile
//     refuses a net.allow entry for one as a contradiction).
//   - limits are suggested in comments from the run's resource peaks, never written as a limit.
//
// A place successfully contacted next to a successful open of a secret for reading is not allowed (leak.go): the dashboard's "secret read,
// then send" verdict, read from the same lines below the control layer, leaves such an address out and says so; the
// rule goes by names and closeness and has limits, which leak.go and the proposal state. The dashboard, which holds a
// verdict of its own, turns it off with Options.LeaveLeaksToCaller. The proposal also says what it leaves open: env (it
// writes no env section) and reads.
//
// The record is the agent's own behaviour, so every string taken from it is checked before it is written into the
// proposal: one that is not a plain path or endpoint is reported, never copied into a list.
//
// Imports: internal/check/internal/mirror, internal/check/secretpath, internal/check/syslookup, pkg/spec
// Must not import: internal/runtime
package learn
