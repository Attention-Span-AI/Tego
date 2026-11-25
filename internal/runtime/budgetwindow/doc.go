// SPDX-License-Identifier: Apache-2.0

// Package budgetwindow reads what an agent's earlier runs spent, for a contract whose limits.window makes tokens and
// cost_usd a total over a span across restarts (ADR 0165).
//
// The ledgers are the only source. Read lists the ledger root, takes the runs of this agent that were not proved to
// have ended before the window began (a run's closing line, matched to chain.log's head for it; never a file's date, which
// the agent can set), checks each one's hash chain against chain.log, and returns every model response in it that the
// window still holds. A counter file would be a second place for the number to live and to be changed; a ledger the
// agent could not write, chained and anchored outside its directory, is the record the rest of Tego already trusts.
// Whose a run is comes from its first line alone, so only a run that says it is this agent's can refuse a start. What
// cannot be proved of one is refused, not guessed (ErrUnprovable): a chain that does not verify, a ledger that cannot be
// read. An ended run with no anchor line is counted from its own verified chain and named in the result, and a run whose
// first line names no agent is left out and named. A run another run still holds open is ErrLive, and more than
// MaxReadBytes of this agent's ledgers to read is ErrTooLarge.
//
// Acquire is the other half: a lock in the ledger root, held for a run's whole life, so two runs of one agent never
// start at once and each count the other's spend as zero.
//
// Imports: internal/ledger, internal/platform/sys, internal/runtime/limits, pkg/spec
// Must not import: internal/runtime
package budgetwindow
