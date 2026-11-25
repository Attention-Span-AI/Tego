// SPDX-License-Identifier: Apache-2.0

// Package receipt builds a run's V1 receipt from its ledger: the time it took, the files it wrote, created,
// deleted and renamed, where it connected, the programs it ran, the secret-looking or rule-guarded files it read,
// each refused action with its rule and reason (and the contract's learn history for an exact withheld endpoint),
// refusals per minute, stall minutes, the tests result, the times it
// asked a person and their answers, and the model calls and tokens the capture recorded.
//
// One builder serves three surfaces: `tego receipt` and tego run's end summary (internal/cli) and the dashboard's
// Receipt tab (internal/control/web), so recorded totals use one builder. The dashboard supplies
// Options.SensitivePath from the run's contract copy to include custom protected paths in sensitive-read
// activity, even when the deciding line did not name that rule. A field the ledger
// cannot support says so (Field.Note) and carries no number: the receipt never invents one.
// Connection and program summaries separate listed identities, other retained identities and
// attempts beyond the identity budget. JSON uses connections_more and programs_more for
// retained identities only, with separate *_overflow_attempts fields for attempts.
// Exact unanswered totals need pending identities beyond the ask list's cap. Their separate count/byte budget
// returns ErrAskLimit and no receipt before it would fill; answers release capacity.
//
// Bound receipts: with Options.Bind (`tego receipt --json` only) the same pass binds the receipt to the record it read
// (Binding: run, lines, head, end, size and sha256 of events.jsonl, the tego that made it, fixed limit codes), and
// Check compares a bound receipt with a record from the two files alone, putting the receipt's head where chain.log's
// would stand (`tego receipt --check`). A binding vouches for nothing: whoever can write both files can make a matching
// pair, and the words of both say so (limits, not_shown).
//
// The builder uses one streaming pass and stores nothing itself: `tego run` places the bound receipt in the run directory
// as receipt.json once the run has ended (internal/cli, ADR 0159) and `tego receipt --verify` compares it with the record
// through Check. Comparison results have a
// schema under spec/receipt. A bound receipt also reads its producer image hash; no runtime state is consulted.
// The cost estimate goes through measure.Prices, the interface `tego measure`
// prices with, so the two print one figure. A file is secret-looking by internal/check/secretpath, the classifier
// the dashboard's highlights use too; a connection is a routine system lookup, counted apart, by
// internal/check/syslookup, the classifier the dashboard's verdict uses too.
//
// Imports: internal/check/mirror, internal/check/measure (Prices, CostText), internal/check/secretpath,
// internal/check/syslookup, internal/liveblock (SameFileNote), internal/ledger, internal/buildinfo (None), pkg/spec/record, pkg/spec/backend (capability
// names), pkg/spec/identity (exit codes)
// Must not import: internal/runtime, internal/cli, internal/serve, internal/control, pkg/spec/agent
package receipt
