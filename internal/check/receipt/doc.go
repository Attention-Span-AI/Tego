// SPDX-License-Identifier: Apache-2.0

// Package receipt builds a run's V1 receipt from its ledger alone: the time it took, the files it wrote, created,
// deleted and renamed, where it connected, the programs it ran, the secret-looking or rule-guarded files it read,
// each refused action with its rule and reason, refusals per minute, stall minutes, the tests result, the times it
// asked a person and their answers, and the model calls and tokens the capture recorded.
//
// One builder serves three surfaces: `tego receipt` and tego run's end summary (internal/cli) and the dashboard's
// Receipt tab (internal/control/web), so the terminal and the page cannot show different numbers. A field the ledger
// cannot support says so (Field.Note) and carries no number: the receipt never invents one.
// Exact unanswered totals need pending identities beyond the ask list's cap. Their separate count/byte budget
// returns ErrAskLimit and no receipt before it would fill; answers release capacity.
//
// Bound receipts: with Options.Bind (`tego receipt --json` only) the same pass binds the receipt to the record it read
// (Binding: run, lines, head, end, size and sha256 of events.jsonl, the tego that made it, fixed limit codes), and
// Check compares a bound receipt with a record from the two files alone, putting the receipt's head where chain.log's
// would stand (`tego receipt --check`). A binding vouches for nothing: whoever can write both files can make a matching
// pair, and the words of both say so (limits, not_shown).
//
// This is a first version: one streaming pass, no receipt.json in the run directory, no schema file yet. The cost estimate goes through measure.Prices, the interface `tego measure`
// prices with, so the two print one figure. A file is secret-looking by internal/check/secretpath, the classifier
// the dashboard's highlights use too; a connection is a routine system lookup, counted apart, by
// internal/check/syslookup, the classifier the dashboard's verdict uses too.
//
// Imports: internal/check/internal/mirror, internal/check/measure (Prices, CostText), internal/check/secretpath,
// internal/check/syslookup, internal/liveblock (SameFileNote), internal/ledger, internal/buildinfo (None), pkg/spec/record, pkg/spec/backend (capability
// names), pkg/spec/identity (exit codes)
// Must not import: internal/runtime, internal/cli, internal/serve, internal/control, pkg/spec/agent
package receipt
