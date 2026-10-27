// SPDX-License-Identifier: Apache-2.0

// Package receipt builds a run's V1 receipt from its ledger alone: the time it took, the files it wrote, created,
// deleted and renamed, where it connected, the programs it ran, the secret-looking or rule-guarded files it read,
// each refused action with its rule and reason, refusals per minute, stall minutes, the tests result, the times it
// asked a person and their answers, and the model calls and tokens the capture recorded.
//
// One builder serves three surfaces: `tego receipt` and tego run's end summary (internal/cli) and the dashboard's
// Receipt tab (internal/control/web), so the terminal and the page cannot show different numbers. A field the ledger
// cannot support says so (Field.Note) and carries no number: the receipt never invents one.
//
// This is a first version: one streaming pass, no receipt.json in the run directory, no schema file yet. The cost estimate goes through measure.Prices, the interface `tego measure`
// prices with, so the two print one figure. A file is secret-looking by internal/check/secretpath, the classifier
// the dashboard's highlights use too; a connection is a routine system lookup, counted apart, by
// internal/check/syslookup, the classifier the dashboard's verdict uses too.
//
// Imports: internal/check/internal/mirror, internal/check/measure (Prices, CostText), internal/check/secretpath,
// internal/check/syslookup, internal/ledger, pkg/spec/record, pkg/spec/backend (capability names)
// Must not import: internal/runtime, internal/cli, internal/serve, internal/control, pkg/spec/agent
package receipt
