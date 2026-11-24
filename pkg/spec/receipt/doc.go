// SPDX-License-Identifier: Apache-2.0

// Package receipt is the run receipt's specification layer: the types of the receipt's JSON (receipt_v 1), the codes of
// its coverage and the words' shapes a program can match, and the block that binds a receipt to the record it was
// computed from. spec/receipt/receipt-v1.schema.json publishes the same shape for programs that are not Go, and a test
// holds the schema, these types and the writer (internal/check/receipt) to one another.
//
// The builder that computes a receipt from a ledger, its text and its comparison with a record live in
// internal/check/receipt, which re-exports these types under their old names. Nothing here reads a ledger, a clock or a
// machine.
//
// Imports: the standard library and pkg/spec/record (the record's own payload types a receipt carries as they were
// written).
// Must not import: anything under internal.
package receipt
