// SPDX-License-Identifier: Apache-2.0

// Package askpair is the one rule that pairs an ask line of a run with the answer line that names the same ask id, and the
// one fallback of an ask line's operation, target and rule. Every reader of a run's asks takes its lines through a Book:
// the receipt (asked, answered and unanswered), `tego status` (the asks a run waits on), the dashboard's read model, the
// signal fold, the line index, the compare page and `tego ask`'s record lookup. The first ask line of an id opens the
// question and the answer pairs with it; a repeated ask line is malformed ("an ask was recorded twice") and changes
// nothing; an answer with no open ask (before its ask, to an id never asked, or a second answer) is malformed ("an answer
// has no ask before it"), never counts as answered; an ask no answer follows stays unanswered. Each reader shows the
// malformed lines in its own place, in these words (RepeatedWords, UnpairedWords), so a record reads the same everywhere.
// The open asks are bounded by a count of ids and an estimate of bytes, so a ledger with a flood of unanswered ids costs a
// bounded amount, and each reader says what it did when the bound was passed.
//
// Imports: the standard library only. Must not import: internal/runtime, internal/control, internal/cli.
package askpair
