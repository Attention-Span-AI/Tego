// SPDX-License-Identifier: Apache-2.0

// Package linewords is the dashboard's glossary for ledger lines: a label for each record payload key, and plain
// words for the values a person cannot read as written (reason codes, sources, verdicts, holds, gap whys, the kernel
// decision plane's mechanisms and reasons, the run_start reads facts, open flags, errno numbers, byte counts and
// durations). The line page (ledgerview.Explain) shows every key of a line through it.
//
// It never invents: a key or a value it has no words for is reported unknown (Label and Value return ok false), and
// the caller shows it as written. A glossary test fails when a record Gap*, Reason*, Source*, Mechanism*,
// PlaneReason*, ReadsNotifiedWhy* or FSReadsWhy* constant has no words here.
//
// Mask hides what looks like a credential in a text a row or the line page shows (an Authorization header, a
// --token flag, a key=value secret, a password in a URL, a well-known token shape); internal/control/web's rows call
// it, so a row and the line page mask the same way.
//
// It is pure: no I/O, no clock, no lookups of users or hosts (Who takes the name lookup from its caller).
//
// Imports: the standard library only.
// Must not import: anything of this module (it sits below internal/control/ledgerview and internal/control/web).
package linewords
