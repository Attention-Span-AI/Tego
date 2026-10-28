// SPDX-License-Identifier: Apache-2.0

// Package secretpath says, by its name alone, whether a path holds a person's secrets: SSH, cloud and GPG
// credentials, private keys, .env files, an app's login token, and directories named confidential or secrets. It is a
// guess a person reads, never a verdict, and it never opens the path.
//
// One classifier serves both sides: the engine-side receipt (internal/check/receipt, "Sensitive files read") and the
// dashboard's highlights and Compare (internal/control/ledgerview wraps it), so the terminal and the page flag the
// same files. It is a pure function over strings: no I/O, no clock. It also holds the rule for how close a send must
// come to a secret touch to count as next to it (NearSeconds, NearLines) and what counts as a read (ReadOpen), which
// the receipt, the dashboard's verdict and tego learn's leak rule share.
//
// Imports: the standard library only (path, strings)
// Must not import: anything under internal/ or pkg/
package secretpath
