// SPDX-License-Identifier: Apache-2.0

package agent

import "slices"

// BuiltInDenyRead is the built-in deny_read list (SEMANTICS §1) as paths relative to the home, a copy: what every
// contract that does not say `deny_read: []` refuses reading beyond its own entries (the .env scan aside,
// IsBuiltInEnvName). A rule editor reads it to tell whether an fs.ask_read entry it adds relaxes one of these
// refusals into a question (ADR 0057 D4), which is a widening, not a narrowing; a caller that writes contracts
// (internal/setup) says when an entry it adds reaches one of them.
func BuiltInDenyRead() []string { return slices.Clone(builtInDenyRead) }
