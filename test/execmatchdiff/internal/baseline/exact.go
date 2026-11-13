// SPDX-License-Identifier: Apache-2.0

package execmatch

import "slices"

// ExactPattern is an allow pattern the runtime grants on its own authority, never one a contract writes (ADR 0064:
// the harness hook's exec grant). It admits an invocation of tool only when the exec's whole vector is argv, element
// for element and byte for byte: argv[0] included, read to its end, with no glob and no trailing argument (an
// exec.allow pattern's generic reading is a token prefix), and only as the exec's own image, read by its name, its
// image, its argv[0] or its identity, never through a #! chain, a loader's program or a dispatcher. kind names the
// grant in the rule, exec.<kind>[<argv[0]>]. argv is copied; it must hold at least argv[0].
func ExactPattern(kind, tool string, argv []string) *Pattern {
	return &Pattern{
		Entry: argv[0], List: ListAllow, Command: argv[0], Tool: tool, Words: slices.Clone(argv[1:]),
		Runtime: kind, Argv0: argv[0],
	}
}

// exactly is a runtime pattern's match (ExactPattern): a direct reading of the whole vector, argv[0] and every
// token equal to the pattern's.
func (p *Pattern) exactly(inv *Invocation) bool {
	return inv.Via.direct() && !inv.Open && inv.Argv0 == p.Argv0 && slices.Equal(inv.Tokens, p.Words)
}

// direct reports whether an interpretation reads the exec's own image: by its name, image, argv[0] or identity.
func (v Via) direct() bool { return v == ViaName || v == ViaImage || v == ViaArgv0 || v == ViaIdentity }
