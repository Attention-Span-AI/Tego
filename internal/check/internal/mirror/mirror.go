// SPDX-License-Identifier: Apache-2.0

// Package mirror recognises a refused line that mirrors the action line before it, the one rule drift (R13)
// and measure (R19) both need to count a refusal once. It lives in one place so the two views cannot count
// refusals differently.
package mirror

import "github.com/attention-span-ai/tego/pkg/spec/record"

// Key is what decides whether a refused line mirrors the line before it: the pipeline writes the mirror
// directly after its action (mirrorRefusals), so it follows an action line refused under the same rule, one
// seq earlier. The zero Key mirrors nothing.
type Key struct {
	seq     uint64
	action  bool
	refused bool
	rule    string
}

// Of is e's Key, to be held while the next line is read.
func Of(e *record.Event) Key {
	return Key{seq: e.Seq, action: e.Kind.IsAction(), refused: e.Verdict == record.VerdictRefused, rule: e.Rule}
}

// Mirrors reports whether e is a refused line that mirrors the action line k describes.
func (k Key) Mirrors(e *record.Event) bool {
	return e.Kind == record.KindRefused && k.action && k.refused && k.seq+1 == e.Seq && k.rule == e.Rule
}
