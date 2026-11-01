// SPDX-License-Identifier: Apache-2.0

package rule

import "slices"

// What this file exports, only this package's tests call.

// String is the edit as one line: "fs.deny_read += ./secrets/", "never fs.ask_read[~/.config/telemetry/]".
func (e Edit) String() string {
	switch e.Op {
	case OpRemove:
		return e.Key + " -= " + e.Entry
	case OpNever:
		return "never " + e.Key + "[" + e.Entry + "]"
	case OpAdd:
	}
	return e.Key + " += " + e.Entry
}

// NeverOf is the "never" edit for the ask entry a ledger rule names: "fs.ask_read[~/.config/telemetry/]" is
// Edit{OpNever, "fs.ask_read", "~/.config/telemetry/"}.
func NeverOf(rule string) (Edit, error) {
	k, e, ok := ruleEntry(rule)
	if !ok || !slices.Contains(askKeys, k) {
		return Edit{}, refuse("%q is not an ask entry's rule (fs.ask_read[...], fs.ask[...] or net.ask[...])", rule)
	}
	return Edit{Op: OpNever, Key: k, Entry: e}, nil
}

// Option is one choice a page offers for an event: OK, or Why not.
type Option struct {
	Action Action
	Folder bool
	OK     bool
	Why    string
	Effect string
}

// Options is every action and scope the grammar has for the event's kind, each said possible or not for this
// contract (without the compiler: Apply with Check says the last word).
func Options(req Request) ([]Option, Target, error) {
	t, err := TargetOf(req.Event)
	if err != nil {
		return nil, t, err
	}
	var out []Option
	for _, a := range Actions(t.Kind) {
		for _, folder := range []bool{false, true} {
			if folder && t.Kind != KindRead && t.Kind != KindWrite {
				continue
			}
			r := req
			r.Action, r.Folder, r.Check = a, folder, nil
			res, err := Apply(r)
			o := Option{Action: a, Folder: folder, OK: err == nil}
			if err != nil {
				o.Why = err.Error()
			} else {
				o.Effect = res.Effect
			}
			out = append(out, o)
		}
	}
	return out, t, nil
}
