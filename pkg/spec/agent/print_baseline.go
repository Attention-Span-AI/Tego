// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/hex"
	"strings"
)

// baseline prints modeled compile coverage. Preparation must still validate the
// actual mechanism; a predicted conditional row is not a kernel claim.
func (p *printer) baseline(rt *RuleTable) {
	b := rt.Baseline
	if b == nil || len(b.Entries) == 0 {
		return
	}
	p.line("effective %s", hex.EncodeToString(rt.EffectiveHash[:]))
	p.line("baseline  owner uid %d, home %q, applied=%t; modeled coverage, verified again before launch", b.Owner.UID, b.Owner.Home, b.Applied)
	for _, e := range b.Entries {
		p.line("baseline.%s %q (expanded %q, identity %d:%d)", e.Key, e.Value, e.Expanded, e.Device, e.Inode)
		for _, s := range e.Sources {
			p.line("           source %s %q:%d", s.Layer, s.File, s.Line)
		}
		for _, c := range e.Coverage {
			p.line("           %s/%s: %s; image mode %q; operations %s; conditions %s; limits %s", c.Tier, c.Plane, c.Held, c.ImageMode, strings.Join(c.Operations, ", "), strings.Join(c.Conditions, "; "), strings.Join(c.Limits, "; "))
		}
	}
}
