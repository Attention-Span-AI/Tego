// SPDX-License-Identifier: Apache-2.0

package agent

// fuseMount names a visible FUSE mount reached by a grant. A different
// filesystem may mirror protected data, but mountinfo cannot establish that
// relationship. Warn about the visible mount without guessing what it mirrors.
func (t *mountTable) fuseMount(p string) string {
	if !t.probed || t.err != nil {
		return ""
	}
	if m, _, ok := t.lookup(p); ok && isFuseType(m.fstype) {
		return m.point
	}
	for _, m := range t.mounts {
		if t.visible(m) && isFuseType(m.fstype) && isAncestorOrSelf(p, m.point) {
			return m.point
		}
	}
	return ""
}
